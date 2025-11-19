local nano = require "kong.plugins.open-appsec-waf-kong-plugin.nano_ffi"
local kong = kong

local NanoHandler = {}

NanoHandler.PRIORITY = 3000
NanoHandler.VERSION = "1.0.0"

NanoHandler.sessions = {}
NanoHandler.processed_requests = {}

function NanoHandler.init_worker()
    nano.init_attachment()
end

-- **Handles Request Headers (DecodeHeaders Equivalent)**
function NanoHandler.access(conf)
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()
    kong.service.request.set_header("x-session-id", tostring(session_id))

    if NanoHandler.processed_requests[session_id] then
        kong.ctx.plugin.blocked = true
        return
    end

    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.log.err("Failed to initialize session - failing open")
        return
    end

    kong.ctx.plugin.session_data = session_data
    kong.ctx.plugin.session_id = session_id

    local meta_data = nano.handle_start_transaction()
    if not meta_data then
    kong.log.err("Failed to handle start transaction - failing open")
        return
    end
    
    local req_headers = nano.handleHeaders(headers)

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0

    local verdict, response = nano.send_data(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    if verdict == nano.AttachmentVerdict.DROP then
        nano.fini_session(session_data)
        kong.ctx.plugin.blocked = true
        local result = nano.handle_custom_response(session_data, response)
        nano.cleanup_all()
        return result
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            verdict, response = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                kong.ctx.plugin.blocked = true
                local result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return result
            end
        else
            kong.log.debug("Request body not in memory, attempting to read from buffer/file")

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.debug("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    nano.fini_session(session_data)
                    kong.ctx.plugin.blocked = true
                    return nano.handle_custom_response(session_data, response)
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    kong.log.debug("Reading request body from file: ", body_file)
                    local file = io.open(body_file, "rb")
                    if file then
                        local entire_body = file:read("*all")
                        file:close()

                        if entire_body and #entire_body > 0 then
                            kong.log.debug("Sending entire body of size ", #entire_body, " bytes to C module")
                            verdict, response = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_REQUEST_BODY)
                            if verdict == nano.AttachmentVerdict.DROP then
                                nano.fini_session(session_data)
                                kong.ctx.plugin.blocked = true
                                local result = nano.handle_custom_response(session_data, response)
                                nano.cleanup_all()
                                return result
                            end
                        else
                            kong.log.debug("Empty body file")
                        end
                    end
                else
                    kong.log.warn("Request body expected but no body data or file available")
                end
            end
        end

        local ok, verdict, response  = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.err("Error ending request inspection: ", verdict, " - failing open")
            nano.fini_session(session_data)
            nano.cleanup_all()
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end
    else
        verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end
    end

    NanoHandler.processed_requests[session_id] = true
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        kong.log.debug("[header_filter] Blocked context, returning early")
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.err("[header_filter] No session data found in header_filter")
        return
    end

    local headers = kong.response.get_headers()
    local header_data = nano.handleHeaders(headers)
    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0

    kong.log.debug("[header_filter] Session: ", session_id, " | Status: ", status_code, " | Content-Length: ", content_length)

    -- Send response headers WITHOUT content_length (like nginx does)
    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, 0)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.warn("[header_filter] Response headers verdict DROP for session: ", session_id)
        kong.ctx.plugin.blocked = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    end

    -- Send content_length separately (like nginx does)
    verdict, response = nano.send_content_length(session_id, session_data, content_length)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.warn("[header_filter] Content length verdict DROP for session: ", session_id)
        kong.ctx.plugin.blocked = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    end

    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
    
    kong.log.debug("[header_filter] Session: ", session_id, " | Expect body: ", ctx.expect_body)
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        kong.log.debug("[body_filter] Blocked context, returning early")
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.debug("[body_filter] No session_id or session_data, returning early")
        return
    end

    if ctx.session_finalized then
        kong.log.debug("[body_filter] Session already finalized for session: ", session_id, ", returning early")
        return
    end

    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

    kong.log.debug("[body_filter] Session: ", session_id, " | Chunk size: ", chunk and #chunk or 0, " | EOF: ", tostring(eof))

    -- Initialize on first call
    if not ctx.chunk_buffer then
        ctx.body_buffer_chunk = 0
        ctx.chunk_buffer = {}
        ctx.chunk_buffer_size = 0
    end

    -- Batch configuration: combine small chunks to reduce nano service calls
    local MAX_BATCH_SIZE = 64 * 1024 -- 64KB batches

    -- Process current chunk if present
    if chunk and #chunk > 0 then
        -- Add chunk to buffer
        table.insert(ctx.chunk_buffer, chunk)
        ctx.chunk_buffer_size = ctx.chunk_buffer_size + #chunk
        
        local should_send = false
        
        -- Send if: batch full or EOF coming
        if ctx.chunk_buffer_size >= MAX_BATCH_SIZE or eof then
            should_send = true
        end
        
        if should_send and #ctx.chunk_buffer > 0 then
            -- Combine buffered chunks
            local combined_chunk = table.concat(ctx.chunk_buffer)
            
            kong.log.debug("[body_filter] Session: ", session_id, " | Sending batched chunk #", ctx.body_buffer_chunk, 
                ", size: ", #combined_chunk, " bytes (", #ctx.chunk_buffer, " chunks combined)")
            
            local verdict, response, modifications = nano.send_body(session_id, session_data, combined_chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)

            kong.log.debug("[body_filter] Session: ", session_id, " | Verdict after chunk #", ctx.body_buffer_chunk, ": ", verdict)

            if modifications then
                kong.log.debug("[body_filter] Session: ", session_id, " | Applying body modifications to chunk")
                combined_chunk = nano.handle_body_modifications(combined_chunk, modifications, ctx.body_buffer_chunk)
                ngx.arg[1] = combined_chunk
            else
                ngx.arg[1] = combined_chunk
            end

            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
            ctx.body_seen = true
            
            -- Clear buffer
            ctx.chunk_buffer = {}
            ctx.chunk_buffer_size = 0

            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("[body_filter] Body chunk verdict DROP for session: ", session_id)
                nano.fini_session(session_data)
                ctx.session_finalized = true
                local result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return result
            end
        else
            -- Buffering chunk, don't send to client yet
            kong.log.debug("[body_filter] Session: ", session_id, " | Buffering chunk (", #chunk, " bytes), total buffered: ", ctx.chunk_buffer_size)
            ngx.arg[1] = nil -- Don't send this chunk to client yet
        end
    end

    -- End inspection at EOF
    if eof then
        kong.log.debug("[body_filter] Session: ", session_id, " | EOF reached, body_seen: ", tostring(ctx.body_seen), ", chunks processed: ", ctx.body_buffer_chunk)
        
        kong.log.debug("[body_filter] Session: ", session_id, " | Ending inspection")
        local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
        
        kong.log.debug("[body_filter] Session: ", session_id, " | End inspection verdict: ", verdict)
        
        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("[body_filter] End inspection verdict DROP for session: ", session_id)
            nano.fini_session(session_data)
            ctx.session_finalized = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end

        kong.log.debug("[body_filter] Session: ", session_id, " | Finalizing session normally")
        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_finalized = true
    end
end

return NanoHandler
