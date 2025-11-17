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
    
    -- Enable response body buffering for inspection
    kong.service.request.enable_buffering()
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

    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.warn("[header_filter] Response headers verdict DROP for session: ", session_id)
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

    -- On first call, try to get the complete buffered body
    if not ctx.body_processed and not ctx.response_body_buffer then
        local body = kong.response.get_raw_body()
        
        if body and #body > 0 then
            kong.log.debug("[body_filter] Session: ", session_id, " | Got complete buffered body, size: ", #body, " bytes")
            ctx.complete_body = body
            ctx.body_processed = true
        else
            kong.log.debug("[body_filter] Session: ", session_id, " | No buffered body available, will collect chunks")
            ctx.response_body_buffer = {}
        end
    end

    -- If we're collecting chunks, buffer them
    if ctx.response_body_buffer then
        local chunk = ngx.arg[1]
        local eof = ngx.arg[2]

        kong.log.debug("[body_filter] Session: ", session_id, " | Chunk size: ", chunk and #chunk or 0, " | EOF: ", tostring(eof))

        if chunk and #chunk > 0 then
            table.insert(ctx.response_body_buffer, chunk)
            kong.log.debug("[body_filter] Session: ", session_id, " | Buffered chunk, total chunks: ", #ctx.response_body_buffer)
        end

        -- When we reach EOF, concatenate chunks
        if eof and #ctx.response_body_buffer > 0 then
            ctx.complete_body = table.concat(ctx.response_body_buffer)
            kong.log.debug("[body_filter] Session: ", session_id, " | Concatenated chunks, total size: ", #ctx.complete_body, " bytes")
        end
    end

    -- Process the complete body at EOF
    local eof = ngx.arg[2]
    if eof and not ctx.session_finalized then
        kong.log.debug("[body_filter] Session: ", session_id, " | EOF reached")
        
        -- Send body to nano service if we have it
        if ctx.complete_body and #ctx.complete_body > 0 then
            kong.log.debug("[body_filter] Session: ", session_id, " | Processing complete body, size: ", #ctx.complete_body, " bytes")
            
            local verdict, response, modifications = nano.send_body(session_id, session_data, ctx.complete_body, nano.HttpChunkType.HTTP_RESPONSE_BODY)

            if modifications then
                kong.log.debug("[body_filter] Session: ", session_id, " | Applying body modifications")
                ctx.complete_body = nano.handle_body_modifications(ctx.complete_body, modifications, 0)
                ngx.arg[1] = ctx.complete_body
            end

            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("[body_filter] Body verdict DROP for session: ", session_id)
                nano.fini_session(session_data)
                ctx.session_finalized = true
                local result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return result
            end
        else
            kong.log.debug("[body_filter] Session: ", session_id, " | No body to process (empty response or no body expected)")
        end

        -- End inspection
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
