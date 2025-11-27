local module_name = ...
local prefix = module_name:match("^(.-)handler$")
local nano = require(prefix .. "nano_ffi")
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
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.err("No session data found in header_filter")
        return
    end

    local headers = kong.response.get_headers()
    local header_data = nano.handleHeaders(headers)
    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0

    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    end

    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
    
    -- If no body is expected, finalize the session here
    if not ctx.expect_body then
        local ok, result = pcall(function()
            return {nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)}
        end)
        
        if ok and result and result[1] then
            if result[1] == nano.AttachmentVerdict.DROP then
                kong.ctx.plugin.blocked = true
                nano.fini_session(session_data)
                nano.cleanup_all()
                return nano.handle_custom_response(session_data, result[2])
            end
        end
        
        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_finalized = true
    end
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        return
    end

    -- If no session was created (timeout in earlier phases), skip body inspection entirely
    if not ctx.session_id or not ctx.session_data then
        return
    end

    -- If expect_body is explicitly false, don't process body at all
    if ctx.expect_body == false then
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if ctx.session_finalized then
        return
    end

    -- Initialize chunk counter and timeout tracking on first call
    if not ctx.body_buffer_chunk then
        ctx.body_buffer_chunk = 0
        ctx.body_filter_start_time = ngx.now() * 1000  -- Current time in milliseconds
        ctx.body_filter_timeout = false
    end

    -- Check if we've exceeded 150ms timeout
    local elapsed_time = (ngx.now() * 1000) - ctx.body_filter_start_time
    if elapsed_time > 1500 then
        if not ctx.body_filter_timeout then
            ctx.body_filter_timeout = true
            kong.log.warn("body_filter timeout exceeded (150ms), failing open - no more chunks sent to nano-agent")
        end
        -- Fail-open: pass through remaining chunks without inspection
        return
    end

    -- Get the current chunk from ngx.arg[1] (this is how Kong streams body data)
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]  -- true on last chunk
    
    -- Try Kong API for small in-memory bodies (backward compatibility)
    local full_body = kong.response.get_raw_body()
    
    -- Determine if we're dealing with a full body or streaming chunks
    local is_streaming = (full_body == nil and chunk ~= nil)
    
    -- If no body content at all (no full_body, no chunk, and no EOF), just return
    -- This prevents sending empty traffic to nano-agent
    if not full_body and not chunk and not eof then
        return
    end
    
    if full_body and not ctx.body_seen then
        -- Small response body - use Kong API (original behavior)
        ctx.body_seen = true
        kong.log.debug("Processing in-memory response body, size: ", #full_body)
        
        local ok, result = pcall(function()
            return {nano.send_body(session_id, session_data, full_body, nano.HttpChunkType.HTTP_RESPONSE_BODY)}
        end)
        
        if ok and result and result[1] then
            local verdict = result[1]
            local response = result[2]
            local modifications = result[3]

            if modifications then
                full_body = nano.handle_body_modifications(full_body, modifications, ctx.body_buffer_chunk)
                kong.response.set_raw_body(full_body)
            end

            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                ctx.session_finalized = true
                local custom_result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return custom_result
            end
        else
            kong.log.warn("nano.send_body failed for in-memory body: ", result)
            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
        end
        
    elseif is_streaming and chunk and type(chunk) == "string" and #chunk > 0 then
        -- Large response body - streaming chunks (file-buffered or large in-memory)
        ctx.body_seen = true
        
        local chunk_size = #chunk
        kong.log.debug("Processing response body chunk #", ctx.body_buffer_chunk, ", size: ", chunk_size, ", eof: ", eof)
            
        local ok, result = pcall(function()
            return {nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)}
        end)
        
        if ok and result and result[1] then
            local verdict = result[1]
            local response = result[2]
            local modifications = result[3]

            -- Apply modifications to this chunk
            if modifications then
                chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
            end

            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                ctx.session_finalized = true
                ngx.arg[1] = nil  -- Clear the output
                ngx.arg[2] = true  -- Force EOF
                local custom_result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return custom_result
            end
            
            -- Update the chunk that will be sent to client (CRITICAL for streaming)
            ngx.arg[1] = chunk
        else
            kong.log.warn("nano.send_body failed for chunk #", ctx.body_buffer_chunk, ": ", result)
            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
            -- Fail-open: pass chunk through unmodified
            -- ngx.arg[1] is already set to the original chunk
        end
    end

    -- Finalize session only on EOF
    if eof then
        kong.log.debug("Finalizing response inspection, body_seen: ", ctx.body_seen, ", eof: ", eof, ", timeout: ", ctx.body_filter_timeout)
        
        -- Only send end_inspection if we haven't timed out
        if not ctx.body_filter_timeout then
            local ok, result = pcall(function()
                return {nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)}
            end)
            
            if ok and result and result[1] then
                local verdict = result[1]
                local response = result[2]
                
                if verdict == nano.AttachmentVerdict.DROP then
                    nano.fini_session(session_data)
                    ctx.session_finalized = true
                    ngx.arg[1] = nil  -- Clear any remaining output
                    ngx.arg[2] = true  -- Force EOF
                    local custom_result = nano.handle_custom_response(session_data, response)
                    nano.cleanup_all()
                    return custom_result
                end
            else
                kong.log.warn("nano.end_inspection failed: ", result)
            end
        else
            kong.log.debug("Skipping end_inspection due to timeout - failing open")
        end

        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_finalized = true
    end
end

return NanoHandler