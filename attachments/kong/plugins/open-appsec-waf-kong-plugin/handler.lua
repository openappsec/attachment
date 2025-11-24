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
    
    -- Initialize response body processing start time for timeout tracking
    if ctx.expect_body then
        ctx.res_body_start_time = ngx.now() * 1000  -- Convert to milliseconds
    end
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    if not ctx or ctx.blocked then
        return
    end

    local session_id   = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data or ctx.session_finalized then
        return
    end

    local chunk = ngx.arg[1]
    local eof   = ngx.arg[2]

    -- Check if response body processing has timed out
    if ctx.res_body_start_time and not ctx.res_body_timeout_triggered then
        local current_time = ngx.now() * 1000
        local elapsed_time = current_time - ctx.res_body_start_time
        local timeout = conf.res_body_thread_timeout_msec or 150
        
        if elapsed_time > timeout then
            ctx.res_body_timeout_triggered = true
            kong.log.warn("[OpenAppSec] Response body processing timeout exceeded (", 
                         string.format("%.2f", elapsed_time), "ms > ", timeout, 
                         "ms). Failing open - skipping body inspection for session ", session_id)
        end
    end

    -- Handle body chunks
    if chunk and #chunk > 0 then
        ctx.body_seen = true

        -- Initialize chunk index if not exists
        if not ctx.body_buffer_chunk then
            ctx.body_buffer_chunk = 0
        end

        -- If timeout triggered in a previous chunk, skip nano inspection and just pass through
        if ctx.res_body_timeout_triggered then
            kong.log.debug("[OpenAppSec] Skipping body chunk ", ctx.body_buffer_chunk, " inspection due to timeout")
            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
            -- Just pass the chunk through without inspection
            return
        end

        -- Check time before calling nano.send_body
        local before_send = ngx.now() * 1000
        
        -- Use pcall to catch any errors from nano.send_body
        local ok, verdict, response, modifications = pcall(function()
            return nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)
        end)
        
        local after_send = ngx.now() * 1000
        local send_duration = after_send - before_send
        
        -- Check if the call failed or took too long
        if not ok then
            kong.log.err("[OpenAppSec] nano.send_body failed: ", verdict, ". Failing open.")
            ctx.res_body_timeout_triggered = true
            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
            return
        end
        
        -- Log if the send_body call took a long time and trigger fail-open
        local timeout = conf.res_body_thread_timeout_msec or 150
        if send_duration > timeout then
            kong.log.warn("[OpenAppSec] nano.send_body took ", string.format("%.2f", send_duration), 
                         "ms (> ", timeout, "ms) for chunk ", ctx.body_buffer_chunk, 
                         ". Triggering fail-open for remaining chunks.")
            ctx.res_body_timeout_triggered = true
            -- Still process this chunk's verdict since we already have it
        elseif send_duration > (timeout * 0.5) then
            -- Warning if approaching timeout
            kong.log.info("[OpenAppSec] nano.send_body took ", string.format("%.2f", send_duration), 
                         "ms for chunk ", ctx.body_buffer_chunk, " (approaching timeout threshold)")
        end

        -- Handle body modifications if any
        if modifications then
            chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
            ngx.arg[1] = chunk
        end

        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            ctx.session_finalized = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            -- Stop current streaming
            ngx.arg[1] = ""
            ngx.arg[2] = true
            return result
        end
    end

    -- Handle end of response
    if eof then
        if ctx.body_seen or ctx.expect_body == false then
            -- If timeout was triggered, finalize without sending end inspection
            if ctx.res_body_timeout_triggered then
                kong.log.warn("[OpenAppSec] Response body inspection skipped due to timeout. Session ", 
                             session_id, " finalized without end_inspection.")
                nano.fini_session(session_data)
                nano.cleanup_all()
                ctx.session_finalized = true
                return
            end
            
            local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                ctx.session_finalized = true
                local result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                ngx.arg[1] = ""
                ngx.arg[2] = true
                return result
            end

            nano.fini_session(session_data)
            nano.cleanup_all()
            ctx.session_finalized = true
        end
    end
end

return NanoHandler