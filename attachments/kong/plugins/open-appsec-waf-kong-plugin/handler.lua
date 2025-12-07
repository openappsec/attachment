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
        nano.fini_session(session_data)
        nano.cleanup_all()
        -- collectgarbage("restart")
        -- collectgarbage("collect")
        kong.ctx.plugin.session_data = nil
        kong.ctx.plugin.session_id = nil
        return
    end
    
    local req_headers = nano.handleHeaders(headers)
    if not req_headers then
        kong.log.err("Failed to handle request headers - failing open")
        nano.fini_session(session_data)
        nano.cleanup_all()
        -- collectgarbage("restart")
        -- collectgarbage("collect")
        kong.ctx.plugin.session_data = nil
        kong.ctx.plugin.session_id = nil
        return
    end

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0

    local verdict, response = nano.send_data(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        kong.ctx.plugin.cleanup_needed = true
        return nano.handle_custom_response(session_data, response)
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            verdict, response = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if verdict == nano.AttachmentVerdict.DROP then
                kong.ctx.plugin.blocked = true
                kong.ctx.plugin.cleanup_needed = true
                return nano.handle_custom_response(session_data, response)
            end
        else
            kong.log.debug("Request body not in memory, attempting to read from buffer/file")

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.debug("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.ctx.plugin.blocked = true
                    kong.ctx.plugin.cleanup_needed = true
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

                        if not entire_body then
                            kong.log.err("Failed to read body file: ", body_file)
                        elseif entire_body and #entire_body > 0 then
                            kong.log.debug("Sending entire body of size ", #entire_body, " bytes to C module")
                            verdict, response = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_REQUEST_BODY)
                            if verdict == nano.AttachmentVerdict.DROP then
                                kong.ctx.plugin.blocked = true
                                kong.ctx.plugin.cleanup_needed = true
                                return nano.handle_custom_response(session_data, response)
                            end
                        else
                            kong.log.debug("Empty body file")
                        end
                    end
                else
                    kong.log.debug("Request body expected but no body data or file available")
                end
            end
        end

        local verdict, response = nano.AttachmentVerdict.INSPECT, nil
        local ok, pcall_verdict, pcall_response = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.err("Error ending request inspection: ", pcall_verdict, " - failing open")
            nano.fini_session(session_data)
            nano.cleanup_all()
            -- collectgarbage("restart")
            -- collectgarbage("collect")
            kong.ctx.plugin.session_data = nil
            kong.ctx.plugin.session_id = nil
            return
        end

        verdict, response = pcall_verdict, pcall_response

        if verdict == nano.AttachmentVerdict.DROP then
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.fini_session(session_data)
            nano.cleanup_all()
            -- collectgarbage("restart")
            -- collectgarbage("collect")
            kong.ctx.plugin.session_data = nil
            kong.ctx.plugin.session_id = nil
            return result
        end
    else
        verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if verdict == nano.AttachmentVerdict.DROP then
            kong.ctx.plugin.blocked = true
            kong.ctx.plugin.cleanup_needed = true
            return nano.handle_custom_response(session_data, response)
        end
    end

    NanoHandler.processed_requests[session_id] = true
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked or ctx.cleanup_needed then
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
    
    if not header_data then
        kong.log.err("Failed to handle response headers - failing open")
        return
    end
    
    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0

    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        kong.ctx.plugin.cleanup_needed = true
        return nano.handle_custom_response(session_data, response)
    end

    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]
    
    if ctx.blocked or ctx.cleanup_needed then
        kong.log.err("Fail-open mode - blocked chunk without inspection, chunk size: ", chunk and #chunk or 0)
        
        if chunk then
            ngx.arg[1] = chunk
        end
        return
    end

    kong.log.err("In body_filter phase")
    local session_id = ctx.session_id
    local session_data = ctx.session_data
    kong.log.err("Session id after")
    if not session_id or not session_data or ctx.session_finalized then
        kong.log.err("Fail-open mode - consuming chunk without inspection, chunk size: ", chunk and #chunk or 0)
        -- In fail-open, we need to consume the chunk to prevent buffering
        -- Setting ngx.arg[1] to itself signals to Kong that we processed it
        if chunk then
            ngx.arg[1] = chunk
        end
        return
    end
    kong.log.err("Session id after 2")

     -- Timeout handling
    if not ctx.body_filter_start_time then
        ctx.body_filter_start_time = ngx.now()
    end
    local elapsed_time = ngx.now() - ctx.body_filter_start_time
    if elapsed_time > 150 then
        kong.log.warn("Body filter timeout after ", elapsed_time, " seconds - failing open")
        local verdict, response, modifications = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
        
        if modifications then
            chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk or 0)
            ngx.arg[1] = chunk
        end
        
        if verdict == nano.AttachmentVerdict.DROP then
            ctx.blocked = true
            ctx.session_finalized = true
            ctx.cleanup_needed = true
            ngx.arg[1] = ""
            ngx.arg[2] = true
            return nano.handle_custom_response(session_data, response)
        end
        -- Don't cleanup here - let log phase handle it
        ctx.cleanup_needed = true
        -- Mark that we're in passthrough mode after timeout
        ctx.timeout_passthrough = true
        return 
    end


    if chunk and #chunk > 0 then
        ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0
        ctx.body_seen = true
        
        local verdict, response, modifications = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)

        if modifications then
            chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
            ngx.arg[1] = chunk
        end

        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

        if verdict == nano.AttachmentVerdict.DROP then
            ctx.blocked = true
            ctx.session_finalized = true
            ctx.cleanup_needed = true
            ngx.arg[1] = ""
            ngx.arg[2] = true
            return nano.handle_custom_response(session_data, response)
        end
        
        nano.free_all_responses()
        nano.free_all_nano_str()
    end

    if eof then
        if ctx.body_seen or ctx.expect_body == false then
            local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
            if verdict == nano.AttachmentVerdict.DROP then
                ctx.blocked = true
                ctx.session_finalized = true
                ctx.cleanup_needed = true
                ngx.arg[1] = ""
                ngx.arg[2] = true
                return nano.handle_custom_response(session_data, response)
            end

            -- Cleanup in log phase instead
            ctx.cleanup_needed = true
            ctx.session_finalized = true
        end
    end
end

function NanoHandler.log(conf)
    local ctx = kong.ctx.plugin
    
    -- Cleanup session if it was blocked (kong.response.exit was called)
    if ctx.cleanup_needed and ctx.session_data then
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_data = nil
        ctx.session_id = nil
    end
end

return NanoHandler