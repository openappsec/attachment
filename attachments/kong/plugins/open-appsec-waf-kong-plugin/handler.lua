local module_name = ...
local prefix = module_name:match("^(.-)handler$")
local nano = require(prefix .. "nano_ffi")
local kong = kong

local NanoHandler = {}

NanoHandler.PRIORITY = 3000
NanoHandler.VERSION = "1.0.0"

function NanoHandler.init_worker()
    nano.init_attachment()
end

function NanoHandler.access(conf)
    kong.log.debug("Entering access phase")
    local ctx = kong.ctx.plugin
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()
    kong.service.request.set_header("x-session-id", tostring(session_id))

    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.log.err("Failed to initialize session - failing open")
        ctx.session_data = nil
        ctx.session_id = nil
        ctx.cleanup_needed = false
        return
    end

    ctx.session_data = session_data
    ctx.session_id = session_id

    local meta_data = nano.handle_start_transaction()
    if not meta_data then
        kong.log.err("Failed to handle start transaction - failing open")
        ctx.cleanup_needed = true
        return
    end
    
    local req_headers = nano.handleHeaders(headers)
    if not req_headers then
        kong.log.err("Failed to handle request headers - failing open")
        ctx.cleanup_needed = true
        return
    end

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0

    local verdict, response = nano.send_data(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    if verdict == nano.AttachmentVerdict.DROP then
        ctx.cleanup_needed = true
        return nano.handle_custom_response(session_data, response)
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            verdict, response = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if verdict == nano.AttachmentVerdict.DROP then
                ctx.cleanup_needed = true
                return nano.handle_custom_response(session_data, response)
            end
        else
            kong.log.debug("Request body not in memory, attempting to read from buffer/file")

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.debug("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    ctx.cleanup_needed = true
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
                                ctx.cleanup_needed = true
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

        local ok, verdict, response  = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.err("Error ending request inspection - failing open")
            ctx.cleanup_needed = true
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            ctx.cleanup_needed = true
            return nano.handle_custom_response(session_data, response)
        end
    else
        verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if verdict == nano.AttachmentVerdict.DROP then
            ctx.cleanup_needed = true
            return nano.handle_custom_response(session_data, response)
        end
    end
end

function NanoHandler.header_filter(conf)
    kong.log.debug("Entering header_filter phase, cleanup_needed: ", tostring(kong.ctx.plugin.cleanup_needed))
    local ctx = kong.ctx.plugin
    if ctx.cleanup_needed then
        kong.log.debug("Cleanup needed in header_filter, skipping processing")
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.debug("No session data found in header_filter")
        return
    end

    local headers = kong.response.get_headers()
    local header_data = nano.handleHeaders(headers)
    
    if not header_data then
        kong.log.err("Failed to handle response headers - failing open")
        ctx.cleanup_needed = true
        return
    end
    
    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0

    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    if verdict == nano.AttachmentVerdict.DROP then
        ctx.cleanup_needed = true
        return nano.handle_custom_response(session_data, response)
    end

    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    kong.log.debug("Entering body_filter phase, cleanup_needed: ", tostring(kong.ctx.plugin.cleanup_needed))
    local ctx = kong.ctx.plugin
    if ctx.cleanup_needed then
        kong.log.debug("Cleanup needed in body_filter, skipping processing")
        return
    end
    
    local session_id = ctx.session_id
    local session_data = ctx.session_data
    if not session_id or not session_data then
        kong.log.debug("No session data found in body_filter")
        return
    end
    
    if not ctx.body_filter_start_time then
        ctx.body_filter_start_time = ngx.now()
    end
    
    local elapsed_time = ngx.now() - ctx.body_filter_start_time
    if elapsed_time > 150 then
        kong.log.warn("Body filter timeout after ", elapsed_time, " seconds - failing open")
        ctx.cleanup_needed = true
        return 
    end
    
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

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
            ctx.cleanup_needed = true
            ngx.arg[1] = ""
            ngx.arg[2] = true
            return nano.handle_custom_response(session_data, response)
        end
    end

    if eof then
        if ctx.body_seen or ctx.expect_body == false then
            local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.debug("Dropping response in body_filter after end_inspection")
                ctx.cleanup_needed = true
                ngx.arg[1] = ""
                ngx.arg[2] = true
                return nano.handle_custom_response(session_data, response)
            end

        end
        ctx.cleanup_needed = true
    end
end

function NanoHandler.log(conf)
    local ctx = kong.ctx.plugin
    kong.log.debug("Entering log phase cleanup, cleanup_needed: ", tostring(ctx.cleanup_needed))
    if ctx.cleanup_needed or ctx.session_data then
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_data = nil
        ctx.session_id = nil
    end
end

return NanoHandler