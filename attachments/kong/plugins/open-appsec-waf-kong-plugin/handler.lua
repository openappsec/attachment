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
    local ctx = kong.ctx.plugin
    
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()
    kong.service.request.set_header("x-session-id", tostring(session_id))
    
    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.ctx.plugin.cleanup_needed = false
        return
    end
    
    ctx.session_data = session_data
    ctx.session_id = session_id
    if nano.is_session_finalized(session_id) then
        kong.log.info("Session has already been inspected, no need for further inspection")
        return
    end

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
    if verdict ~= nano.AttachmentVerdict.INSPECT then
        ctx.cleanup_needed = true
        if verdict == nano.AttachmentVerdict.DROP then
            return nano.handle_custom_response(session_data, response)
        end
        return
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            verdict, response = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if verdict ~= nano.AttachmentVerdict.INSPECT then
                ctx.cleanup_needed = true
                if verdict == nano.AttachmentVerdict.DROP then
                    return nano.handle_custom_response(session_data, response)
                end
                return
            end
        else
            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.debug("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict ~= nano.AttachmentVerdict.INSPECT then
                    ctx.cleanup_needed = true
                    if verdict == nano.AttachmentVerdict.DROP then
                        return nano.handle_custom_response(session_data, response)
                    end
                    return
                end
            else        
                local body_file = ngx.var.request_body_file
                if body_file then
                    local file = io.open(body_file, "rb")
                    if file then
                        local chunk_size = 8192
                        local chunk_count = 0
                        local start_time = ngx.now()
                        
                        while true do
                            ngx.update_time()
                            local current_time = ngx.now()
                            local elapsed = current_time - start_time
                            
                            if elapsed > 3 then
                                kong.log.warn("Request body reading timeout after ", elapsed, " seconds")
                                file:close()
                                return
                            end
                            
                            local chunk = file:read(chunk_size)
                            if not chunk or #chunk == 0 then
                                kong.log.err("End of request body file reached")
                                break
                            end
                            
                            chunk_count = chunk_count + 1
                            kong.log.debug("Sending request body chunk ", chunk_count, " of size ", #chunk, " bytes to C module")
                            verdict, response = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_REQUEST_BODY)
                            
                            if verdict ~= nano.AttachmentVerdict.INSPECT then
                                file:close()
                                ctx.cleanup_needed = true
                                if verdict == nano.AttachmentVerdict.DROP then
                                    return nano.handle_custom_response(session_data, response)
                                end
                                return
                            end
                        end
                        file:close()
                        kong.log.debug("Sent ", chunk_count, " chunks from request body file")
                    end
                else
                    kong.log.err("Request body expected but no body data or file available")
                end
            end
        end

        local ok, verdict, response = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        kong.log.err("Error ending request inspection: ", verdict, " - failing open")
        if not ok then
            ctx.cleanup_needed = true
            return
        end

        if verdict ~= nano.AttachmentVerdict.INSPECT then
            ctx.cleanup_needed = true
            if verdict == nano.AttachmentVerdict.DROP then
                return nano.handle_custom_response(session_data, response)
            end
            return
        end
    end
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    if nano.is_session_finalized(ctx.session_data) then
        kong.log.err("Session has already been inspected, no need for further inspection")
        return
    end

    if ctx.cleanup_needed then
        kong.log.err("cleanup in header_filter, passing through")
        return
    end
    kong.log.err("header_filter phase started")

    local session_id = ctx.session_id
    local session_data = ctx.session_data

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
    if verdict ~= nano.AttachmentVerdict.INSPECT then
        ctx.cleanup_needed = true
        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("DROP verdict in header_filter - will replace response in body_filter")
            ctx.blocked = true
            ctx.block_response = response
        end
        return
    end

    -- Clear Content-Length since we're buffering the response
    kong.log.err("Clearing Content-Length header to enable response body buffering, current value: ", tostring(content_length))
    
    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    kong.log.err("Entering body_filter phase")
    local ctx = kong.ctx.plugin
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

    
    local session_id = ctx.session_id
    local session_data = ctx.session_data
    
    if ctx.blocked then
        kong.log.err("Sending custom block response in body_filter")
        if ctx.block_response then
            kong.log.err("Block response data available, preparing custom response")
            local code, body, headers = nano.get_custom_response_data(session_data, ctx.block_response)
            kong.log.info("Replacing response with custom response, code: ", code)
            ngx.status = code
            
            for header_name, header_value in pairs(headers) do
                ngx.header[header_name] = header_value
            end
            
            if body and #body > 0 then
                ngx.header["Content-Length"] = #body
                ngx.arg[1] = body
            else
                ngx.header["Content-Length"] = 0
                ngx.arg[1] = ""
            end
        else
            kong.log.err("Missing session_data or block_response, sending empty response")
            ngx.status = 403
            ngx.arg[1] = ""
        end
        ngx.arg[2] = true
        ctx.cleanup_needed = true
        return
    end

    if nano.is_session_finalized(session_data) then
        kong.log.err("Session has already been inspected, no need for further inspection")
        return
    end
    
    if ctx.cleanup_needed then
        kong.log.err("cleanup chunk without inspection, passing through")
        return
    end

    if not ctx.body_filter_start_time then
        ctx.body_filter_start_time = ngx.now()
    end
    local elapsed_time = ngx.now() - ctx.body_filter_start_time
    if elapsed_time > 3 then
        kong.log.warn("Body filter timeout after ", elapsed_time, " seconds - failing open")
        ctx.cleanup_needed = true
        -- Send buffered chunks before timeout
        if ctx.response_buffer and #ctx.response_buffer > 0 then
            ngx.arg[1] = table.concat(ctx.response_buffer)
        end
        return
    end

    -- Initialize response buffer
    if not ctx.response_buffer then
        ctx.response_buffer = {}
    end

    if chunk and #chunk > 0 then
        kong.log.err("Processing response body chunk of size ", #chunk, " bytes")
        ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0
        ctx.body_seen = true

        table.insert(ctx.response_buffer, chunk)

        local verdict, response, modifications = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)
        
        if modifications then
            chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
            -- Update buffered chunk with modifications
            ctx.response_buffer[#ctx.response_buffer] = chunk
        end

        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

        if verdict ~= nano.AttachmentVerdict.INSPECT then
            kong.log.err("Final verdict for response body chunk: ", verdict)
            ctx.cleanup_needed = true
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("DROP verdict in body_filter - replacing with custom response")
                local code, body, headers = nano.get_custom_response_data(session_data, response)
                ngx.status = code
                for header_name, header_value in pairs(headers) do
                    ngx.header[header_name] = header_value
                end
                if body and #body > 0 then
                    ngx.header["Content-Length"] = #body
                    ngx.arg[1] = body
                else
                    ngx.header["Content-Length"] = 0
                    ngx.arg[1] = ""
                end
                ngx.arg[2] = true
                return
            else
                kong.log.err("ACCEPT verdict in body_filter - flushing buffer and switching to pass-through  chucnk :" , ctx.body_buffer_chunk)
                local buffered_data = table.concat(ctx.response_buffer)
                kong.log.err("Flushing ", #ctx.response_buffer, " buffered chunks (", #buffered_data, " bytes) before switching to pass-through")
                ngx.arg[1] = buffered_data
                ctx.response_buffer = nil
                return
            end
        end
        kong.log.err("Response body chunk of size ", #chunk, " bytes inspected and passed")
        -- Don't send chunk yet - hold it in buffer
        ngx.arg[1] = ""
        return
    end

    if eof then
        kong.log.err("End of response body reached in body_filter, eof=true")
        
        -- Call end_inspection if we haven't gotten ACCEPT verdict yet
        if ctx.body_seen or ctx.expect_body == false then
            kong.log.err("Calling end_inspection for response")
            local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
            if verdict ~= nano.AttachmentVerdict.INSPECT then
                kong.log.debug("Final verdict after end_inspection: ", verdict)
                ctx.cleanup_needed = true
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.warn("DROP verdict at EOF - replacing with custom response")
                    local code, body, headers = nano.get_custom_response_data(session_data, response)
                    ngx.status = code
                    for header_name, header_value in pairs(headers) do
                        ngx.header[header_name] = header_value
                    end
                    if body and #body > 0 then
                        ngx.header["Content-Length"] = #body
                        ngx.arg[1] = body
                    else
                        ngx.header["Content-Length"] = 0
                        ngx.arg[1] = ""
                    end
                    ngx.arg[2] = true
                    return
                else
                    -- ACCEPT verdict at EOF
                    kong.log.err("ACCEPT verdict at EOF - will flush buffered response")
                end
            end
        end
        
        -- Send buffered response (for INSPECT or ACCEPT verdicts)
        kong.log.err("Response fully inspected and passed - flushing buffered chunks , total buffered chunks: ", #ctx.response_buffer)
        if ctx.response_buffer and #ctx.response_buffer > 0 then
            local buffered_data = table.concat(ctx.response_buffer)
            kong.log.err("Flushing ", #ctx.response_buffer, " buffered chunks, total size: ", #buffered_data, " bytes")
            -- Set Content-Length for the buffered data
            ngx.header["Content-Length"] = #buffered_data
            ngx.arg[1] = buffered_data
        else
            kong.log.err("No buffered chunks to flush")
            ngx.header["Content-Length"] = 0
        end
        ngx.arg[2] = true
        ctx.cleanup_needed = true
    end
end

function NanoHandler.log(conf)
    local ctx = kong.ctx.plugin
    if ctx.cleanup_needed then
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_data = nil
        ctx.session_id = nil
        collectgarbage("collect")
    end
end

return NanoHandler