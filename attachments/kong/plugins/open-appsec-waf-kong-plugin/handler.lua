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
    kong.log.err("1-111111111 ACCESS PHASE START -------------------------------------------------------------------------------------------------------------------------------------------------")
    
    local route = kong.router.get_route()
    if not route then
        kong.log.err("ACCESS SKIPPED: no route matched")
        return
    end
    
    local request_path = kong.request.get_path()
    if request_path and (
        request_path:match("^/status") or 
        request_path:match("^/_health") or
        request_path:match("^/metrics")
    ) then
        kong.log.err("ACCESS SKIPPED: internal endpoint: ", request_path)
        return
    end
    
    if ngx.var.internal then
        kong.log.err("ACCESS SKIPPED: internal subrequest")
        return
    end
    
    local request_uri = ngx.var.request_uri
    if not request_uri or request_uri == "" then
        kong.log.err("ACCESS SKIPPED: TLS handshake or no URI")
        return
    end
    
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
            kong.log.err("Request body not in memory, attempting to read from buffer/file")

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.err("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    nano.fini_session(session_data)
                    kong.ctx.plugin.blocked = true
                    return nano.handle_custom_response(session_data, response)
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    kong.log.err("Reading request body from file: ", body_file)
                    local file = io.open(body_file, "rb")
                    if file then
                        local entire_body = file:read("*all")
                        file:close()

                        if entire_body and #entire_body > 0 then
                            kong.log.err("Sending entire body of size ", #entire_body, " bytes to C module")
                            verdict, response = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_REQUEST_BODY)
                            if verdict == nano.AttachmentVerdict.DROP then
                                nano.fini_session(session_data)
                                kong.ctx.plugin.blocked = true
                                local result = nano.handle_custom_response(session_data, response)
                                nano.cleanup_all()
                                return result
                        else
                            kong.log.err("Empty body file")
                        end
                    end
                else
                    kong.log.err("Request body expected but no body data or file available")
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
        end
    else
        local ok, verdict, response  = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.err("Error ending request inspection (no body): ", verdict, " - failing open")
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
    end
end

function NanoHandler.header_filter(conf)
    kong.log.err("2-222222222 HEADER_FILTER PHASE START -------------------------------------------------------------------------------------------------------------------------------------------------")
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        return
    end

    if ctx.inspection_complete then
        kong.log.err("Inspection already completed, skipping header_filter")
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

    kong.log.err("2-BEFORE send_response_headers call - session_id=", session_id, " status=", status_code, " content_length=", content_length)
    
    local ok, verdict, response = pcall(function()
        return nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    end)
    
    if not ok then
        kong.log.err("2-ERROR in send_response_headers: ", tostring(verdict), " - failing open, skipping response inspection")
        ctx.inspection_complete = true
        return
    end
    
    kong.log.err("2-Response headers verdict: ", verdict, " (INSPECT=", nano.AttachmentVerdict.INSPECT, ", ACCEPT=", nano.AttachmentVerdict.ACCEPT, ", DROP=", nano.AttachmentVerdict.DROP, ")")
    
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    end
    
    kong.log.err("2-Response headers verdict: ", verdict, " - continuing to body_filter (will inspect body chunks)")
end

function NanoHandler.body_filter(conf)
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]
    local chunk_size = chunk and #chunk or 0
    kong.log.err("3-333333333 BODY_FILTER - chunk_size=" .. chunk_size .. " eof=" .. tostring(eof) .. " -------------------------------------------------------------------------------------------------------------------------------------------------")
    
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        kong.log.err("3-BLOCKED: returning early")
        return
    end

    if ctx.inspection_complete then
        kong.log.err("3-INSPECTION_COMPLETE: chunk_size=" .. chunk_size .. " eof=" .. tostring(eof) .. " - PASSING THROUGH")
        goto skip_inspection
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.err("No session data found in body_filter - letting chunk pass through")
        goto skip_inspection
    end

    if not ctx.body_buffer_chunk then
        ctx.body_buffer_chunk = 0
        ctx.body_filter_start_time = ngx.now() * 1000
    end
    
    local current_time = ngx.now() * 1000
    local elapsed = current_time - ctx.body_filter_start_time
    if elapsed > 150000 then
        kong.log.err("Body filter timeout exceeded (", elapsed, "ms) - finalizing session")
        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_id = nil
        ctx.session_data = nil
        kong.log.err("------------------------------------------------------------------------")
        kong.log.err("SETTING inspection_complete=true in body_filter (TIMEOUT)")
        kong.log.err("------------------------------------------------------------------------")
        ctx.inspection_complete = true
        goto skip_inspection
    end

    if chunk and #chunk > 0 then
        ctx.body_seen = true
        
        -- Only send to nano if inspection not yet complete
        if not ctx.inspection_complete then
            local ok, result = pcall(function()
                return {nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)}
            end)

            if ok then
                local verdict = result[1]
                local response = result[2]
                local modifications = result[3]

                kong.log.err("CHUNK #", ctx.body_buffer_chunk, " VERDICT: ", verdict, " (INSPECT=", nano.AttachmentVerdict.INSPECT, ", ACCEPT=", nano.AttachmentVerdict.ACCEPT, ", DROP=", nano.AttachmentVerdict.DROP, ")")
                kong.log.err("Response body chunk verdict: ", verdict, " (chunk #", ctx.body_buffer_chunk, ")")

                if modifications then
                    chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
                    ngx.arg[1] = chunk
                end

                ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

                if verdict == nano.AttachmentVerdict.DROP then
                    nano.fini_session(session_data)
                    local custom_result = nano.handle_custom_response(session_data, response)
                    nano.cleanup_all()
                    ctx.plugin.blocked = true
                    ctx.session_id = nil
                    ctx.session_data = nil
                    return custom_result
            else
                    kong.log.err("nano.send_body failed, failing open: ", tostring(result))
                end
            else
                -- Inspection already complete - just count the chunk and pass through
                kong.log.err("CHUNK #", ctx.body_buffer_chunk, " - skipping nano.send_body (inspection complete)")
                ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1
            end
        end
    end

    if eof or (ctx.expect_body == false and not ctx.body_seen) then
        local ok, result = pcall(function()
            return {nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)}
        end)

        if ok then
            local verdict = result[1]
            local response = result[2]

            kong.log.err("3-Response END verdict: " .. tostring(verdict))

            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                local custom_result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                ctx.session_id = nil
                ctx.session_data = nil
                ctx.plugin.blocked = true
                return custom_result
            end
        else
            kong.log.err("nano.end_inspection failed, failing open: ", tostring(result))
        end

        kong.log.err("------------------------------------------------------------------------")
        kong.log.err("SETTING inspection_complete=true in body_filter (EOF processing complete)")
        kong.log.err("------------------------------------------------------------------------")
        ctx.inspection_complete = true
        
        kong.log.err("EOF reached - finalizing session in body_filter")
        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_id = nil
        ctx.session_data = nil
    end
    
    ::skip_inspection::
end

function NanoHandler.log(conf)
    kong.log.err("4-44444444444444444444-------------------------------------------------------------------------------------------------------------------------------------------------")
    local ctx = kong.ctx.plugin
    
    if ctx.session_id and ctx.session_data then
        if not ctx.inspection_complete then
            kong.log.err("Log phase called but body_filter may still be processing - NOT finalizing session to avoid breaking streaming")
            return
        end
        
        local session_data = ctx.session_data
        local session_id = ctx.session_id
        
        kong.log.err("Log phase: finalizing session ", session_id)
        
        nano.fini_session(session_data)
        
        nano.cleanup_all()
        
        ctx.session_id = nil
        ctx.session_data = nil
        
        kong.log.err("Session ", session_id, " finalized in log phase")
    else
        kong.log.err("Log phase: no session data to finalize")
    end
end

return NanoHandler
