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
    kong.log.err("1--------------------------------------------------------------------------------------------------------------------------------------------------")
    
    -- Skip if no route is matched (internal Kong requests, unmapped paths)
    local route = kong.router.get_route()
    if not route then
        kong.log.debug("Skipping WAF inspection - no route matched")
        return
    end
    
    -- Skip internal Kong requests (admin API, status endpoint, etc.)
    local request_path = kong.request.get_path()
    if request_path and (
        request_path:match("^/status") or 
        request_path:match("^/_health") or
        request_path:match("^/metrics")
    ) then
        kong.log.debug("Skipping WAF inspection for internal endpoint: ", request_path)
        return
    end
    
    -- Skip if this is an internal subrequest (ngx.location.capture, etc.)
    if ngx.var.internal then
        kong.log.debug("Skipping WAF inspection for internal subrequest")
        return
    end
    
    -- Skip TLS/SSL handshake and certificate phase requests (no HTTP data yet)
    local request_uri = ngx.var.request_uri
    if not request_uri or request_uri == "" then
        kong.log.debug("Skipping WAF inspection - TLS handshake or no URI")
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
    elseif verdict ~= nano.AttachmentVerdict.INSPECT then
        -- ACCEPT or other - stop inspection but keep session alive until log phase
        kong.log.debug("Got final verdict (not INSPECT) after request headers: ", verdict, " - session will be finalized in log phase")
        kong.ctx.plugin.inspection_complete = true
        return
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
            elseif verdict ~= nano.AttachmentVerdict.INSPECT then
                -- ACCEPT or other - stop inspection but keep session alive until log phase
                kong.log.debug("Got final verdict (not INSPECT) after request body: ", verdict, " - session will be finalized in log phase")
                kong.ctx.plugin.inspection_complete = true
                -- Continue to response phase
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
                elseif verdict ~= nano.AttachmentVerdict.INSPECT then
                    -- ACCEPT or other - stop inspection but keep session alive until log phase
                    kong.log.debug("Got final verdict (not INSPECT) after request body from var: ", verdict, " - session will be finalized in log phase")
                    kong.ctx.plugin.inspection_complete = true
                    -- Continue to response phase
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
                            elseif verdict ~= nano.AttachmentVerdict.INSPECT then
                                -- ACCEPT or other - stop inspection but keep session alive until log phase
                                kong.log.debug("Got final verdict (not INSPECT) after request body from file: ", verdict, " - session will be finalized in log phase")
                                kong.ctx.plugin.inspection_complete = true
                                -- Continue to response phase
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
        elseif verdict ~= nano.AttachmentVerdict.INSPECT then
            -- ACCEPT or other - stop inspection but keep session alive until log phase
            kong.log.debug("Got final verdict (not INSPECT) at request END: ", verdict, " - session will be finalized in log phase")
            kong.ctx.plugin.inspection_complete = true
            -- Continue to response phase
        end
    else
        verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        elseif verdict ~= nano.AttachmentVerdict.INSPECT then
            -- ACCEPT or other - stop inspection but keep session alive until log phase
            kong.log.debug("Got final verdict (not INSPECT) at request END (no body): ", verdict, " - session will be finalized in log phase")
            kong.ctx.plugin.inspection_complete = true
            -- Continue to response phase
        end
    end

    NanoHandler.processed_requests[session_id] = true
end

function NanoHandler.header_filter(conf)
    kong.log.err("22222222222222222222222--------------------------------------------------------------------------------------------------------------------------------------------------")
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        return
    end

    -- Skip if inspection already completed
    if ctx.inspection_complete then
        kong.log.debug("Inspection already completed, skipping header_filter")
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
    
    kong.log.warn("Response headers verdict: ", verdict, " (INSPECT=", nano.AttachmentVerdict.INSPECT, ", ACCEPT=", nano.AttachmentVerdict.ACCEPT, ", DROP=", nano.AttachmentVerdict.DROP, ")")
    
    -- Check verdict following Envoy pattern: if verdict != INSPECT, finalize
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    elseif verdict ~= nano.AttachmentVerdict.INSPECT then
        -- ACCEPT or other verdict - stop inspection but keep session alive until log phase
        kong.log.debug("Got final verdict (not INSPECT) in header_filter: ", verdict, " - session will be finalized in log phase")
        ctx.inspection_complete = true
        return
    end

    -- Only reach here if verdict == INSPECT - need to inspect body
    kong.log.debug("Got INSPECT verdict - continuing to body_filter")
    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    kong.log.err("3-3333333333333333333333333-------------------------------------------------------------------------------------------------------------------------------------------------")
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        return
    end

    -- Skip if inspection already completed
    if ctx.inspection_complete then
        kong.log.debug("Inspection already completed, skipping body_filter")
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data then
        kong.log.err("No session data found in body_filter")
        return
    end

    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

    -- Initialize on first call
    if not ctx.body_buffer_chunk then
        ctx.body_buffer_chunk = 0
        ctx.body_filter_start_time = ngx.now() * 1000
    end
    -- Check timeout (2.5 minutes)
    local current_time = ngx.now() * 1000
    if current_time - ctx.body_filter_start_time > 150000 then
        kong.log.warn("body_filter timeout exceeded (2.5 minutes), failing open")
        nano.fini_session(session_data)
        nano.cleanup_all()
        ctx.session_id = nil
        ctx.session_data = nil
        return
    end

    if chunk and #chunk > 0 then
        ctx.body_seen = true
        
        -- Send response body chunk
        local ok, result = pcall(function()
            return {nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)}
        end)

        if ok and result and result[1] then
            local verdict = result[1]
            local response = result[2]
            local modifications = result[3]

            kong.log.debug("Response body chunk verdict: ", verdict, " (chunk #", ctx.body_buffer_chunk, ")")

            if modifications then
                chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
                ngx.arg[1] = chunk
            end

            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

            -- Following Envoy pattern: check if verdict != INSPECT
            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                local custom_result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                ctx.session_id = nil
                ctx.session_data = nil
                return custom_result
            elseif verdict ~= nano.AttachmentVerdict.INSPECT then
                -- ACCEPT or other - stop inspection but keep session alive until log phase
                kong.log.debug("Got final verdict (not INSPECT) during body chunk: ", verdict, " - session will be finalized in log phase")
                ctx.inspection_complete = true
                return
            end
            -- Continue if verdict == INSPECT
        else
            kong.log.warn("nano.send_body failed, failing open: ", tostring(result))
            -- Continue processing, fail open
        end
    end

    -- Handle EOF - this is where we signal end of transaction and get final verdict
    if eof or (ctx.expect_body == false and not ctx.body_seen) then
        kong.log.debug("Reached EOF, sending RESPONSE_END signal")
        
        local ok, result = pcall(function()
            return {nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)}
        end)

        if ok and result and result[1] then
            local verdict = result[1]
            local response = result[2]

            kong.log.debug("Response END verdict: ", verdict)

            -- Following Envoy pattern: check verdict after RESPONSE_END
            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                local custom_result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                ctx.session_id = nil
                ctx.session_data = nil
                return custom_result
            elseif verdict ~= nano.AttachmentVerdict.INSPECT then
                -- ACCEPT or other - mark inspection complete, finalize in log phase
                kong.log.debug("Got final verdict at EOF: ", verdict, " - session will be finalized in log phase")
                ctx.inspection_complete = true
                return
            end
            -- If still INSPECT (shouldn't happen at EOF, but handle gracefully)
            kong.log.warn("Got INSPECT verdict at EOF - this is unexpected, finalizing anyway")
        else
            kong.log.warn("nano.end_inspection failed, failing open: ", tostring(result))
        end

        -- Mark inspection complete, actual cleanup in log phase
        ctx.inspection_complete = true
    end
end

-- log phase - equivalent to Envoy's OnDestroy
-- This is called when the last response byte has been sent to the client
function NanoHandler.log(conf)
    kong.log.err("4-44444444444444444444-------------------------------------------------------------------------------------------------------------------------------------------------")
    local ctx = kong.ctx.plugin
    
    -- Clean up session data if it exists
    if ctx.session_data then
        kong.log.debug("log phase: cleaning up session")
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_id = nil
        ctx.session_data = nil
    end
end

return NanoHandler