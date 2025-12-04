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
    kong.log.debug("1-ACCESS PHASE START ========================================")
    
    if not kong.router.get_route() then
        kong.log.debug("ACCESS SKIPPED: no route matched")
        return
    end
    
    local request_path = kong.request.get_path()
    if request_path and (
        request_path:match("^/status") or 
        request_path:match("^/_health") or
        request_path:match("^/metrics")
    ) then
        kong.log.debug("ACCESS SKIPPED: internal endpoint: ", request_path)
        return
    end
    
    if ngx.var.internal then
        kong.log.debug("ACCESS SKIPPED: internal subrequest")
        return
    end
    
    local request_uri = ngx.var.request_uri
    if not request_uri or request_uri == "" then
        kong.log.debug("ACCESS SKIPPED: TLS handshake or no URI")
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
        kong.log.err("Failed to initialize session - failing open (no session created)")
        kong.ctx.plugin.inspection_complete = true
        return
    end

    kong.ctx.plugin.session_data = session_data
    kong.ctx.plugin.session_id = session_id

    local meta_data = nano.handle_start_transaction()
    if not meta_data then
        kong.log.err("Failed to handle start transaction - cleaning up session and failing open")
        kong.ctx.plugin.inspection_complete = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        kong.ctx.plugin.session_id = nil
        kong.ctx.plugin.session_data = nil
        return
    end
    
    local req_headers = nano.handleHeaders(headers)

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0

    local verdict, response = nano.send_data(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    
    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.err("DROP verdict in access/send_data - session_id: ", session_id)
        kong.ctx.plugin.blocked = true
        kong.ctx.plugin.inspection_complete = true
        local result = nano.handle_custom_response(session_data, response)
        nano.fini_session(session_data)
        nano.cleanup_all()
        kong.ctx.plugin.session_id = nil
        kong.ctx.plugin.session_data = nil
        return result
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            verdict, response = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.err("DROP verdict in access/send_body (raw) - session_id: ", session_id)
                kong.ctx.plugin.blocked = true
                kong.ctx.plugin.inspection_complete = true
                local result = nano.handle_custom_response(session_data, response)
                nano.fini_session(session_data)
                nano.cleanup_all()
                kong.ctx.plugin.session_id = nil
                kong.ctx.plugin.session_data = nil
                return result
            end
            -- Free body from memory after sending
            body = nil
            collectgarbage("step", 100)
        else
            kong.log.err("Request body not in memory, attempting to read from buffer/file")

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.err("Found request body in nginx var, size: ", #body_data)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.err("DROP verdict in access/send_body (var) - session_id: ", session_id)
                    kong.ctx.plugin.blocked = true
                    kong.ctx.plugin.inspection_complete = true
                    local result = nano.handle_custom_response(session_data, response)
                    nano.fini_session(session_data)
                    nano.cleanup_all()
                    kong.ctx.plugin.session_id = nil
                    kong.ctx.plugin.session_data = nil
                    return result
                end
                -- Free body_data from memory
                body_data = nil
                collectgarbage("step", 100)
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
                                kong.log.err("DROP verdict in access/send_body (file) - session_id: ", session_id)
                                kong.ctx.plugin.blocked = true
                                kong.ctx.plugin.inspection_complete = true
                                local result = nano.handle_custom_response(session_data, response)
                                nano.fini_session(session_data)
                                nano.cleanup_all()
                                kong.ctx.plugin.session_id = nil
                                kong.ctx.plugin.session_data = nil
                                return result
                            end
                            -- Free entire_body from memory
                            entire_body = nil
                            collectgarbage("step", 100)
                        else
                            kong.log.err("Empty body file")
                        end
                    end
                else
                    kong.log.err("Request body expected but no body data or file available")
                end
            end
        end
    end

    -- End request inspection
    local ok, verdict, response = pcall(function()
        return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
    end)

    if not ok then
        kong.log.err("Error ending request inspection: ", verdict, " - failing open")
        kong.ctx.plugin.inspection_complete = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        collectgarbage("collect")
        kong.ctx.plugin.session_id = nil
        kong.ctx.plugin.session_data = nil
        return
    end

    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.err("DROP verdict in access/end_inspection - session_id: ", session_id)
        kong.ctx.plugin.blocked = true
        kong.ctx.plugin.inspection_complete = true
        local result = nano.handle_custom_response(session_data, response)
        nano.fini_session(session_data)
        nano.cleanup_all()
        kong.ctx.plugin.session_id = nil
        kong.ctx.plugin.session_data = nil
        return result
    end

    NanoHandler.processed_requests[session_id] = true
end

function NanoHandler.header_filter(conf)
    kong.log.debug("2-HEADER_FILTER PHASE START")
    local ctx = kong.ctx.plugin
    
    if ctx.blocked or ctx.inspection_complete then
        return
    end

    if not ctx.session_id or not ctx.session_data then
        kong.log.debug("No session data in header_filter")
        return
    end

    local headers = kong.response.get_headers()
    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0
    
    local ok, verdict, response = pcall(function()
        return nano.send_response_headers(ctx.session_id, ctx.session_data, nano.handleHeaders(headers), status_code, content_length)
    end)
    
    if not ok then
        kong.log.err("send_response_headers failed: ", tostring(verdict))
        ctx.inspection_complete = true
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        collectgarbage("collect")
        ctx.session_id = nil
        ctx.session_data = nil
        return
    end
    
    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.err("DROP verdict in header_filter - session_id: ", ctx.session_id)
        ctx.blocked = true
        ctx.inspection_complete = true
        local result = nano.handle_custom_response(ctx.session_data, response)
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_id = nil
        ctx.session_data = nil
        return result
    elseif verdict == nano.AttachmentVerdict.ACCEPT then
        kong.log.debug("ACCEPT verdict in header_filter - marking inspection complete")
        ctx.inspection_complete = true
    end
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    local eof = ngx.arg[2]
    
    -- Log first chunk only
    if not ctx.body_filter_start_time then
        kong.log.debug("3-BODY_FILTER PHASE START")
        ctx.body_filter_start_time = ngx.now() * 1000
    end
    
    -- Fast path: skip if already blocked
    if ctx.blocked then
        ngx.arg[1] = nil  -- Discard chunk if blocked
        collectgarbage("step", 100)
        return
    end

    if not ctx.session_id or not ctx.session_data then
        ngx.arg[1] = nil
        collectgarbage("step", 100)
        return
    end
    
    -- CRITICAL: Check if session is finalized (exactly like Envoy does)
    -- This prevents sending chunks after final verdict received
    if ctx.inspection_complete or nano.is_session_finalized(ctx.session_data) then
        kong.log.debug("Session already finalized - skipping inspection")
        return
    end
    
    -- Check timeout (150 seconds)
    local elapsed = (ngx.now() * 1000) - ctx.body_filter_start_time
    if elapsed > 150000 then
        kong.log.err("Timeout after ", elapsed, "ms - cleaning up session")
        ngx.arg[1] = nil  -- Discard chunk first
        ctx.inspection_complete = true
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        collectgarbage("collect")
        ctx.session_id = nil
        ctx.session_data = nil
        return
    end
    
    -- Read chunk for active inspection
    local chunk = ngx.arg[1]
    
    if chunk and #chunk > 0 then
        local ok, result = pcall(function()
            return {nano.send_body(ctx.session_id, ctx.session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)}
        end)

        if ok then
            local verdict = result[1]
            local response = result[2]
            local modifications = result[3]

            if modifications then
                chunk = nano.handle_body_modifications(chunk, modifications, 0)
                ngx.arg[1] = chunk
            end

            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.err("DROP verdict in body_filter/send_body - session_id: ", ctx.session_id)
                ctx.blocked = true
                ctx.inspection_complete = true
                local result = nano.handle_custom_response(ctx.session_data, response)
                nano.fini_session(ctx.session_data)
                nano.cleanup_all()
                ctx.session_id = nil
                ctx.session_data = nil
                return result
            elseif verdict == nano.AttachmentVerdict.ACCEPT then
                -- Final ACCEPT verdict received - mark complete but don't cleanup yet (wait for EOF)
                kong.log.debug("ACCEPT verdict received - session finalized")
                ctx.inspection_complete = true
            end
            
            -- Incremental GC after processing chunk
            chunk = nil
            collectgarbage("step", 100)
        else
            kong.log.err("nano.send_body failed: ", tostring(result), " - cleaning up session")
            ctx.inspection_complete = true
            nano.fini_session(ctx.session_data)
            nano.cleanup_all()
            collectgarbage("collect")
            ctx.session_id = nil
            ctx.session_data = nil
            return
        end
    end

    -- Process EOF
    if eof then
        -- Only send end_inspection if we haven't already finalized
        if not ctx.inspection_complete then
            local ok, result = pcall(function()
                return {nano.end_inspection(ctx.session_id, ctx.session_data, nano.HttpChunkType.HTTP_RESPONSE_END)}
            end)

            if ok then
                local verdict = result[1]
                local response = result[2]

                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.err("DROP verdict in body_filter/end_inspection - session_id: ", ctx.session_id)
                    ctx.blocked = true
                    ctx.inspection_complete = true
                    local result = nano.handle_custom_response(ctx.session_data, response)
                    nano.fini_session(ctx.session_data)
                    nano.cleanup_all()
                    ctx.session_id = nil
                    ctx.session_data = nil
                    return result
                end
            else
                kong.log.err("nano.end_inspection failed: ", tostring(result), " - cleaning up session")
            end
        end
        
        -- CRITICAL: Always cleanup session at EOF, even if inspection_complete is true
        -- This ensures ACCEPT verdict sessions get cleaned up
        if ctx.session_data then
            nano.fini_session(ctx.session_data)
            nano.cleanup_all()
            collectgarbage("collect")
            ctx.session_id = nil
            ctx.session_data = nil
        end
    end
end

function NanoHandler.log(conf)
    kong.log.debug("4-LOG PHASE START")
    local ctx = kong.ctx.plugin
    
    -- Force GC if memory is high
    local mem_before = collectgarbage("count")
    if mem_before > 10240 then
        kong.log.err("High memory: ", string.format("%.2f", mem_before), " KB - forcing GC")
        collectgarbage("collect")
        local mem_after = collectgarbage("count")
        kong.log.err("Memory after GC: ", string.format("%.2f", mem_after), " KB (freed ", string.format("%.2f", mem_before - mem_after), " KB)")
    end
    
    -- Log memory periodically
    if ngx.worker.id() == 0 then
        local request_count = ngx.shared.kong_cache and ngx.shared.kong_cache:incr("request_count", 1, 0) or 0
        if request_count % 100 == 0 then
            local mem_kb = collectgarbage("count")
            kong.log.err("Lua memory: ", string.format("%.2f", mem_kb), " KB")
        end
    end
    
    -- Emergency cleanup if body_filter never completed
    if ctx.session_id and ctx.session_data and not ctx.inspection_complete then
        kong.log.err("Emergency cleanup for session ", ctx.session_id)
        nano.fini_session(ctx.session_data)
        collectgarbage("collect")
        ctx.inspection_complete = true
        ctx.session_id = nil
        ctx.session_data = nil
    end
end

return NanoHandler
