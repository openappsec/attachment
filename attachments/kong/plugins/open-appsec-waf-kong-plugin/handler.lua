local module_name = ...
local prefix = module_name:match("^(.-)handler$")
local nano = require(prefix .. "nano_ffi")
local nano_attachment = require "lua_attachment_wrapper"
local semaphore = require "ngx.semaphore"
local verdict_poller = require(prefix .. "lib.verdict_poller")
local verdict_handler = require(prefix .. "lib.verdict_handler")
local utils = require(prefix .. "lib.utils")
local kong = kong

local NanoHandler = {}

NanoHandler.PRIORITY = 3000
NanoHandler.VERSION = "1.0.0"

NanoHandler.sessions = {}

-- per-worker state
local pending = {} -- sid -> { semaphore }

function NanoHandler.init_worker()
    nano.init_attachment()
    
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if is_async_mode then
        kong.log.info("Initializing in async mode")
        verdict_poller.start_verdict_listener(nano, pending)
    else
        kong.log.info("Initializing in sync mode")
        if verdict_poller.is_started() then
            verdict_poller.stop_verdict_listener(pending)
        end
    end
end

local function handle_access_async(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    local sem = semaphore.new()
    local final_response = nil
    pending[session_id] = { sem = sem }
    ctx.fail_open_mode = false
    ctx.is_final_verdict = false

    local verdict, response
    local result = nano.send_data_async(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    if result ~= nano.NanoCommunicationResult.NANO_OK then
        kong.log.debug("send_data_async failed (session=", session_id, ", result=", result, ")")
        ctx.fail_open_mode = true
        goto cleanup
    end

    verdict, response = verdict_handler.wait_for_verdict_async(nano, sem, session_id, nano.get_req_header_thread_timeout, 3, ctx, "headers")
    if not verdict then
        ctx.fail_open_mode = true
        if response == "blocked" then
            ctx.is_final_verdict = true
            verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, nil, true, meta_data, req_headers, sem, pending)
            meta_data, req_headers = nil, nil
        end
        goto cleanup
    end

    ctx.session_data = session_data
    ctx.session_id = session_id
    ctx.session_finalized = false
    if nano.is_session_finalized(ctx.session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        ctx.session_finalized = true
        return
    end

    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.debug("Request blocked: headers (session=", session_id, ")")
        ctx.is_final_verdict = true
        final_response = response
        verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
        meta_data, req_headers = nil, nil
        goto cleanup
    elseif verdict == nano.AttachmentVerdict.ACCEPT then
        ctx.is_final_verdict = true
    end
    
    if response then
        nano.free_verdict_response(session_data, response)
        response = nil
    end

    if contains_body == 1 then
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            local body_result = nano.send_body_async(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if body_result ~= nano.NanoCommunicationResult.NANO_OK then
                kong.log.debug("send_body_async failed (session=", session_id, ", result=", body_result, ") - failing open")
                ctx.fail_open_mode = true
                goto cleanup
            end

            verdict, response = verdict_handler.wait_for_verdict_async(nano, sem, session_id, nano.get_req_body_thread_timeout, 3, ctx, "body")
            if not verdict then
                ctx.fail_open_mode = true
                if response == "blocked" then
                    ctx.is_final_verdict = true
                    verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, nil, true, meta_data, req_headers, sem, pending)
                    meta_data, req_headers = nil, nil
                end
                goto cleanup
            end
            
            verdict, response = verdict_handler.handle_delayed_verdict(nano, session_id, session_data, sem, verdict, response, pending)
            if not verdict then
                kong.log.debug("Freeing session (session=", session_id, ")")
                nano.fini_session(session_data)
                ctx.session_finalized = true
                ctx.fail_open_mode = true
                goto cleanup
            end
            
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.debug("Request blocked: body (session=", session_id, ")")
                ctx.is_final_verdict = true
                final_response = response
                verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
                meta_data, req_headers = nil, nil
                goto cleanup
            elseif verdict == nano.AttachmentVerdict.ACCEPT then
                ctx.is_final_verdict = true
            end
            
            if response then
                nano.free_verdict_response(session_data, response)
                response = nil
            end
        else
            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.debug("Request blocked: body from var (session=", session_id, ")")
                    ctx.is_final_verdict = true
                    final_response = response
                    verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
                    meta_data, req_headers = nil, nil
                    goto cleanup
                elseif verdict == nano.AttachmentVerdict.ACCEPT then
                    ctx.is_final_verdict = true
                end
                if response then
                    nano.free_verdict_response(session_data, response)
                    response = nil
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    verdict, response = utils.read_and_send_body_file_chunked(nano, body_file, session_id, session_data, nano.get_request_processing_timeout_sec(), ctx, true, sem, verdict_handler)
                    if not verdict then
                        ctx.fail_open_mode = true
                        goto cleanup
                    end
                    
                    verdict, response = verdict_handler.handle_delayed_verdict(nano, session_id, session_data, sem, verdict, response, pending)
                    if not verdict then
                        kong.log.debug("Freeing session (session=", session_id, ")")
                        nano.fini_session(session_data)
                        ctx.session_finalized = true
                        ctx.fail_open_mode = true
                        goto cleanup
                    end
                    
                    if verdict == nano.AttachmentVerdict.DROP then
                        kong.log.debug("Request blocked: body from file (session=", session_id, ")")
                        ctx.is_final_verdict = true
                        final_response = response
                        verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
                        meta_data, req_headers = nil, nil  -- Resources freed by handle_drop_verdict
                        goto cleanup
                    elseif verdict == nano.AttachmentVerdict.ACCEPT then
                        ctx.is_final_verdict = true
                    end
                    if response then
                        nano.free_verdict_response(session_data, response)
                        response = nil
                    end
                else
                    kong.log.warn("Request body expected but not available (session=", session_id, ")")
                end
            end
        end

        local ok, result  = pcall(function()
            return nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.debug("Error ending request inspection (session=", session_id, ", error=", result, ")")
            ctx.fail_open_mode = true
            goto cleanup
        end

        if result ~= nano.NanoCommunicationResult.NANO_OK then
            kong.log.debug("end_inspection_async failed (session=", session_id, ", result=", result, ")")
            ctx.fail_open_mode = true
            goto cleanup
        end

        verdict, response = verdict_handler.wait_for_verdict_async(nano, sem, session_id, nano.get_req_body_thread_timeout, 3, ctx, "end inspection")
        if not verdict then
            ctx.fail_open_mode = true
            if response == "blocked" then
                ctx.is_final_verdict = true
                kong.response.exit(403, "Request blocked")
            end
            goto cleanup
        end

        verdict, response = verdict_handler.handle_delayed_verdict(nano, session_id, session_data, sem, verdict, response, pending)
        if not verdict then
            kong.log.debug("Freeing session (session=", session_id, ")")
            nano.fini_session(session_data)
            ctx.session_finalized = true
            ctx.fail_open_mode = true
            goto cleanup
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.debug("Request blocked: end inspection (session=", session_id, ")")
            ctx.is_final_verdict = true
            final_response = response
            verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
            meta_data, req_headers = nil, nil  -- Resources freed by handle_drop_verdict
            goto cleanup
        elseif verdict == nano.AttachmentVerdict.ACCEPT then
            ctx.is_final_verdict = true
        end
        
        -- Free end inspection verdict response after handling it
        if response then
            nano.free_verdict_response(session_data, response)
            response = nil
        end
    else
        local end_result = nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if end_result ~= nano.NanoCommunicationResult.NANO_OK then
            kong.log.debug("end_inspection_async failed (session=", session_id, ", result=", end_result, ")")
            ctx.fail_open_mode = true
            goto cleanup
        end

        verdict, response = verdict_handler.wait_for_verdict_async(nano, sem, session_id, nano.get_req_header_thread_timeout, 3, ctx, "end inspection (no body)")
        if not verdict then
            ctx.fail_open_mode = true
            if response == "blocked" then
                ctx.is_final_verdict = true
                kong.response.exit(403, "Request blocked")
            end
            goto cleanup
        end

        -- Handle DELAYED verdict
        verdict, response = verdict_handler.handle_delayed_verdict(nano, session_id, session_data, sem, verdict, response, pending)
        if not verdict then
            kong.log.debug("Freeing session (session=", session_id, ")")
            nano.fini_session(session_data)
            ctx.session_finalized = true
            ctx.fail_open_mode = true
            goto cleanup
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.debug("Request blocked: end inspection (session=", session_id, ")")
            ctx.is_final_verdict = true
            final_response = response
            verdict_handler.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, true, meta_data, req_headers, sem, pending)
            meta_data, req_headers = nil, nil  -- Resources freed by handle_drop_verdict
            goto cleanup
        elseif verdict == nano.AttachmentVerdict.ACCEPT then
            ctx.is_final_verdict = true
        end
        
        if response then
            nano.free_verdict_response(session_data, response)
            response = nil
        end
    end

    ::cleanup::
    if final_response then
        nano.free_verdict_response(session_data, final_response)
    end
    utils.free_async_resources(nano, nano_attachment, nil, meta_data, req_headers, nil)
    pending[session_id] = nil
end

local function handle_access_sync(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    ctx.is_final_verdict = false
    local verdict, response = nano.send_data(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)
    if verdict ~= nano.AttachmentVerdict.INSPECT then
        ctx.cleanup_needed = true
        if verdict == nano.AttachmentVerdict.DROP then
            ctx.is_final_verdict = true
            return nano.handle_custom_response(session_data, response)
        elseif verdict == nano.AttachmentVerdict.ACCEPT then
            ctx.is_final_verdict = true
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
                    ctx.is_final_verdict = true
                    return nano.handle_custom_response(session_data, response)
                elseif verdict == nano.AttachmentVerdict.ACCEPT then
                    ctx.is_final_verdict = true
                end
                return
            end
        else
            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                if verdict ~= nano.AttachmentVerdict.INSPECT then
                    ctx.cleanup_needed = true
                    if verdict == nano.AttachmentVerdict.DROP then
                        ctx.is_final_verdict = true
                        return nano.handle_custom_response(session_data, response)
                    elseif verdict == nano.AttachmentVerdict.ACCEPT then
                        ctx.is_final_verdict = true
                    end
                    return
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    verdict, response = utils.read_and_send_body_file_chunked(nano, body_file, session_id, session_data, nano.get_request_processing_timeout_sec(), ctx, false, nil, nil)
                    if not verdict then
                        return
                    end
                    if verdict ~= nano.AttachmentVerdict.INSPECT then
                        ctx.cleanup_needed = true
                        if verdict == nano.AttachmentVerdict.DROP then
                            ctx.is_final_verdict = true
                            return nano.handle_custom_response(session_data, response)
                        elseif verdict == nano.AttachmentVerdict.ACCEPT then
                            ctx.is_final_verdict = true
                        end
                        return
                    end
                else
                    kong.log.err("Request body expected but no body data or file available")
                end
            end
        end

        local ok, verdict, response = pcall(function()
            return nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.debug("Error ending request inspection: ", verdict, " - failing open")
            ctx.cleanup_needed = true
            return
        end

        if verdict ~= nano.AttachmentVerdict.INSPECT then
            ctx.cleanup_needed = true
            if verdict == nano.AttachmentVerdict.DROP then
                ctx.is_final_verdict = true
                return nano.handle_custom_response(session_data, response)
            elseif verdict == nano.AttachmentVerdict.ACCEPT then
                ctx.is_final_verdict = true
            end
            return
        end
    end
end

function NanoHandler.access(conf)
    local ctx = kong.ctx.plugin
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()

    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.ctx.plugin.cleanup_needed = false
        return
    end

    ctx.session_data = session_data
    ctx.session_id = session_id
    
    if is_async_mode and not verdict_poller.is_started() then
        kong.log.info("Starting verdict listener in access phase")
        verdict_poller.start_verdict_listener(nano, pending)
    elseif not is_async_mode and verdict_poller.is_started() then
        kong.log.info("Stopping verdict listener (async mode disabled)")
        verdict_poller.stop_verdict_listener(pending)
    end

    if nano.is_session_finalized(session_data) then
        return
    end
    
    local meta_data = nano.handle_start_transaction()
    if not meta_data then
        ctx.cleanup_needed = true
        return
    end
    
    local req_headers = nano.handleHeaders(headers)
    if not req_headers then
        ctx.cleanup_needed = true
        return
    end

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0
    
    if is_async_mode then
        return handle_access_async(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    else
        return handle_access_sync(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    end
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    
    if ctx.blocked or ctx.fail_open_mode or ctx.is_final_verdict then
        return
    end

    if ctx.session_finalized then
        kong.log.debug("Session has already been finalized, no need for further inspection")
        return
    end

    if nano.is_session_finalized(ctx.session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        ctx.session_finalized = true
        return
    end

    if ctx.cleanup_needed then
        return
    end

    kong.log.debug("Processing response headers (session=", ctx.session_id, ")")
    local session_id = ctx.session_id
    local session_data = ctx.session_data

    local headers = kong.response.get_headers()
    local header_data = nano.handleHeaders(headers)
    
    if not header_data then
        kong.log.debug("Failed to handle response headers - failing open")
        ctx.cleanup_needed = true
        return
    end

    local status_code = kong.response.get_status()
    local content_length = tonumber(headers["content-length"]) or 0
    
    local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
    if verdict ~= nano.AttachmentVerdict.INSPECT then
        ctx.cleanup_needed = true
        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.debug("Response blocked: headers (session=", session_id, ")")
            return nano.handle_custom_response(session_data, response)
        end
        ngx.header["Content-Length"] = nil
        return
    end

    ngx.header["Content-Length"] = nil
    
    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    
    if ctx.blocked or ctx.fail_open_mode or ctx.is_final_verdict then
        return
    end

    if nano.is_session_finalized(ctx.session_data) then
        return
    end

    if ctx.cleanup_needed then
        return
    end

    kong.log.debug("Processing response body chunk (session=", ctx.session_id, ")")
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]
    
    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if ctx.session_finalized then
        kong.log.debug("Session has already been finalized, no need for further inspection")
        return
    end
    
    if nano.is_session_finalized(session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        ctx.session_finalized = true
        return
    end
    
    if ctx.cleanup_needed then
        return
    end

    if not ctx.body_filter_start_time then
        ctx.body_filter_start_time = ngx.now()
        ctx.body_filter_timeout_sec = nano.get_response_processing_timeout_sec()
    end
    
    local elapsed_time = ngx.now() - ctx.body_filter_start_time
    if elapsed_time > ctx.body_filter_timeout_sec then
        kong.log.debug("Response body filter timeout (", elapsed_time, "s) - failing open")
        ctx.cleanup_needed = true
        return
    end

    if chunk and #chunk > 0 then
        ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0
        ctx.body_seen = true

        local verdict, response, modifications = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)
        
        if modifications then
            chunk = nano.handle_body_modifications(chunk, modifications, ctx.body_buffer_chunk)
        end

        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

        if verdict ~= nano.AttachmentVerdict.INSPECT then
            ctx.cleanup_needed = true
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.debug("Response blocked: streaming body (session=", session_id, ")")
                ngx.header["Connection"] = "close"
                ngx.arg[1] = ""
                ngx.arg[2] = true
                return
            end
        end
        
        ngx.arg[1] = chunk
        return
    end

    if eof then
        if ctx.body_seen or ctx.expect_body == false then
            ctx.cleanup_needed = true
            local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
            if verdict ~= nano.AttachmentVerdict.INSPECT then
                ctx.cleanup_needed = true
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.debug("Response blocked: EOF (session=", session_id, ")")
                    ngx.header["Connection"] = "close"
                    ngx.arg[1] = ""
                    ngx.arg[2] = true
                    return
                end
            end
        end
        
    end
end

function NanoHandler.log(conf)
    local ctx = kong.ctx.plugin
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if ctx.cleanup_needed and ctx.session_data and not is_async_mode then
        kong.log.debug("Finalizing session in log phase (session=", ctx.session_id, ")")
        if not ctx.session_finalized then
            kong.log.debug("Freeing session (session=", ctx.session_id, ")")
            nano.fini_session(ctx.session_data)
            ctx.session_finalized = true
        end
        nano.cleanup_all()
        ctx.session_data = nil
        ctx.session_id = nil
        collectgarbage("collect")
    end
end

return NanoHandler
