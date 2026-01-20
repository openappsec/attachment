local module_name = ...
local prefix = module_name:match("^(.-)handler$")
local nano = require(prefix .. "nano_ffi")
local semaphore = require "ngx.semaphore"
local ffi = require "ffi"
local kong = kong

-- FFI declarations for socket operations
ffi.cdef[[
    typedef long ssize_t;
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);
]]

local NanoHandler = {}

NanoHandler.PRIORITY = 3000
NanoHandler.VERSION = "1.0.0"

NanoHandler.sessions = {}

-- per-worker state
local pending = {} -- sid -> { semaphore }
local verdict_listener_started = false

local function drain_queue()
    kong.log.debug("drain_queue: Starting to drain queue")
    local drained_count = 0
    while not nano.is_queue_empty() do
        local session_id = nano.pop_from_queue()
        if session_id and session_id > 0 then
            kong.log.debug("drain_queue: Popped session_id=", session_id)
            local session_info = pending[session_id]
            if session_info and session_info.sem then
                kong.log.debug("drain_queue: Notifying semaphore for session_id=", session_id)
                session_info.sem:post()
                drained_count = drained_count + 1
            else
                kong.log.warn("drain_queue: No semaphore found for session_id=", session_id)
            end
        end
    end
    kong.log.debug("drain_queue: Drained ", drained_count, " sessions")
end

local function get_timeout_and_fail_mode(timeout_getter_fn, default_timeout_sec)
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    local timeout = is_async_mode and (timeout_getter_fn() / 1000.0) or default_timeout_sec
    local fail_mode_verdict = is_async_mode and nano.get_fail_mode_verdict() or 0
    return timeout, fail_mode_verdict
end

local function handle_drop_verdict(ctx, session_id, session_data, response, is_async)
    if is_async then
        ctx.blocked = true
    else
        ctx.cleanup_needed = true
    end
    local result = nano.handle_custom_response(session_data, response)
    nano.fini_session(session_data)
    nano.cleanup_all()
    return result
end

local function wait_for_verdict_async(sem, session_id, timeout_getter_fn, default_timeout, ctx, log_context)
    local timeout, fail_mode_verdict = get_timeout_and_fail_mode(timeout_getter_fn, default_timeout)
    kong.log.debug("access: Waiting for ", log_context, " verdict for session_id=", session_id, " timeout=", timeout)
    local ok, err = sem:wait(timeout)
    
    if not ok then
        local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
        kong.log.err("access: Timeout while waiting for ", log_context, " verdict for session_id=", session_id, " err=", err or "nil", " - ", fail_action)
        nano.fini_session(nil)  -- session_data will be accessed from ctx in caller
        nano.cleanup_all()
        if fail_mode_verdict ~= 0 then
            ctx.blocked = true
            return nil, "blocked"
        end
        return nil, "timeout"
    end
    
    -- Query verdict after semaphore wakeup
    kong.log.debug("access: Querying ", log_context, " verdict for session_id=", session_id)
    local verdict, response = nano.get_attachment_verdict_response(session_id)
    kong.log.debug("access: ", log_context, " verdict=", verdict, " for session_id=", session_id)
    return verdict, response
end

local function read_body_from_file(body_file, session_id, session_data, is_async, ctx)
    kong.log.debug("access: Reading request body from file=", body_file, " for session_id=", session_id)
    local file, open_err = io.open(body_file, "rb")
    if not file then
        kong.log.err("access: Failed to open body file=", body_file, " err=", open_err or "nil", " for session_id=", session_id)
        return nil, nil
    end
    
    if is_async then
        -- Read entire file at once for async mode
        local entire_body = file:read("*all")
        file:close()
        if entire_body and #entire_body > 0 then
            kong.log.debug("access: Sending entire body from file, size=", #entire_body, " bytes for session_id=", session_id)
            local verdict, response = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_REQUEST_BODY)
            kong.log.debug("access: File body verdict=", verdict, " for session_id=", session_id)
            return verdict, response
        else
            kong.log.debug("access: Empty body file for session_id=", session_id)
        end
    else
        -- Chunked reading for sync mode with timeout
        local chunk_size = 8192
        local chunk_count = 0
        local start_time = ngx.now()
        local timeout_sec = nano.get_request_processing_timeout_sec()
        kong.log.debug("Request body reading timeout set to ", timeout_sec, " seconds")
        
        while true do
            ngx.update_time()
            local current_time = ngx.now()
            local elapsed = current_time - start_time
            
            if elapsed > timeout_sec then
                ctx.cleanup_needed = true
                kong.log.warn("Request body reading timeout after ", elapsed, " seconds")
                file:close()
                return nil, nil
            end
            
            local chunk = file:read(chunk_size)
            if not chunk or #chunk == 0 then
                kong.log.debug("End of request body file reached")
                break
            end
            
            chunk_count = chunk_count + 1
            kong.log.debug("Sending request body chunk ", chunk_count, " of size ", #chunk, " bytes to C module")
            local verdict, response = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_REQUEST_BODY)
            
            if verdict ~= nano.AttachmentVerdict.INSPECT then
                file:close()
                return verdict, response
            end
        end
        file:close()
        kong.log.debug("Sent ", chunk_count, " chunks from request body file")
    end
    return nano.AttachmentVerdict.INSPECT, nil
end

local function handle_delayed_verdict(session_id, session_data, sem, verdict, response)
    if verdict ~= nano.AttachmentVerdict.DELAYED then
        return verdict, response
    end
    
    kong.log.info("handle_delayed_verdict: Initial verdict DELAYED for session_id=", session_id)
    
    -- Drain any pending semaphore posts to ensure we wait for NEW verdicts
    while sem:wait(0) do
        kong.log.debug("handle_delayed_verdict: Drained pending semaphore post for session_id=", session_id)
    end
    
    local start_time = ngx.now()
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    local max_timeout_ms = is_async_mode and nano.get_request_processing_timeout() or 3000
    local max_timeout = max_timeout_ms / 1000.0
    local polling_time_ms = is_async_mode and (nano.get_hold_verdict_polling_time() * 50) or 50
    local polling_time = polling_time_ms / 1000.0
    local fail_mode_verdict = is_async_mode and nano.get_fail_mode_verdict() or 0

    ngx.sleep(polling_time)
    nano.send_wait_signal(session_id, session_data)
    
    while verdict == nano.AttachmentVerdict.DELAYED do
        local elapsed = ngx.now() - start_time
        if elapsed >= max_timeout then
            local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
            kong.log.warn("handle_delayed_verdict: Total timeout reached for session_id=", session_id, " - ", fail_action)
            nano.fini_session(session_data)
            nano.cleanup_all()
            pending[session_id] = nil
            return nil, nil
        end
        
        -- Calculate remaining timeout
        local remaining = max_timeout - elapsed
        
        kong.log.debug("handle_delayed_verdict: Waiting for verdict notification, remaining=", remaining, " for session_id=", session_id)
        local ok, err = sem:wait(remaining)
        
        if ok then
            -- Got a notification, check the verdict
            verdict, response = nano.get_attachment_verdict_response(session_id)
            kong.log.info("handle_delayed_verdict: Received verdict notification, verdict=", verdict, " for session_id=", session_id)
            
            -- If still DELAYED, send wait signal and continue
            if verdict == nano.AttachmentVerdict.DELAYED then
                kong.log.info("handle_delayed_verdict: Verdict still DELAYED, sending wait signal for session_id=", session_id)
                nano.send_wait_signal(session_id, session_data)
                ngx.sleep(polling_time)
            end
        else
            -- Timeout waiting for notification
            if err == "timeout" then
                local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
                kong.log.warn("handle_delayed_verdict: No verdict received within timeout for session_id=", session_id, " - ", fail_action)
                nano.fini_session(session_data)
                nano.cleanup_all()
                pending[session_id] = nil
                return nil, nil
            else
                local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
                kong.log.err("handle_delayed_verdict: Semaphore error for session_id=", session_id, " err=", err, " - ", fail_action)
                nano.fini_session(session_data)
                nano.cleanup_all()
                pending[session_id] = nil
                return nil, nil
            end
        end
    end
    
    kong.log.debug("handle_delayed_verdict: Exited loop with verdict=", verdict, " for session_id=", session_id)
    return verdict, response
end

local function start_verdict_listener()
    if verdict_listener_started then
        kong.log.debug("Verdict listener already started, skipping")
        return true
    end

    local socket_fd = nano.get_attachment_socket()
    if not socket_fd or socket_fd < 0 then
        kong.log.err("Failed to get attachment socket")
        verdict_listener_started = false
        return false
    end

    kong.log.info("Starting verdict listener on socket fd: ", socket_fd, " with periodic draining")

    -- Use a recurring timer to periodically check and drain the socket and queue
    local function periodic_drain(premature)
        if premature then
            kong.log.info("verdict_listener: Timer premature, stopping")
            verdict_listener_started = false
            return
        end

        -- Drain the socket (doorbell notifications)
        local buf = ffi.new("char[1024]")
        local bytes_read = ffi.C.recv(socket_fd, buf, 1024, 0x40) -- MSG_DONTWAIT = 0x40
        if bytes_read > 0 then
            kong.log.debug("verdict_listener: Drained ", bytes_read, " bytes from socket")
        elseif bytes_read < 0 then
            local errno = ffi.errno()
            -- EAGAIN (11) or EWOULDBLOCK means no data available, which is fine
            if errno ~= 11 then
                kong.log.debug("verdict_listener: Socket recv error, errno=", errno)
            end
        end

        -- Drain the queue if it has data
        if not nano.is_queue_empty() then
            kong.log.debug("verdict_listener: Queue not empty, draining")
            local ok, drain_err = pcall(drain_queue)
            if not ok then
                kong.log.err("verdict_listener: Error draining queue: ", drain_err)
            end
        end

        -- Schedule next check - use small interval for responsiveness (10ms)
        local ok, err = ngx.timer.at(0.01, periodic_drain)
        if not ok then
            kong.log.err("verdict_listener: Failed to reschedule timer: ", err, " - marking listener as stopped")
            verdict_listener_started = false
        end
    end

    -- Start the periodic timer
    local ok, err = ngx.timer.at(0.01, periodic_drain)
    if not ok then
        kong.log.err("verdict_listener: Failed to start timer: ", err)
        verdict_listener_started = false
        return false
    end

    verdict_listener_started = true
    kong.log.info("verdict_listener: Started successfully with 10ms polling interval on socket fd: ", socket_fd)
    return true
end

function NanoHandler.init_worker()
    nano.init_attachment()
    
    -- Only start verdict listener in async mode
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if is_async_mode then
        kong.log.info("Async mode enabled - starting verdict listener")
        start_verdict_listener()
    else
        kong.log.info("Sync mode enabled - verdict listener not started")
    end
end

local function handle_access_async(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    local sem = semaphore.new()
    pending[session_id] = { sem = sem, verdict = nil }

    -- Use non-blocking send_data_async
    kong.log.debug("access: Sending headers async for session_id=", session_id, " contains_body=", contains_body)
    nano.send_data_async(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)

    -- Wait for verdict
    local verdict, response = wait_for_verdict_async(sem, session_id, nano.get_req_header_thread_timeout, 3, ctx, "headers")
    if not verdict then
        if response == "blocked" then
            return kong.response.exit(403, "Request blocked")
        end
        return
    end

    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.warn("access: Headers verdict DROP for session_id=", session_id)
        return handle_drop_verdict(ctx, session_id, session_data, response, true)
    end
    kong.log.debug("access: Headers verdict ACCEPT for session_id=", session_id)

    if contains_body == 1 then
        kong.log.debug("access: Request contains body for session_id=", session_id)
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            -- Use non-blocking send_body_async
            kong.log.debug("access: Sending body async, size=", #body, " for session_id=", session_id)
            nano.send_body_async(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)

            -- Wait for verdict
            verdict, response = wait_for_verdict_async(sem, session_id, nano.get_req_body_thread_timeout, 3, ctx, "body")
            if not verdict then
                if response == "blocked" then
                    return kong.response.exit(403, "Request blocked")
                end
                return
            end
            
            -- Handle DELAYED verdict
            verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
            if not verdict then
                return
            end
            
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("access: Body verdict DROP for session_id=", session_id)
                return handle_drop_verdict(ctx, session_id, session_data, response, true)
            end
        else
            kong.log.debug("access: Request body not in memory, attempting to read from buffer/file for session_id=", session_id)

            local body_data = ngx.var.request_body
            if body_data and #body_data > 0 then
                kong.log.debug("access: Found request body in nginx var, size=", #body_data, " for session_id=", session_id)
                verdict, response = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_REQUEST_BODY)
                kong.log.debug("access: Nginx var body verdict=", verdict, " for session_id=", session_id)
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.warn("access: Nginx var body verdict DROP for session_id=", session_id)
                    return handle_drop_verdict(ctx, session_id, session_data, response, true)
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    verdict, response = read_body_from_file(body_file, session_id, session_data, true, ctx)
                    if verdict == nano.AttachmentVerdict.DROP then
                        kong.log.warn("access: File body verdict DROP for session_id=", session_id)
                        return handle_drop_verdict(ctx, session_id, session_data, response, true)
                    end
                else
                    kong.log.warn("access: Request body expected but no body data or file available for session_id=", session_id)
                end
            end
        end

        kong.log.debug("access: Ending request inspection (with body) for session_id=", session_id)
        local ok, result  = pcall(function()
            return nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        end)

        if not ok then
            kong.log.err("access: Error ending request inspection for session_id=", session_id, " err=", result, " - failing open")
            nano.fini_session(session_data)
            nano.cleanup_all()
            return
        end

        -- Wait for verdict
        verdict, response = wait_for_verdict_async(sem, session_id, nano.get_req_body_thread_timeout, 3, ctx, "end inspection")
        if not verdict then
            if response == "blocked" then
                return kong.response.exit(403, "Request blocked")
            end
            return
        end

        -- Handle DELAYED verdict
        verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
        if not verdict then
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP for session_id=", session_id)
            return handle_drop_verdict(ctx, session_id, session_data, response, true)
        end
    else
        kong.log.debug("access: Ending request inspection (no body) for session_id=", session_id)
        nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)

        -- Wait for verdict
        verdict, response = wait_for_verdict_async(sem, session_id, nano.get_req_header_thread_timeout, 3, ctx, "end inspection (no body)")
        if not verdict then
            if response == "blocked" then
                return kong.response.exit(403, "Request blocked")
            end
            return
        end

        -- Handle DELAYED verdict
        verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
        if not verdict then
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP (no body) for session_id=", session_id)
            return handle_drop_verdict(ctx, session_id, session_data, response, true)
        end
    end

    kong.log.debug("access: Request processing complete for session_id=", session_id)
    pending[session_id] = nil
end

local function handle_access_sync(ctx, session_id, session_data, meta_data, req_headers, contains_body)
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
                kong.log.debug("access: Found request body in nginx var, size=", #body_data, " for session_id=", session_id)
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
                    verdict, response = read_body_from_file(body_file, session_id, session_data, false, ctx)
                    if not verdict then
                        return
                    end
                    if verdict ~= nano.AttachmentVerdict.INSPECT then
                        ctx.cleanup_needed = true
                        if verdict == nano.AttachmentVerdict.DROP then
                            return nano.handle_custom_response(session_data, response)
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
                return nano.handle_custom_response(session_data, response)
            end
            return
        end
    end
end

function NanoHandler.access(conf)
    local ctx = kong.ctx.plugin
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    
    -- Common initialization
    kong.log.debug("access: Starting access phase", is_async_mode and " (async)" or " (sync)")
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()
    kong.log.debug("access: Generated session_id=", session_id)

    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.ctx.plugin.cleanup_needed = false
        return
    end

    kong.log.debug("access: Session initialized successfully for session_id=", session_id)
    ctx.session_data = session_data
    ctx.session_id = session_id
    
    if is_async_mode and not verdict_listener_started then
        kong.log.info("access: Verdict listener not started, attempting to start")
        start_verdict_listener()
    end

    if nano.is_session_finalized(session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        return
    end
    
    local meta_data = nano.handle_start_transaction()
    if not meta_data then
        kong.log.debug("Failed to handle start transaction - failing mode")
        ctx.cleanup_needed = true
        return
    end
    kong.log.debug("access: Start transaction handled for session_id=", session_id)
    
    local req_headers = nano.handleHeaders(headers)
    if not req_headers then
        kong.log.debug("Failed to handle request headers - failing mode")
        ctx.cleanup_needed = true
        return
    end

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0
    
    -- Delegate to appropriate handler
    if is_async_mode then
        return handle_access_async(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    else
        return handle_access_sync(ctx, session_id, session_data, meta_data, req_headers, contains_body)
    end
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    
    -- Skip header_filter in async mode
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if is_async_mode then
        return
    end
    
    if ctx.blocked then
        return
    end
    
    if nano.is_session_finalized(ctx.session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        return
    end

    if ctx.cleanup_needed then
        kong.log.debug("cleanup in header_filter, passing through")
        return
    end

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
            kong.log.debug("DROP verdict in header_filter - sending block response immediately")
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
    
    -- Skip body_filter in async mode
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if is_async_mode then
        return
    end
    
    if ctx.blocked then
        return
    end
    
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]
    
    local session_id = ctx.session_id
    local session_data = ctx.session_data
    
    if nano.is_session_finalized(session_data) then
        kong.log.debug("Session has already been inspected, no need for further inspection")
        return
    end
    
    if ctx.cleanup_needed then
        kong.log.debug("cleanup chunk without inspection, passing through")
        return
    end

    if not ctx.body_filter_start_time then
        ctx.body_filter_start_time = ngx.now()
        ctx.body_filter_timeout_sec = nano.get_response_processing_timeout_sec()
        kong.log.debug("body_filter timeout set to ", ctx.body_filter_timeout_sec, " seconds")
    end
    
    local elapsed_time = ngx.now() - ctx.body_filter_start_time
    if elapsed_time > ctx.body_filter_timeout_sec then
        kong.log.warn("Body filter timeout after ", elapsed_time, " seconds - failing open")
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
                kong.log.debug("DROP verdict during response streaming - closing connection")
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
                kong.log.debug("Final verdict after end_inspection: ", verdict)
                ctx.cleanup_needed = true
                if verdict == nano.AttachmentVerdict.DROP then
                    kong.log.debug("DROP verdict at EOF - closing connection")
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
    if ctx.cleanup_needed then
        nano.fini_session(ctx.session_data)
        nano.cleanup_all()
        ctx.session_data = nil
        ctx.session_id = nil
        collectgarbage("collect")
    end
end

return NanoHandler
