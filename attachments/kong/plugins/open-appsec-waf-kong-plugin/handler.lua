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
NanoHandler.processed_requests = {}

-- per-worker state
local pending = {} -- sid -> { semaphore, verdict }
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
    local max_timeout = 3

    ngx.sleep(0.05)
    nano.send_wait_signal(session_id, session_data)
    
    while verdict == nano.AttachmentVerdict.DELAYED do
        local elapsed = ngx.now() - start_time
        if elapsed >= max_timeout then
            kong.log.warn("handle_delayed_verdict: Total timeout reached for session_id=", session_id, " - failing open")
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
            end
        else
            -- Timeout waiting for notification
            if err == "timeout" then
                kong.log.warn("handle_delayed_verdict: No verdict received within timeout for session_id=", session_id, " - failing open")
                nano.fini_session(session_data)
                nano.cleanup_all()
                pending[session_id] = nil
                return nil, nil
            else
                kong.log.err("handle_delayed_verdict: Semaphore error for session_id=", session_id, " err=", err, " - failing open")
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
    start_verdict_listener()
end

-- **Handles Request Headers (DecodeHeaders Equivalent)**
function NanoHandler.access(conf)
    -- Ensure verdict listener is running
    if not verdict_listener_started then
        kong.log.info("access: Verdict listener not started, attempting to start")
        start_verdict_listener()
    end

    kong.log.debug("access: Starting access phase")
    local headers = kong.request.get_headers()
    local session_id = nano.generate_session_id()
    kong.log.debug("access: Generated session_id=", session_id)
    kong.service.request.set_header("x-session-id", tostring(session_id))

    if NanoHandler.processed_requests[session_id] then
        kong.log.warn("access: Session already processed, blocking session_id=", session_id)
        kong.ctx.plugin.blocked = true
        return
    end

    local session_data = nano.init_session(session_id)
    if not session_data then
        kong.log.err("access: Failed to initialize session for session_id=", session_id, " - failing open")
        return
    end
    kong.log.debug("access: Session initialized successfully for session_id=", session_id)

    kong.ctx.plugin.session_data = session_data
    kong.ctx.plugin.session_id = session_id

    local meta_data = nano.handle_start_transaction()
    if not meta_data then
        kong.log.err("access: Failed to handle start transaction for session_id=", session_id, " - failing open")
        return
    end
    kong.log.debug("access: Start transaction handled for session_id=", session_id)
    
    local req_headers = nano.handleHeaders(headers)

    local has_content_length = tonumber(ngx.var.http_content_length) and tonumber(ngx.var.http_content_length) > 0
    local contains_body = has_content_length and 1 or 0

    local sem = semaphore.new()
    pending[session_id] = { sem = sem, verdict = nil }

    -- Use non-blocking send_data_async
    kong.log.debug("access: Sending headers async for session_id=", session_id, " contains_body=", contains_body)
    nano.send_data_async(session_id, session_data, meta_data, req_headers, contains_body, nano.HttpChunkType.HTTP_REQUEST_FILTER)

    -- Wait on semaphore for verdict
    -- TODO get timeout from conf
    kong.log.debug("access: Waiting for headers verdict for session_id=", session_id)
    local ok, err = sem:wait(3)

    if not ok then
        kong.log.err(
        "access: Timeout while waiting for headers verdict for session_id=", session_id, " err=", err or "nil"
        )
        -- Todo check if fail open/close
        nano.fini_session(session_data)
        nano.cleanup_all()
        return
    end

    -- Query verdict after semaphore wakeup
    kong.log.debug("access: Querying headers verdict for session_id=", session_id)
    local verdict, response = nano.get_attachment_verdict_response(session_id)
    kong.log.debug("access: Headers verdict=", verdict, " for session_id=", session_id)

    if verdict == nano.AttachmentVerdict.DROP then
        kong.log.warn("access: Headers verdict DROP for session_id=", session_id)
        kong.ctx.plugin.blocked = true
        local result = nano.handle_custom_response(session_data, response)
        nano.fini_session(session_data)
        nano.cleanup_all()
        return result
    end
    kong.log.debug("access: Headers verdict ACCEPT for session_id=", session_id)

    if contains_body == 1 then
        kong.log.debug("access: Request contains body for session_id=", session_id)
        local body = kong.request.get_raw_body()
        if body and #body > 0 then
            -- Use non-blocking send_body_async
            kong.log.debug("access: Sending body async, size=", #body, " for session_id=", session_id)
            nano.send_body_async(session_id, session_data, body, nano.HttpChunkType.HTTP_REQUEST_BODY)

            -- Wait on semaphore for verdict
            kong.log.debug("access: Waiting for body verdict for session_id=", session_id)
            local ok, err = sem:wait(3)
            if not ok then
                kong.log.err(
                "access: Timeout while waiting for body verdict for session_id=", session_id, " err=", err or "nil"
                )
                -- Todo check if fail open/close
                nano.fini_session(session_data)
                nano.cleanup_all()
                return
            end

            -- Query verdict after semaphore wakeup
            kong.log.debug("access: Querying body verdict for session_id=", session_id)
            local verdict, response = nano.get_attachment_verdict_response(session_id)
            kong.log.debug("access: Body verdict=", verdict, " for session_id=", session_id)
            
            -- Handle DELAYED verdict
            verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
            if not verdict then
                return
            end
            
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("access: Body verdict DROP for session_id=", session_id)
                kong.ctx.plugin.blocked = true
                local result = nano.handle_custom_response(session_data, response)
                nano.fini_session(session_data)
                nano.cleanup_all()
                return result
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
                    kong.ctx.plugin.blocked = true
                    local result = nano.handle_custom_response(session_data, response)
                    nano.fini_session(session_data)
                    nano.cleanup_all()
                    return result
                end
            else
                local body_file = ngx.var.request_body_file
                if body_file then
                    kong.log.debug("access: Reading request body from file=", body_file, " for session_id=", session_id)
                    local file, open_err = io.open(body_file, "rb")
                    if file then
                        local entire_body = file:read("*all")
                        file:close()

                        if entire_body and #entire_body > 0 then
                            kong.log.debug("access: Sending entire body from file, size=", #entire_body, " bytes for session_id=", session_id)
                            verdict, response = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_REQUEST_BODY)
                            kong.log.debug("access: File body verdict=", verdict, " for session_id=", session_id)
                            if verdict == nano.AttachmentVerdict.DROP then
                                kong.log.warn("access: File body verdict DROP for session_id=", session_id)
                                kong.ctx.plugin.blocked = true
                                local result = nano.handle_custom_response(session_data, response)
                                nano.fini_session(session_data)
                                nano.cleanup_all()
                                return result
                            end
                        else
                            kong.log.debug("access: Empty body file for session_id=", session_id)
                        end
                    else
                        kong.log.err("access: Failed to open body file=", body_file, " err=", open_err or "nil", " for session_id=", session_id)
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

        -- Wait on semaphore for verdict
        kong.log.debug("access: Waiting for end inspection verdict for session_id=", session_id)
        local ok, err = sem:wait(3)
        if not ok then
            kong.log.err("access: Timeout waiting for end inspection verdict for session_id=", session_id, " err=", err or "nil")
            nano.fini_session(session_data)
            nano.cleanup_all()
            return
        end

        -- Query verdict after semaphore wakeup
        kong.log.debug("access: Querying end inspection verdict for session_id=", session_id)
        local verdict, response = nano.get_attachment_verdict_response(session_id)
        kong.log.debug("access: End inspection verdict=", verdict, " for session_id=", session_id)

        -- Handle DELAYED verdict
        verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
        if not verdict then
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP for session_id=", session_id)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.fini_session(session_data)
            nano.cleanup_all()
            return result
        end
    else
        kong.log.debug("access: Ending request inspection (no body) for session_id=", session_id)
        nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)

        -- Wait on semaphore for verdict
        kong.log.debug("access: Waiting for end inspection verdict (no body) for session_id=", session_id)
        local ok, err = sem:wait(3)
        if not ok then
            kong.log.err("access: Timeout waiting for end inspection verdict (no body) for session_id=", session_id, " err=", err or "nil")
            nano.fini_session(session_data)
            nano.cleanup_all()
            return
        end

        -- Query verdict after semaphore wakeup
        kong.log.debug("access: Querying end inspection verdict (no body) for session_id=", session_id)
        local verdict, response = nano.get_attachment_verdict_response(session_id)
        kong.log.debug("access: End inspection verdict (no body)=", verdict, " for session_id=", session_id)

        -- Handle DELAYED verdict
        verdict, response = handle_delayed_verdict(session_id, session_data, sem, verdict, response)
        if not verdict then
            return
        end

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP (no body) for session_id=", session_id)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.fini_session(session_data)
            nano.cleanup_all()
            return result
        end
    end

    kong.log.debug("access: Request processing complete for session_id=", session_id)
    pending[session_id] = nil
    NanoHandler.processed_requests[session_id] = true
end

-- function NanoHandler.header_filter(conf)
--     local ctx = kong.ctx.plugin
--     if ctx.blocked then
--         return
--     end

--     local session_id = ctx.session_id
--     local session_data = ctx.session_data

--     if not session_id or not session_data then
--         return
--     end

--     local headers = kong.response.get_headers()
--     local header_data = nano.handleHeaders(headers)
--     local status_code = kong.response.get_status()
--     local content_length = tonumber(headers["content-length"]) or 0

--     local verdict, response = nano.send_response_headers(session_id, session_data, header_data, status_code, content_length)
--     if verdict == nano.AttachmentVerdict.DROP then
--         kong.ctx.plugin.blocked = true
--         nano.fini_session(session_data)
--         nano.cleanup_all()
--         return nano.handle_custom_response(session_data, response)
--     end

--     ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
-- end

-- function NanoHandler.body_filter(conf)
--     local ctx = kong.ctx.plugin
--     if ctx.blocked then
--         return
--     end

--     local session_id = ctx.session_id
--     local session_data = ctx.session_data

--     if not session_id or not session_data or ctx.session_finalized then
--         return
--     end

--     local body = kong.response.get_raw_body()

--     if body then
--         ctx.body_seen = true
--         local verdict, response, modifications = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_RESPONSE_BODY)

--         -- Initialize if not exists
--         ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0

--         -- Handle body modifications if any
--         if modifications then
--             body = nano.handle_body_modifications(body, modifications, ctx.body_buffer_chunk)
--             kong.response.set_raw_body(body)
--         end

--         ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

--         if verdict == nano.AttachmentVerdict.DROP then
--             nano.fini_session(session_data)
--             ctx.session_finalized = true
--             local result = nano.handle_custom_response(session_data, response)
--             -- Clean up allocated memory
--             nano.cleanup_all()
--             return result
--         end
--         return
--     end

--     if ctx.body_seen or ctx.expect_body == false then
--         local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
--         if verdict == nano.AttachmentVerdict.DROP then
--             nano.fini_session(session_data)
--             ctx.session_finalized = true
--             local result = nano.handle_custom_response(session_data, response)
--             -- Clean up allocated memory
--             nano.cleanup_all()
--             return result
--         end

--         nano.fini_session(session_data)
--         -- Clean up allocated memory
--         nano.cleanup_all()
--         ctx.session_finalized = true
--     end
-- end

return NanoHandler
