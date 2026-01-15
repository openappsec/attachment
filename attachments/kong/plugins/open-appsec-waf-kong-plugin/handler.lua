local module_name = ...
local prefix = module_name:match("^(.-)handler$")
local nano = require(prefix .. "nano_ffi")
local semaphore = require "ngx.semaphore"
local kong = kong

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
        kong.log.debug("drain_queue: Popped session_id=", session_id or "nil")
        if session_id and session_id > 0 then
            local session_info = pending[session_id]
            if session_info and session_info.sem then
                kong.log.debug("drain_queue: Notifying semaphore for session_id=", session_id)
                session_info.sem:post()
                drained_count = drained_count + 1
            else
                kong.log.warn("drain_queue: No semaphore found for session_id=", session_id)
            end
        else
            kong.log.err("drain_queue: Invalid session_id=", session_id or "nil")
        end
    end
    kong.log.debug("drain_queue: Drained ", drained_count, " sessions")
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

    kong.log.info("Starting verdict listener on socket fd: ", socket_fd)

    ngx.timer.at(0, function(premature)
        if premature then
            return
        end

        local sock = ngx.socket.tcp()
        sock:settimeout(1000) -- 1 second timeout

        -- Set the socket to the existing file descriptor
        local ok, err = sock:setfd(socket_fd)
        if not ok then
            kong.log.err("Failed to set socket fd: ", err)
            verdict_listener_started = false
            return
        end

        kong.log.info("Listening on verdict socket")
        verdict_listener_started = true

        while true do
            -- Use socket as a doorbell - wait for any data
            local data, err, partial = sock:receive(1)
            if not data and not partial then
                if err == "timeout" then
                    -- Continue waiting
                    goto continue
                else
                    kong.log.err("verdict_listener: Fatal error receiving from verdict socket: ", err, " - marking listener as stopped")
                    verdict_listener_started = false
                    break
                end
            end

            -- Socket has data - drain the queue
            kong.log.debug("verdict_listener: Received doorbell signal, draining queue")
            local ok, drain_err = pcall(drain_queue)
            if not ok then
                kong.log.err("verdict_listener: Error draining queue: ", drain_err)
            end

            ::continue::
        end
    end)
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
    local ok, err = sem:wait(1)

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
        nano.fini_session(session_data)
        kong.ctx.plugin.blocked = true
        local result = nano.handle_custom_response(session_data, response)
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
            local ok, err = sem:wait(1)
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
            if verdict == nano.AttachmentVerdict.DROP then
                kong.log.warn("access: Body verdict DROP for session_id=", session_id)
                nano.fini_session(session_data)
                kong.ctx.plugin.blocked = true
                local result = nano.handle_custom_response(session_data, response)
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
                    nano.fini_session(session_data)
                    kong.ctx.plugin.blocked = true
                    return nano.handle_custom_response(session_data, response)
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
                                nano.fini_session(session_data)
                                kong.ctx.plugin.blocked = true
                                local result = nano.handle_custom_response(session_data, response)
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
        local ok, err = sem:wait(1)
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

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP for session_id=", session_id)
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end
    else
        kong.log.debug("access: Ending request inspection (no body) for session_id=", session_id)
        nano.end_inspection_async(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)

        -- Wait on semaphore for verdict
        kong.log.debug("access: Waiting for end inspection verdict (no body) for session_id=", session_id)
        local ok, err = sem:wait(1)
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

        if verdict == nano.AttachmentVerdict.DROP then
            kong.log.warn("access: End inspection verdict DROP (no body) for session_id=", session_id)
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
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

