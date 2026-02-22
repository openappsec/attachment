local ffi = require "ffi"
local kong = kong

ffi.cdef[[
    typedef long ssize_t;
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);
]]

local _M = {}

-- Module state
local verdict_listener_started = false
local recv_buf = ffi.new("char[1024]")
local EAGAIN = 11

function _M.drain_queue(nano, pending)
    local drained_count = 0
    while not nano.is_queue_empty() do
        local session_id = nano.pop_from_queue()
        if session_id and session_id > 0 then
            local session_info = pending[session_id]
            if session_info and session_info.sem then
                session_info.sem:post(1)
                drained_count = drained_count + 1
            else
                kong.log.warn("No semaphore found for session ", session_id)
            end
        end
    end
    if drained_count > 0 then
        kong.log.debug("Drained ", drained_count, " verdict(s) from queue")
    end
end

function _M.start_verdict_listener(nano, pending)
    if verdict_listener_started then
        return true
    end

    local socket_fd = nano.get_attachment_socket()
    if not socket_fd or socket_fd < 0 then
        kong.log.err("Failed to get attachment socket")
        verdict_listener_started = false
        return false
    end

    kong.log.info("Starting verdict listener (socket fd=", socket_fd, ")")

    local function periodic_drain(premature)
        if premature then
            verdict_listener_started = false
            return
        end

        -- Check if we should stop the polling cycle
        if not verdict_listener_started then
            kong.log.info("Verdict listener stopped")
            return
        end

        local current_socket_fd = nano.get_attachment_socket()
        if current_socket_fd and current_socket_fd >= 0 then
            while true do
                local bytes_read = ffi.C.recv(current_socket_fd, recv_buf, 1024, 0x40)
                if bytes_read > 0 then
                    -- consumed data, continue draining
                elseif bytes_read == 0 then
                    kong.log.debug("Verdict socket closed by peer")
                    break
                else
                    local errno = ffi.errno()
                    if errno ~= EAGAIN then
                        kong.log.debug("Verdict socket recv error, errno=", errno)
                    end
                    break
                end
            end
        end

        if not nano.is_queue_empty() then
            pcall(_M.drain_queue, nano, pending)
        end

        -- Only reschedule if still started
        if verdict_listener_started then
            if not ngx.timer.at(0.01, periodic_drain) then
                verdict_listener_started = false
            end
        end
    end

    -- Start the periodic timer
    local ok, err = ngx.timer.at(0.01, periodic_drain)
    if not ok then
        kong.log.err("Failed to start verdict polling timer: ", err)
        verdict_listener_started = false
        return false
    end

    verdict_listener_started = true
    kong.log.info("Verdict listener started successfully")
    return true
end

function _M.stop_verdict_listener(pending)
    if not verdict_listener_started then
        return false
    end

    verdict_listener_started = false
    
    -- Wake up all pending sessions
    local woken_count = 0
    if pending then
        for session_id, session_info in pairs(pending) do
            if session_info and session_info.sem then
                session_info.sem:post(1)
                woken_count = woken_count + 1
            end
        end
        -- Clear the pending table
        for k in pairs(pending) do
            pending[k] = nil
        end
    end
    
    kong.log.info("Verdict listener stopped (", woken_count, " session(s) woken)")
    return true
end

function _M.is_started()
    return verdict_listener_started
end

return _M
