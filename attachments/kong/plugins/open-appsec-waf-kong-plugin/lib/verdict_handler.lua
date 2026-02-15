local kong = kong

local _M = {}

function _M.get_timeout_and_fail_mode(nano, timeout_getter_fn, default_timeout_sec)
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    local timeout = is_async_mode and math.max(1.0, timeout_getter_fn() / 1000.0) or default_timeout_sec
    local fail_mode_verdict = is_async_mode and nano.get_fail_mode_verdict() or 0
    return timeout, fail_mode_verdict
end

function _M.handle_drop_verdict(nano, nano_attachment, ctx, session_id, session_data, response, is_async, meta_data, req_headers, sem, pending)
    while sem:count() > 0 do
        sem:wait(0)
    end

    if is_async then
        ctx.blocked = true
        local result = nano.handle_custom_response(session_data, response, meta_data, req_headers, sem, session_id, pending)
        return result
    else
        ctx.cleanup_needed = true
        local result = nano.handle_custom_response(session_data, response)
        nano.cleanup_all()
        return result
    end
end

function _M.wait_for_verdict_async(nano, sem, session_id, timeout_getter_fn, default_timeout, ctx, log_context)
    while sem:count() > 0 do
        sem:wait(0)
    end
    local timeout, fail_mode_verdict = _M.get_timeout_and_fail_mode(nano, timeout_getter_fn, default_timeout)
    
    local ok, err = sem:wait(timeout)
    
    if not ok then
        local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
        kong.log.warn("Timeout waiting for ", log_context, " verdict (session=", session_id, ", ", fail_action, ")")
        if fail_mode_verdict ~= 0 then
            ctx.blocked = true
            return nil, "blocked"
        end
        return nil, "timeout"
    end
    
    local verdict, response = nano.get_attachment_verdict_response(session_id)
    
    return verdict, response
end

function _M.handle_delayed_verdict(nano, session_id, session_data, sem, verdict, response, pending)
    if verdict ~= nano.AttachmentVerdict.DELAYED then
        return verdict, response
    end
    
    kong.log.debug("Handling DELAYED verdict (session=", session_id, ")")
    
    if response then
        nano.free_verdict_response(session_data, response)
        response = nil
    end
    
    -- Drain any pending semaphore posts to ensure we wait for NEW verdicts
    while sem:count() > 0 do
        sem:wait(0)
    end
    
    local start_time = ngx.now()
    local max_timeout_ms = nano.get_request_processing_timeout()
    local max_timeout = max_timeout_ms / 1000.0
    local polling_time_ms = nano.get_hold_verdict_polling_time() * 50
    local polling_time = polling_time_ms / 1000.0
    local fail_mode_verdict = nano.get_fail_mode_verdict()

    ngx.sleep(polling_time)
    nano.send_wait_signal(session_id, session_data)
    
    while verdict == nano.AttachmentVerdict.DELAYED do
        local elapsed = ngx.now() - start_time
        if elapsed >= max_timeout then
            local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
            kong.log.warn("DELAYED verdict timeout (session=", session_id, ", ", fail_action, ")")
            if response then
                nano.free_verdict_response(session_data, response)
            end
            pending[session_id] = nil
            return nil, nil
        end
        
        local remaining = max_timeout - elapsed
        local ok, err = sem:wait(remaining)
        
        if ok then
            local old_response = response
            verdict, response = nano.get_attachment_verdict_response(session_id)
            
            if old_response then
                nano.free_verdict_response(session_data, old_response)
            end
            
            if verdict == nano.AttachmentVerdict.DELAYED then
                nano.send_wait_signal(session_id, session_data)
                ngx.sleep(polling_time)
            end
        else
            if err == "timeout" then
                local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
                kong.log.warn("No verdict received within timeout (session=", session_id, ", ", fail_action, ")")
                if response then
                    nano.free_verdict_response(session_data, response)
                end
                pending[session_id] = nil
                return nil, nil
            else
                local fail_action = (fail_mode_verdict == 0) and "failing open" or "failing closed"
                kong.log.err("Semaphore error (session=", session_id, ", error=", err, ", ", fail_action, ")")
                if response then
                    nano.free_verdict_response(session_data, response)
                end
                pending[session_id] = nil
                return nil, nil
            end
        end
    end
    
    return verdict, response
end

return _M
