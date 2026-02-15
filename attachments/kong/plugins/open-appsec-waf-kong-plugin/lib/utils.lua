local kong = kong

local _M = {}

function _M.free_async_resources(nano, nano_attachment, session_data, meta_data, req_headers, response)
    if response then
        nano.free_verdict_response(session_data, response)
    end
    if meta_data then
        nano_attachment.free_http_metadata(meta_data)
    end
    if req_headers then
        nano_attachment.freeHttpHeaders(req_headers)
    end
end

function _M.read_and_send_body_file_chunked(nano, body_file, session_id, session_data, timeout_sec, ctx, is_async, sem, verdict_handler)
    kong.log.debug("Reading body file in chunks (session=", session_id, ", file=", body_file, ")")
    
    local file, open_err = io.open(body_file, "rb")
    if not file then
        kong.log.err("Failed to open body file: ", body_file, " (", open_err or "unknown error", ")")
        return nil, nil
    end
    
    local chunk_size = 8192
    local chunk_count = 0
    local start_time = ngx.now()
    
    while true do
        ngx.update_time()
        local current_time = ngx.now()
        local elapsed = current_time - start_time
        
        if elapsed > timeout_sec then
            ctx.cleanup_needed = true
            kong.log.debug("Body file read timeout after ", elapsed, "s")
            file:close()
            return nil, nil
        end
        
        local chunk = file:read(chunk_size)
        if not chunk or #chunk == 0 then
            break
        end
        
        chunk_count = chunk_count + 1
        local verdict, response
        
        if is_async then
            local body_result = nano.send_body_async(session_id, session_data, chunk, nano.HttpChunkType.HTTP_REQUEST_BODY)
            if body_result ~= nano.NanoCommunicationResult.NANO_OK then
                kong.log.debug("send_body_async failed for body file chunk (session=", session_id, ", result=", body_result, ")")
                ctx.fail_open_mode = true
                file:close()
                return nil, nil
            end
            verdict, response = verdict_handler.wait_for_verdict_async(nano, sem, session_id, nano.get_req_body_thread_timeout, 3, ctx, "body file chunk")
        else
            verdict, response = nano.send_body(session_id, session_data, chunk, nano.HttpChunkType.HTTP_REQUEST_BODY)
        end
        
        if verdict ~= nano.AttachmentVerdict.INSPECT then
            file:close()
            return verdict, response
        end
    end
    
    file:close()
    return nano.AttachmentVerdict.INSPECT, nil
end

return _M
