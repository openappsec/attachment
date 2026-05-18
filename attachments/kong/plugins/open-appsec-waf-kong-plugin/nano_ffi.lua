package.cpath = "/usr/local/kong/lib/?.so;" .. package.cpath
local nano_attachment = require "lua_attachment_wrapper"
local kong = kong
local nano = {}

nano.session_counter = 0
nano.attachments = {}
nano.num_workers = ngx.worker.count() or 1
nano.allocated_strings = {}
nano.allocate_headers = {}
nano.allocated_metadata = {}
nano.allocated_responses = {}
nano.AttachmentVerdict = {
    INSPECT = 0,
    ACCEPT = 1,
    DROP = 2,
    INJECT = 3,
    DELAYED = 4
}
nano.HttpChunkType = {
    HTTP_REQUEST_FILTER = 0,
    HTTP_REQUEST_METADATA = 1,
    HTTP_REQUEST_HEADER = 2,
    HTTP_REQUEST_BODY = 3,
    HTTP_REQUEST_END = 4,
    HTTP_RESPONSE_HEADER = 5,
    HTTP_RESPONSE_BODY = 6,
    HTTP_RESPONSE_END = 7,
    HOLD_DATA = 8
}

nano.NanoCommunicationResult = {
    NANO_OK = 0,
    NANO_ERROR = 1,
    NANO_ABORT = 2,
    NANO_AGAIN = 3,
    NANO_HTTP_FORBIDDEN = 4,
    NANO_DECLINED = 5,
    NANO_TIMEOUT = 6
}

nano.WebResponseType = {
    CUSTOM_WEB_RESPONSE = 0,
    CUSTOM_WEB_BLOCK_PAGE_RESPONSE = 1,
    RESPONSE_CODE_ONLY = 2,
    REDIRECT_WEB_RESPONSE = 3,
    NO_WEB_RESPONSE = 4,
}

local ffi = require "ffi"

ffi.cdef[[
typedef enum HttpModificationType
{
    APPEND,
    INJECT,
    REPLACE
} HttpModificationType;

typedef enum NanoWebResponseType
{
    CUSTOM_WEB_RESPONSE,
    CUSTOM_WEB_BLOCK_PAGE_RESPONSE,
    RESPONSE_CODE_ONLY,
    REDIRECT_WEB_RESPONSE,
    NO_WEB_RESPONSE
} NanoWebResponseType;

typedef struct __attribute__((__packed__)) HttpInjectData {
    int64_t injection_pos;
    HttpModificationType mod_type;
    uint16_t injection_size;
    uint8_t is_header;
    uint8_t orig_buff_index;
    char data[0];
} HttpInjectData;

typedef struct NanoHttpModificationList {
    struct NanoHttpModificationList *next;
    HttpInjectData modification;
    char *modification_buffer;
} NanoHttpModificationList;
]]

-- Assuming you already defined the C struct somewhere:
-- ffi.cdef[[
-- typedef struct NanoHttpModificationList { ... } NanoHttpModificationList;
-- ]]

local NanoHttpModificationListPtr = ffi.typeof("NanoHttpModificationList*")

function nano.generate_session_id()
    nano.session_counter = nano.session_counter + 1
    local worker_id = ngx.worker.id()
    return tonumber(string.format("%d%05d", worker_id, nano.session_counter))
end

function nano.handle_custom_response(session_data, response, meta_data, req_headers, sem, session_id, pending_table)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Cannot handle custom response: Attachment not available for worker ", worker_id, " - failing open")
        return kong.response.exit(200, "Request allowed due to attachment unavailability")
    end
    
    -- Helper function to do all cleanup before exiting
    local function cleanup_and_exit(code, body, headers)
        local is_async_mode = nano.get_is_async_mode_enabled() > 0

        if is_async_mode then
            -- Free async resources if provided
            if meta_data then
                nano_attachment.free_http_metadata(meta_data)
            end
            if req_headers then
                nano_attachment.freeHttpHeaders(req_headers)
            end

            -- Free verdict response + finalize session only in async mode
            nano.free_verdict_response(session_data, response)
            nano.fini_session(session_data)

            -- Remove from pending if session_id and pending_table provided
            if session_id and pending_table then
                pending_table[session_id] = nil
            end
        end

        return kong.response.exit(code, body, headers)
    end

    local response_type = nano_attachment.get_web_response_type(attachment, session_data, response)

    if response_type == nano.WebResponseType.RESPONSE_CODE_ONLY then
        local code = nano_attachment.get_response_code(response)
        if not code or code < 100 or code > 599 then
            kong.log.warn("Invalid response code received: ", code, " - using 403 instead")
            code = 403
        end
        kong.log.debug("Response code only: ", code)
        return cleanup_and_exit(code, "")
    end

    if response_type == nano.WebResponseType.REDIRECT_WEB_RESPONSE then
        local location = nano_attachment.get_redirect_page(attachment, session_data, response)
        return cleanup_and_exit(307, "", { ["Location"] = location })
    end

    local block_page = nano_attachment.get_block_page(attachment, session_data, response)
    if not block_page then
        kong.log.err("Failed to retrieve custom block page for session ", session_data)
        return cleanup_and_exit(500, { message = "Internal Server Error" })
    end
    local code = nano_attachment.get_response_code(response)
    if not code or code < 100 or code > 599 then
        kong.log.warn("Invalid response code received: ", code, " - using 403 instead")
        code = 403
    end
    kong.log.debug("Block page response with code: ", code)
    return cleanup_and_exit(code, block_page, { ["Content-Type"] = "text/html" })

end



function nano.create_nano_str_alloc(str)
    if not str then return nil end

    local nano_str = nano_attachment.createNanoStrAlloc(str)
    table.insert(nano.allocated_strings, nano_str)
    return nano_str
end

function nano.free_nano_str(nano_str)
    if nano_str then
        nano_attachment.freeNanoStr(nano_str)
    end
end

function nano.free_all_nano_str()
    for _, nano_str in ipairs(nano.allocated_strings) do
        nano_attachment.freeNanoStr(nano_str)
    end

    nano.allocated_strings = {}
end

function nano.free_http_headers(header_data)
    for _, nano_header in ipairs(nano.allocate_headers) do
        nano_attachment.freeHttpHeaders(nano_header)
    end

    nano.allocate_headers = {}
end

function nano.free_all_metadata()
    for _, metadata in ipairs(nano.allocated_metadata) do
        nano_attachment.free_http_metadata(metadata)
    end
    nano.allocated_metadata = {}
end

function nano.free_all_responses()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]
    for _, response in ipairs(nano.allocated_responses) do
        if attachment then
            nano_attachment.free_verdict_response(attachment, nil, response)
        else
            nano_attachment.free_verdict_response(nil, nil, response)
        end
    end
    nano.allocated_responses = {}
end

function nano.free_verdict_response(session_data, response)
    if response then
        local worker_id = ngx.worker.id()
        local attachment = nano.attachments[worker_id]
        if attachment then
            nano_attachment.free_verdict_response(attachment, session_data, response)
        else
            nano_attachment.free_verdict_response(nil, session_data, response)
        end
    end
end

function nano.cleanup_all()
    nano.free_all_nano_str()
    nano.free_all_metadata()
    nano.free_all_responses()
    nano.free_http_headers()
end

function nano.init_attachment()
    local worker_id = ngx.worker.id()
    local attachment, err
    local retries = 3

    for attempt = 1, retries do
        attachment, err = nano_attachment.init_nano_attachment(worker_id, nano.num_workers)
        if attachment then
            break
        end

        kong.log.err("Worker ", worker_id, " failed to initialize attachment (attempt ", attempt, "/", retries, "): ", err)
    end

    if not attachment then
        kong.log.err("Worker ", worker_id, " failed to initialize attachment after ", retries, " attempts. Worker will operate in fail-open mode.")
    else
        nano.attachments[worker_id] = attachment
        kong.log.info("Worker ", worker_id, " successfully initialized nano_attachment.")
        return true
    end
end

function nano.init_session(session_id)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not found for worker ", worker_id, ", attempting to reinitialize...")
        nano.init_attachment()
        attachment = nano.attachments[worker_id]

        if not attachment then
            kong.log.warn("Cannot initialize session: Attachment still not available for worker ", worker_id, " - failing open")
            return nil
        end
    end

    local session_data, err = nano_attachment.init_session(attachment, session_id)
    if not session_data then
        kong.log.err("Failed to initialize session for session_id ", session_id, ": ", err, " - failing open")
        return nil
    end

    return session_data
end

function nano.is_session_finalized(session_data)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment or not session_data then
        kong.log.err("Cannot check session finalization: Invalid attachment or session_data")
        return false
    end

    return nano_attachment.is_session_finalized(attachment, session_data)
end

function nano.handle_start_transaction()
    local stream_info = kong.request

    local full_host = stream_info.get_host()
    local host = full_host:match("([^:]+)") or full_host

    local method = stream_info.get_method()
    local uri = stream_info.get_path_with_query()
    local scheme = stream_info.get_scheme()
    local client_ip = kong.client.get_ip()
    local client_port = kong.client.get_port()

    local listening_ip = ngx.var.server_addr or "127.0.0.1"
    local listening_port = ngx.var.server_port or 80

    local metadata = nano_attachment.create_http_metadata(
        scheme, method, host, listening_ip, tonumber(listening_port) or 0,
        uri, client_ip, tonumber(client_port) or 0, "", ""
    )

    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if not is_async_mode then
        table.insert(nano.allocated_metadata, metadata)
        collectgarbage("stop")
    end

    return metadata
end

function nano.handleHeaders(headers)
    local header_data = nano_attachment.allocHttpHeaders()
    local is_async_mode = nano.get_is_async_mode_enabled() > 0
    if not is_async_mode then
        table.insert(nano.allocate_headers, header_data)
    end
    local index = 0

    for key, value in pairs(headers) do
        if index > 10000 then break end

        if key == "x-request-id" or
           key == ":method" or key == ":path" or key == ":scheme" or
           key == "x-forwarded-proto" then
            goto continue
        end

        if key == ":authority" then key = "Host" end

        -- Handle multiple header values (Kong represents them as tables)
        local header_value = value
        if type(value) == "table" then
            kong.log.debug("Header '", key, "' has multiple values: ", table.concat(value, ", "))
            header_value = table.concat(value, ", ")
        elseif type(value) ~= "string" then
            kong.log.warn("Header '", key, "' has unexpected type: ", type(value), " - converting to string")
            header_value = tostring(value)
        end

        nano_attachment.setHeaderElement(header_data, index, key, header_value)
        index = index + 1

        ::continue::
    end

    nano_attachment.setHeaderCount(header_data, index)

    return header_data
end

function nano.send_data(session_id, session_data, meta_data, header_data, contains_body, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.AttachmentVerdict.INSPECT
    end

    contains_body = tonumber(contains_body) or 0
    contains_body = (contains_body > 0) and 1 or 0

    local verdict, response = nano_attachment.send_data(attachment, session_id, session_data, chunk_type, meta_data, header_data, contains_body)

    if response then
        table.insert(nano.allocated_responses, response)
    end

    return verdict, response
end

function nano.send_data_async(session_id, session_data, meta_data, header_data, contains_body, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.NanoCommunicationResult.NANO_ERROR
    end

    contains_body = tonumber(contains_body) or 0
    contains_body = (contains_body > 0) and 1 or 0

    local _, result = nano_attachment.send_data_async(attachment, session_id, session_data, chunk_type, meta_data, header_data, contains_body)
    return result
end

function nano.send_body(session_id, session_data, body_chunk, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.AttachmentVerdict.INSPECT
    end

    local verdict, response, modifications = nano_attachment.send_body(attachment, session_id, session_data, body_chunk, chunk_type)

    if response then
        table.insert(nano.allocated_responses, response)
    end

    return verdict, response, modifications
end

function nano.send_body_async(session_id, session_data, body_chunk, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.NanoCommunicationResult.NANO_ERROR
    end

    local _, result = nano_attachment.send_body_async(attachment, session_id, session_data, body_chunk, chunk_type)
    return result
end

function nano.send_wait_signal(session_id, session_data)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.NanoCommunicationResult.NANO_ERROR
    end

    local result = nano_attachment.send_wait_signal(attachment, session_id, session_data)
    return result
end

function nano.inject_at_position(buffer, injection, pos)
    if pos < 0 or pos > #buffer then
        kong.log.err("Invalid injection position: ", pos, ", buffer length: ", #buffer)
        return buffer
    end
    return buffer:sub(1, pos) .. injection .. buffer:sub(pos + 1)
end

function nano.handle_body_modifications(body, modifications, body_buffer_chunk)
    if modifications == nil then
        return body
    end
    local curr_modification = ffi.cast(NanoHttpModificationListPtr, modifications)

    while curr_modification ~= nil do
        if tonumber(curr_modification.modification.orig_buff_index) == body_buffer_chunk then
            local injection_pos = tonumber(curr_modification.modification.injection_pos)
            local modification_str = ffi.string(curr_modification.modification_buffer)

            kong.log.debug("Injecting modification at pos ", injection_pos, " body buffer chunk ", body_buffer_chunk)

            body = nano.inject_at_position(body, modification_str, injection_pos)
        end

        curr_modification = curr_modification.next
    end

    return body
end

function nano.send_response_body(session_id, session_data, body_chunk)
    local verdict, response, modifications = nano.send_body(session_id, session_data, body_chunk, nano.HttpChunkType.HTTP_RESPONSE_BODY)
    return verdict, response, modifications
end

function nano.fini_session(session_data)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment or not session_data then
        kong.log.warn("Cannot finalize session: Invalid attachment or session_data for worker ", worker_id)
        return false
    end

    nano_attachment.fini_session(attachment, session_data)
    kong.log.info("Successfully finalized session ", session_data, " for worker ", worker_id)
    return true
end

function nano.send_response_headers(session_id, session_data, headers, status_code, content_length)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open")
        return nano.AttachmentVerdict.INSPECT
    end

    local verdict, response = nano_attachment.send_response_headers(
        attachment,
        session_id,
        session_data,
        headers,
        status_code,
        content_length
    )

    if response then
        table.insert(nano.allocated_responses, response)
    end

    return verdict, response
end

function nano.handle_header_modifications(headers, modifications)
    if not modifications then
        return headers
    end

    local curr_modification = modifications
    local modified_headers = headers

    while curr_modification do
        local mod = curr_modification.modification
        if mod.is_header then
            local type = mod.mod_type
            local key = curr_modification.modification_buffer
            local value = curr_modification.next and curr_modification.next.modification_buffer or nil

            if type == 0 then -- APPEND
                kong.log.debug("Appending header: ", key, " : ", value)
                modified_headers[key] = value
            elseif type == 1 then -- INJECT
                local header_index = mod.orig_buff_index
                local header_name = nil
                local header_value = nil
                local i = 0
                for k, v in pairs(modified_headers) do
                    if i == header_index then
                        header_name = k
                        header_value = v
                        break
                    end
                    i = i + 1
                end
                if header_name then
                    kong.log.debug("Injecting into header: ", header_name)
                    modified_headers[header_name] = nano.inject_at_position(header_value, value, mod.injection_pos)
                end
            elseif type == 2 then 
                kong.log.debug("Replacing header: ", key)
                modified_headers[key] = value
            end
        end
        curr_modification = curr_modification.next
    end

    return modified_headers
end

function nano.end_inspection(session_id, session_data, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open during end_inspection")
        return nano.AttachmentVerdict.INSPECT, nil
    end

    if not session_data then
        kong.log.err("Cannot end inspection: Invalid session_data for session ", session_id)
        return nano.AttachmentVerdict.INSPECT, nil
    end

    local verdict, response = nano_attachment.end_inspection(attachment, session_id, session_data, chunk_type)

    if response then
        table.insert(nano.allocated_responses, response)
    end

    return verdict, response
end

function nano.end_inspection_async(session_id, session_data, chunk_type)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.warn("Attachment not available for worker ", worker_id, " - failing open during end_inspection_async")
        return nano.NanoCommunicationResult.NANO_ERROR
    end

    if not session_data then
        kong.log.err("Cannot end inspection async: Invalid session_data for session ", session_id)
        return nano.NanoCommunicationResult.NANO_ERROR
    end

    local _, result = nano_attachment.end_inspection_async(attachment, session_id, session_data, chunk_type)
    return result
end

function nano.get_attachment_verdict_response(session_id)
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return nil, nil
    end

    local verdict, response = nano_attachment.get_attachment_verdict_response(attachment, session_id)

    return verdict, response
end

function nano.get_attachment_socket()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return nil
    end

    return nano_attachment.get_attachment_socket(attachment)
end

function nano.pop_from_queue()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return nil
    end

    return nano_attachment.pop_from_queue(attachment)
end

function nano.is_queue_empty()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return true
    end

    return nano_attachment.is_queue_empty(attachment)
end

function nano.get_is_async_mode_enabled()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 0
    end

    return nano_attachment.get_is_async_mode_enabled(attachment)
end

function nano.get_hold_verdict_polling_time()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 1
    end

    return nano_attachment.get_hold_verdict_polling_time(attachment)
end

function nano.get_hold_verdict_retries()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 10
    end

    return nano_attachment.get_hold_verdict_retries(attachment)
end

function nano.get_req_body_thread_timeout()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 150
    end

    return nano_attachment.get_req_body_thread_timeout(attachment)
end

function nano.get_req_header_thread_timeout()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 100
    end

    return nano_attachment.get_req_header_thread_timeout(attachment)
end

function nano.get_fail_mode_verdict()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 0  -- NANO_OK (fail open)
    end

    return nano_attachment.get_fail_mode_verdict(attachment)
end

function nano.get_request_processing_timeout()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 3000  -- Default 3000ms
    end

    return nano_attachment.get_request_processing_timeout(attachment)
end

function nano.get_request_processing_timeout_sec()
    local timeout_ms = nano.get_request_processing_timeout()
    return timeout_ms / 1000  -- Convert milliseconds to seconds
end

function nano.get_response_processing_timeout()
    local worker_id = ngx.worker.id()
    local attachment = nano.attachments[worker_id]

    if not attachment then
        kong.log.err("Attachment not available for worker ", worker_id)
        return 3000  -- Default 3000ms
    end

    return nano_attachment.get_response_processing_timeout(attachment)
end

function nano.get_response_processing_timeout_sec()
    local timeout_ms = nano.get_response_processing_timeout()
    return timeout_ms / 1000  -- Convert milliseconds to seconds
end

return nano
