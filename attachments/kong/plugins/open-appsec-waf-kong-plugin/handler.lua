local nano = require "kong.plugins.open-appsec-waf-kong-plugin.nano_ffi"
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
        end
    else
        verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_REQUEST_END)
        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            kong.ctx.plugin.blocked = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end
    end

    NanoHandler.processed_requests[session_id] = true
end

function NanoHandler.header_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked then
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
    if verdict == nano.AttachmentVerdict.DROP then
        kong.ctx.plugin.blocked = true
        nano.fini_session(session_data)
        nano.cleanup_all()
        return nano.handle_custom_response(session_data, response)
    end

    ctx.expect_body = not (status_code == 204 or status_code == 304 or (100 <= status_code and status_code < 200) or content_length == 0)
end

function NanoHandler.body_filter(conf)
    local ctx = kong.ctx.plugin
    if ctx.blocked then
        return
    end

    local session_id = ctx.session_id
    local session_data = ctx.session_data

    if not session_id or not session_data or ctx.session_finalized then
        return
    end

    local body = kong.response.get_raw_body()

    if body and #body > 0 then
        ctx.body_seen = true
        local verdict, response, modifications = nano.send_body(session_id, session_data, body, nano.HttpChunkType.HTTP_RESPONSE_BODY)

        ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0

        if modifications then
            body = nano.handle_body_modifications(body, modifications, ctx.body_buffer_chunk)
            kong.response.set_raw_body(body)
        end

        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            ctx.session_finalized = true
            local result = nano.handle_custom_response(session_data, response)
            nano.cleanup_all()
            return result
        end
        return
    elseif ctx.expect_body then
        kong.log.debug("Response body not in memory, attempting to read from buffer/file")

        local body_data = ngx.var.response_body
        if body_data and #body_data > 0 then
            kong.log.debug("Found response body in nginx var, size: ", #body_data)
            ctx.body_seen = true
            local verdict, response, modifications = nano.send_body(session_id, session_data, body_data, nano.HttpChunkType.HTTP_RESPONSE_BODY)

            ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0

            if modifications then
                body_data = nano.handle_body_modifications(body_data, modifications, ctx.body_buffer_chunk)
                kong.response.set_raw_body(body_data)
            end

            ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

            if verdict == nano.AttachmentVerdict.DROP then
                nano.fini_session(session_data)
                ctx.session_finalized = true
                local result = nano.handle_custom_response(session_data, response)
                nano.cleanup_all()
                return result
            end
            return
        else
            -- Try to read from response body file
            local body_file = ngx.var.response_body_file
            if body_file then
                kong.log.debug("Reading response body from file: ", body_file)
                local file = io.open(body_file, "rb")
                if file then
                    local entire_body = file:read("*all")
                    file:close()

                    if entire_body and #entire_body > 0 then
                        kong.log.debug("Sending entire response body of size ", #entire_body, " bytes to C module")
                        ctx.body_seen = true
                        local verdict, response, modifications = nano.send_body(session_id, session_data, entire_body, nano.HttpChunkType.HTTP_RESPONSE_BODY)

                        ctx.body_buffer_chunk = ctx.body_buffer_chunk or 0

                        if modifications then
                            entire_body = nano.handle_body_modifications(entire_body, modifications, ctx.body_buffer_chunk)
                            kong.response.set_raw_body(entire_body)
                        end

                        ctx.body_buffer_chunk = ctx.body_buffer_chunk + 1

                        if verdict == nano.AttachmentVerdict.DROP then
                            nano.fini_session(session_data)
                            ctx.session_finalized = true
                            local result = nano.handle_custom_response(session_data, response)
                            nano.cleanup_all()
                            return result
                        end
                        return
                    end
                else
                    kong.log.warn("Failed to open response body file: ", body_file)
                end
            else
                kong.log.debug("Response body expected but no body data or file available")
            end
        end
    end

    if ctx.body_seen or ctx.expect_body == false then
        local verdict, response = nano.end_inspection(session_id, session_data, nano.HttpChunkType.HTTP_RESPONSE_END)
        if verdict == nano.AttachmentVerdict.DROP then
            nano.fini_session(session_data)
            ctx.session_finalized = true
            local result = nano.handle_custom_response(session_data, response)
            -- Clean up allocated memory
            nano.cleanup_all()
            return result
        end

        nano.fini_session(session_data)
        -- Clean up allocated memory
        nano.cleanup_all()
        ctx.session_finalized = true
    end
end

return NanoHandler
