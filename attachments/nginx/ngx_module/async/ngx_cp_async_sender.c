#include "ngx_cp_async_sender.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <errno.h>
#include <stddef.h>
#include <poll.h>

#include "ngx_cp_async_core.h"
#include "ngx_cp_async_ctx_validation.h"
#include "../ngx_cp_utils.h"
#include "../ngx_cp_io.h"
#include "../ngx_cp_initializer.h"

///
/// @brief Signals nano service about new session to inspect with timeout protection.
/// @param[in] cur_session_id Session's Id.
/// @param[in] ctx Async context for setting flow_error on timeout (can be NULL).
/// @param[in] timeout_ms Write timeout in milliseconds (default 200ms if 0).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR  
///         - #NGX_HTTP_REQUEST_TIME_OUT
///
static ngx_int_t
ngx_http_cp_signal_to_service_with_timeout(uint32_t cur_session_id, ngx_uint_t timeout_ms)
{
    int res = 0;
    size_t bytes_written = 0;
    ngx_uint_t actual_timeout_ms = timeout_ms > 0 ? timeout_ms : 200; // Default 200ms
    struct pollfd poll_fd;
    int poll_result;

    write_dbg(DBG_LEVEL_TRACE, "Signaling service for session %d (timeout: %dms)", cur_session_id, actual_timeout_ms);
    while (bytes_written < sizeof(cur_session_id)) {
        res = write(comm_socket, ((char *)&cur_session_id) + bytes_written, sizeof(cur_session_id) - bytes_written);
        
        if (res > 0) {
            bytes_written += res;
            continue;
        }
        
        if (res < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket would block - use poll to wait for write readiness with timeout
                poll_fd.fd = comm_socket;
                poll_fd.events = POLLOUT;
                poll_fd.revents = 0;
                
                poll_result = poll(&poll_fd, 1, actual_timeout_ms);
                
                if (poll_result < 0) {
                    write_dbg(DBG_LEVEL_WARNING, "Poll failed for comm_socket write: %s", strerror(errno));
                    disconnect_communication();
                    return NGX_ERROR;
                } else if (poll_result == 0) {
                    write_dbg(DBG_LEVEL_DEBUG, "Write timeout (%dms) reached during signal to nano service for session %d", actual_timeout_ms, cur_session_id);
                    return NGX_HTTP_REQUEST_TIME_OUT;
                } else {
                    // Socket is ready for writing, continue the loop
                    continue;
                }
            } else {
                // Fatal write error - disconnect and return error
                write_dbg(DBG_LEVEL_WARNING, "Fatal write error on comm_socket: %s", strerror(errno));
                disconnect_communication();
                return NGX_ERROR;
            }
        } else {
            // res == 0, which shouldn't happen for write() on a socket
            write_dbg(DBG_LEVEL_WARNING, "Unexpected write() return value 0 on comm_socket");
            disconnect_communication();
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/// @brief Generic wait verdict handler for all wait stages
/// @param[in] ctx Async context
/// @param[in] stage_name Stage name for logging
/// @return NGX_OK, NGX_AGAIN, NGX_HTTP_FORBIDDEN, or NGX_ERROR
///
ngx_int_t
ngx_cp_async_wait_signal_sender(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent)
{
    int err_code = 0;
    ngx_int_t signal_res;
    uint32_t session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    
    if (session_id == 0) {
        write_dbg(DBG_LEVEL_WARNING, "Wait signal sender: invalid session ID");
        return NGX_ERROR;
    }
    
    static const ngx_uint_t wait_fragments_count = 2;
    char *fragments[wait_fragments_count];
    uint16_t fragments_sizes[wait_fragments_count];
    AttachmentDataType transaction_type = REQUEST_DELAYED_VERDICT;
    
    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&transaction_type, &session_id);
    
    write_dbg(DBG_LEVEL_DEBUG, "Sending async wait data to shared memory for session %d", session_id);
    
    err_code = sendChunkedData(nano_service_ipc, fragments_sizes, (const char **)fragments, wait_fragments_count);
    if (err_code != 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send wait data to shared memory for session %d, error: %d", session_id, err_code);
        disconnect_communication();
        return NGX_ERROR;
    }
    ngx_cp_async_increment_pending_chunks(session_id, "wait_signal");

    write_dbg(DBG_LEVEL_DEBUG, "Signaling agent service about wait data for session %d with %dms timeout protection", session_id, async_signal_timeout_ms);
    signal_res = ngx_http_cp_signal_to_service_with_timeout(session_id, async_signal_timeout_ms);
    if (signal_res != NGX_OK) {
        if (signal_res == NGX_HTTP_REQUEST_TIME_OUT) {
            write_dbg(DBG_LEVEL_DEBUG, "Signal timeout (%dms) reached for wait data, session %d - flow_error set", async_signal_timeout_ms, session_id);
            ngx_cp_async_post_backpressure_drain_event();
            return NGX_HTTP_REQUEST_TIME_OUT;
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Failed to signal service for wait data, session %d", session_id);
        }
        return NGX_ERROR;
    }
    
    *num_messages_sent = 1;
    return NGX_OK;
}

///
/// @brief Async version of ngx_http_cp_meta_data_sender - sends data but doesn't wait
/// @param[in] ctx Async context
/// @param[out] num_messages_sent Number of messages sent
/// @return NGX_OK on success, NGX_ERROR on failure, INSPECTION_IRRELEVANT if irrelevant
///
ngx_int_t
ngx_cp_async_send_meta_data_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent)
{
    static ngx_str_t ngx_parsed_host_str = ngx_string("host");
    char client_ip[INET6_ADDRSTRLEN];
    char listening_ip[INET6_ADDRSTRLEN];
    uint16_t client_ip_len;
    uint16_t listening_ip_len;
    uint16_t client_port;
    uint16_t chunck_type;
    uint16_t listening_port;
    ngx_int_t res;
    ngx_str_t maybe_host = { 0, (u_char *)"" };
    ngx_str_t ngx_parsed_host = { 0, (u_char *)"" };
    ngx_str_t parsed_uri = { 0, (u_char *)"" };
    ngx_http_variable_value_t *ngx_var;
    char *fragments[META_DATA_COUNT + 2];
    uint16_t fragments_sizes[META_DATA_COUNT + 2];
    int err_code = 0;
    
    write_dbg(DBG_LEVEL_TRACE, "Sending request start meta data for session %d", ctx->session_id);
    
    convert_sock_addr_to_string(((struct sockaddr *)ctx->request->connection->sockaddr), client_ip);
    if(!is_inspection_required_for_source(client_ip)) return INSPECTION_IRRELEVANT;
    
    chunck_type = REQUEST_START;
    set_fragments_identifiers(fragments, fragments_sizes, &chunck_type, &ctx->session_id);
    
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &ctx->request->http_protocol.len,
        sizeof(uint16_t),
        HTTP_PROTOCOL_SIZE + 2
    );
    
    set_fragment_elem(
        fragments,
        fragments_sizes,
        ctx->request->http_protocol.data,
        ctx->request->http_protocol.len,
        HTTP_PROTOCOL_DATA + 2
    );
    
    set_fragment_elem(fragments, fragments_sizes, &ctx->request->method_name.len, sizeof(uint16_t), HTTP_METHOD_SIZE + 2);
    set_fragment_elem(
        fragments,
        fragments_sizes,
        ctx->request->method_name.data,
        ctx->request->method_name.len,
        HTTP_METHOD_DATA + 2
    );
    
    ngx_var = ngx_http_get_variable(ctx->request, &ngx_parsed_host_str, ngx_hash_key(ngx_parsed_host_str.data, ngx_parsed_host_str.len));
    if (ngx_var == NULL || ngx_var->not_found) {
        write_dbg(DBG_LEVEL_DEBUG, "No parsed host found, using headers host");
        if (ctx->request->headers_in.host != NULL) {
            maybe_host.data = ctx->request->headers_in.host->value.data;
            maybe_host.len = ctx->request->headers_in.host->value.len;
        }
    } else {
        ngx_parsed_host.data = ngx_var->data;
        ngx_parsed_host.len = ngx_var->len;
    }
    
    if (ctx->request->uri.len > 0) {
        parsed_uri.data = ctx->request->uri.data;
        parsed_uri.len = ctx->request->uri.len;
    } else {
        parsed_uri.data = ctx->request->unparsed_uri.data;
        parsed_uri.len = ctx->request->unparsed_uri.len;
    }
    
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &maybe_host.len,
        sizeof(uint16_t),
        HOST_NAME_SIZE + 2
    );
    set_fragment_elem(
        fragments,
        fragments_sizes,
        maybe_host.data,
        maybe_host.len,
        HOST_NAME_DATA + 2
    );
    
    // Add listening IP and port data (exact same logic)
    convert_sock_addr_to_string(((struct sockaddr *)ctx->request->connection->local_sockaddr), listening_ip);
    listening_ip_len = strlen(listening_ip);
    set_fragment_elem(fragments, fragments_sizes, &listening_ip_len, sizeof(uint16_t), LISTENING_ADDR_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, listening_ip, listening_ip_len, LISTENING_ADDR_DATA + 2);
    
    listening_port = htons(((struct sockaddr_in *)ctx->request->connection->local_sockaddr)->sin_port);
    set_fragment_elem(fragments, fragments_sizes, &listening_port, sizeof(listening_port), LISTENING_PORT + 2);
    
    // Add URI data (exact same logic)
    set_fragment_elem(fragments, fragments_sizes, &ctx->request->unparsed_uri.len, sizeof(uint16_t), URI_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, ctx->request->unparsed_uri.data, ctx->request->unparsed_uri.len, URI_DATA + 2);
    
    // Add client IP and port data (exact same logic)
    client_ip_len = strlen(client_ip);
    set_fragment_elem(fragments, fragments_sizes, &client_ip_len, sizeof(uint16_t), CLIENT_ADDR_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, client_ip, client_ip_len, CLIENT_ADDR_DATA + 2);
    
    client_port = htons(((struct sockaddr_in *)ctx->request->connection->sockaddr)->sin_port);
    set_fragment_elem(fragments, fragments_sizes, &client_port, sizeof(client_port), CLIENT_PORT + 2);
    
    // Add parsed host and URI data (exact same logic)
    set_fragment_elem(fragments, fragments_sizes, &ngx_parsed_host.len, sizeof(uint16_t), PARSED_HOST_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, ngx_parsed_host.data, ngx_parsed_host.len, PARSED_HOST_DATA + 2);
    
    set_fragment_elem(fragments, fragments_sizes, &parsed_uri.len, sizeof(uint16_t), PARSED_URI_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, parsed_uri.data, parsed_uri.len, PARSED_URI_DATA + 2);
    
    // Add WAF tag data (exact same logic)
    if (ctx->waf_tag.len > 0) {
        set_fragment_elem(fragments, fragments_sizes, &ctx->waf_tag.len, sizeof(uint16_t), WAF_TAG_SIZE + 2);
        set_fragment_elem(fragments, fragments_sizes, ctx->waf_tag.data, ctx->waf_tag.len, WAF_TAG_DATA + 2);
    } else {
        uint16_t zero = 0;
        set_fragment_elem(fragments, fragments_sizes, &zero, sizeof(uint16_t), WAF_TAG_SIZE + 2);
        set_fragment_elem(fragments, fragments_sizes, "", 0, WAF_TAG_DATA + 2);
    }
    
    write_dbg(DBG_LEVEL_TRACE, "Sending meta data to shared memory");
    
    err_code = sendChunkedData(nano_service_ipc, fragments_sizes, (const char **)fragments, META_DATA_COUNT + 2);
    if (err_code != 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send meta data chunk - error code %d", err_code);
        disconnect_communication();
        return NGX_ERROR;
    }
    ngx_cp_async_increment_pending_chunks(ctx->session_id, "meta_data");

    write_dbg(DBG_LEVEL_TRACE, "Signaling agent for meta data (timeout: %dms)", async_signal_timeout_ms);
    res = ngx_http_cp_signal_to_service_with_timeout(ctx->session_id, async_signal_timeout_ms);
    if (res != NGX_OK && res != NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to signal agent for single body chunk, session %d", ctx->session_id);
        return NGX_ERROR;
    }
    
    if (res == NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_DEBUG, "Signal timeout (%dms) reached for single body chunk, session %d", async_signal_timeout_ms, ctx->session_id);
        ngx_cp_async_post_backpressure_drain_event();
    }    
    
    *num_messages_sent = 1;
    return NGX_OK;
}

///
/// @brief Async version of ngx_http_cp_header_sender - sends data but doesn't wait
/// @param[in] ctx Async context
/// @param[out] num_messages_sent Number of messages sent
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t
ngx_cp_async_send_headers_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent)
{
    ngx_uint_t header_idx = 0;
    ngx_uint_t idx_in_bulk = 0;
    ngx_uint_t num_of_bulks_sent = 0;
    uint8_t part_count = 0;
    uint8_t bulk_part_idx = 0;
    uint8_t is_last_part;
    ngx_list_part_t *headers_iter;
    ngx_table_elt_t *headers_to_inspect;
    ngx_table_elt_t *header;
    const ngx_uint_t max_bulk_size = 10;
    char *fragments[HEADER_DATA_COUNT * max_bulk_size + 4];
    uint16_t fragments_sizes[HEADER_DATA_COUNT * max_bulk_size + 4];
    int err_code = 0;
    ngx_int_t res;
    
    write_dbg(DBG_LEVEL_TRACE, "Sending request headers for session %d", ctx->session_id);
    
    uint16_t header_type = REQUEST_HEADER;
    set_fragments_identifiers(fragments, fragments_sizes, &header_type, &ctx->session_id);
    
    for (headers_iter = &(ctx->request->headers_in.headers.part); headers_iter; headers_iter = headers_iter->next) {
        for (header_idx = 0; header_idx < headers_iter->nelts; ++header_idx) {
            headers_to_inspect = headers_iter->elts;
            header = headers_to_inspect + header_idx;
            
            write_dbg(
                DBG_LEVEL_TRACE,
                "Header: '%.*s': '%.*s'",
                header->key.len,
                header->key.data,
                header->value.len,
                header->value.data
            );
            
            is_last_part = (headers_iter->next == NULL && header_idx + 1 == headers_iter->nelts) ? 1 : 0;
            add_header_to_bulk(fragments, fragments_sizes, header, idx_in_bulk);
            
            idx_in_bulk++;
            part_count++;
            if (idx_in_bulk < max_bulk_size && !is_last_part) continue;
            
            set_fragment_elem(fragments, fragments_sizes, &is_last_part, sizeof(is_last_part), 2);
            set_fragment_elem(fragments, fragments_sizes, &bulk_part_idx, sizeof(bulk_part_idx), 3);
            
            write_dbg(DBG_LEVEL_TRACE, "Sending header bulk to shared memory");
            err_code = sendChunkedData(
                nano_service_ipc,
                fragments_sizes, 
                (const char **)fragments,
                HEADER_DATA_COUNT * idx_in_bulk + 4
            );

            if (err_code != 0) {
                write_dbg(DBG_LEVEL_WARNING, "Failed to send header bulk - error code %d", err_code);
                disconnect_communication();
                return NGX_ERROR;
            }
            
            ngx_cp_async_increment_pending_chunks(ctx->session_id, "headers");
            
            num_of_bulks_sent++;
            
            if (is_last_part) break;
            
            idx_in_bulk = 0;
            bulk_part_idx = part_count;
        }
    }
    
    if (part_count == 0) {
        write_dbg(DBG_LEVEL_TRACE, "Sending empty header list");
        
        uint8_t is_last_part = 1;
        uint8_t bulk_part_idx = 0;
        set_fragment_elem(fragments, fragments_sizes, &is_last_part, sizeof(is_last_part), 2);
        set_fragment_elem(fragments, fragments_sizes, &bulk_part_idx, sizeof(bulk_part_idx), 3);
        
        err_code = sendChunkedData(
            nano_service_ipc,
            fragments_sizes, 
            (const char **)fragments,
            HEADER_DATA_COUNT * 1 + 4
        );

        if (err_code != 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to send empty header list - error code %d", err_code);
            disconnect_communication();
            return NGX_ERROR;
        }
        
        // Increment pending chunks counter for empty headers
        ngx_cp_async_increment_pending_chunks(ctx->session_id, "headers");
        
        num_of_bulks_sent = 1;
    }
    
    // Signal agent once after all header bulks are sent
    write_dbg(DBG_LEVEL_TRACE, "Signaling agent for headers (timeout: %dms)", async_signal_timeout_ms);
    res = ngx_http_cp_signal_to_service_with_timeout(ctx->session_id, async_signal_timeout_ms);
    if (res != NGX_OK && res != NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to signal agent for single body chunk, session %d", ctx->session_id);
        return NGX_ERROR;
    }
    
    if (res == NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_DEBUG, "Signal timeout (%dms) reached for single body chunk, session %d", async_signal_timeout_ms, ctx->session_id);
        ngx_cp_async_post_backpressure_drain_event();
    }
    
    *num_messages_sent = num_of_bulks_sent;
    return NGX_OK;
}

///
/// @brief Async version of ngx_http_cp_end_transaction_sender - sends data but doesn't wait
/// @param[in] ctx Async context
/// @param[out] num_messages_sent Number of messages sent
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t
ngx_cp_async_send_end_transaction_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent)
{
    char *fragments[2];
    uint16_t fragments_sizes[2];
    uint16_t chunck_type = REQUEST_END;
    int err_code = 0;
    ngx_int_t res;
    
    write_dbg(DBG_LEVEL_TRACE, "Sending end transaction for session %d", ctx->session_id);

    set_fragments_identifiers(fragments, fragments_sizes, &chunck_type, &ctx->session_id);
    err_code = sendChunkedData(nano_service_ipc, fragments_sizes, (const char **)fragments, 2);
    if (err_code != 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send end transaction - error code %d", err_code);
        disconnect_communication();
        return NGX_ERROR;
    }
    
    ngx_cp_async_increment_pending_chunks(ctx->session_id, "end_transaction");

    write_dbg(DBG_LEVEL_TRACE, "Signaling agent for end transaction (timeout: %dms)", async_signal_timeout_ms);
    res = ngx_http_cp_signal_to_service_with_timeout(ctx->session_id, async_signal_timeout_ms);
    if (res != NGX_OK && res != NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to signal agent for end transaction");
        return NGX_ERROR;
    }

    if (res == NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_DEBUG, "Signal timeout (%dms) reached for end transaction, session %d", async_signal_timeout_ms, ctx->session_id);
        ngx_cp_async_post_backpressure_drain_event();
    }
    
    *num_messages_sent = 1;
    ctx->end_transaction_sent = 1;
    return NGX_OK;
}

ngx_int_t
ngx_cp_async_send_single_body_chunk_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_chain_t *chunk, ngx_uint_t *num_messages_sent)
{
    static const ngx_uint_t num_body_chunk_fragments = 5;
    
    ngx_buf_t *buf;
    ngx_int_t res = NGX_ERROR;
    uint8_t is_last_chunk;
    uint8_t part_count = 0;
    size_t buf_size;
    char *fragments[num_body_chunk_fragments];
    uint16_t fragments_sizes[num_body_chunk_fragments];
    AttachmentDataType body_type = REQUEST_BODY;
    
    write_dbg(DBG_LEVEL_DEBUG, "Sending single body chunk for session %d", ctx->session_id);
    
    if (chunk == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "No chunk data to send for session %d", ctx->session_id);
        *num_messages_sent = 0;
        return NGX_OK;
    }
    
    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&body_type, &ctx->session_id);
    
    buf = chunk->buf;
    is_last_chunk = buf->last_buf ? 1 : 0;
    buf_size = buf->last - buf->pos;
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Processing single body chunk of size: %zu, last_chunk: %d for session %d",
        buf_size,
        is_last_chunk,
        ctx->session_id
    );
    
    if (buf_size > 0 || is_last_chunk) {
        set_fragment_elem(fragments, fragments_sizes, &is_last_chunk, sizeof(is_last_chunk), 2);
        set_fragment_elem(fragments, fragments_sizes, &part_count, sizeof(part_count), 3);
        set_fragment_elem(fragments, fragments_sizes, buf->pos, buf->last - buf->pos, 4);
        
        ctx->session_data->processed_req_body_size += (buf->last - buf->pos);
        
        write_dbg(DBG_LEVEL_DEBUG, "Sending single body chunk to agent for session %d", ctx->session_id);
        res = sendChunkedData(nano_service_ipc, fragments_sizes, (const char **)fragments, num_body_chunk_fragments);
        if (res != 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to send single body chunk to agent for session %d: %d", ctx->session_id, res);
            disconnect_communication();
            return NGX_ERROR;
        }
        ngx_cp_async_increment_pending_chunks(ctx->session_id, "body_chunk");
        
        res = ngx_http_cp_signal_to_service_with_timeout(ctx->session_id, async_signal_timeout_ms);
        if (res != NGX_OK && res != NGX_HTTP_REQUEST_TIME_OUT) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to signal agent for single body chunk, session %d", ctx->session_id);
            return NGX_ERROR;
        }
        
        if (res == NGX_HTTP_REQUEST_TIME_OUT) {
            write_dbg(DBG_LEVEL_DEBUG, "Signal timeout (%dms) reached for single body chunk, session %d", async_signal_timeout_ms, ctx->session_id);
            ngx_cp_async_post_backpressure_drain_event();
        }

        *num_messages_sent = 1;
        return NGX_OK;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Empty single chunk for session %d", ctx->session_id);
    *num_messages_sent = 0;
    return NGX_OK;
}


ngx_int_t
ngx_cp_async_send_to_agent_nonblocking(
    ngx_http_cp_async_ctx_t *ctx, 
    AttachmentDataType chunk_type,
    const void *data, 
    uint16_t data_size)
{
    ngx_int_t res;
    NanoHttpRequestData *request_data;
    uint16_t total_size;
    const char *chunks[2];
    uint16_t chunk_sizes[2];
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Sending non-blocking data to agent for session %d, type: %d", 
        ctx->session_id,
        chunk_type
    );
    
    total_size = sizeof(NanoHttpRequestData) + data_size;
    
    request_data = ngx_palloc(ctx->request->pool, total_size);
    if (request_data == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate request data for session %d", ctx->session_id);
        return NGX_ERROR;
    }
    
    request_data->data_type = chunk_type;
    request_data->session_id = ctx->session_id;
    
    if (data && data_size > 0) {
        ngx_memcpy(request_data->data, data, data_size);
    }
    
    chunks[0] = (const char *)request_data;
    chunk_sizes[0] = total_size;
    
    res = sendChunkedData(nano_service_ipc, chunk_sizes, chunks, 1);
    if (res != 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send data to agent for session %d: %d", ctx->session_id, res);
        disconnect_communication();
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

ngx_int_t
ngx_cp_async_signal_agent_nonblocking(ngx_http_cp_async_ctx_t *ctx)
{
    ssize_t bytes_written;
    uint32_t session_id = ctx->session_id;
    
    write_dbg(DBG_LEVEL_TRACE, "Signaling agent for session %d", ctx->session_id);
    
    if (comm_socket < 0) {
        write_dbg(DBG_LEVEL_ERROR, "Communication socket not ready yet for session %d - skipping signal", ctx->session_id);
        return NGX_OK;
    }
    
    bytes_written = write(comm_socket, &session_id, sizeof(session_id));
    if (bytes_written != sizeof(session_id)) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to signal agent for session %d: %zd", ctx->session_id, bytes_written);
        return NGX_ERROR;
    }
    
    return NGX_OK;
}
