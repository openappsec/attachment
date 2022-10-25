// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file ngx_cp_custom_response.c
#include "ngx_cp_custom_response.h"

#include "ngx_cp_utils.h"

///
/// @brief Pushes a key and value into a header list.
/// @param[in, out] headers_list Headers list to push the new head into.
/// @param[in] key_data_size Key data size to be pushed.
/// @param[in, out] key_data Key data to be pushed.
/// @param[in] value_data_size Value data size to be pushed.
/// @param[in, out] value_data Value data to be pushed.
/// @return ngx_table_elt_t
///      - #A pointer to the pushed NGINX header element.
///      - #NULL if failed.
///
static ngx_table_elt_t *
push_header_to_list(
    ngx_list_t *headers_list,
    int16_t key_data_size,
    u_char *key_data,
    int16_t value_data_size,
    u_char *value_data
);

///
/// @brief Allocates a file buffer to the provided file.
/// @param[in, out] memory_pool NGINX pool.
/// @param[in, out] open_file_info NGINX file info - file information.
/// @param[in, out] is_last_buffer Symbolize if the newly allocated buffer is the last buffer.
/// @param[in, out] file_path NGINX string.
/// @param[in, out] log NGINX log.
/// @returns ngx_buf_t
///      - #A valid pointer to NGINX buffer.
///      - #NULL
///
static ngx_buf_t *
allocate_file_buffer(
    ngx_pool_t *memory_pool,
    ngx_open_file_info_t *open_file_info,
    ngx_int_t is_last_buffer,
    ngx_str_t *file_path,
    ngx_log_t *log
)
{
    ngx_buf_t *file_buffer = ngx_calloc_buf(memory_pool);
    if (file_buffer == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate file buffer: could not allocate memory for the buffer");
        return NULL;
    }

    file_buffer->file = ngx_pcalloc(memory_pool, sizeof(ngx_file_t));
    if (file_buffer->file == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate file buffer's file descriptor");

        ngx_pfree(memory_pool, file_buffer);
        return NULL;
    }

    file_buffer->file_pos = 0;
    file_buffer->file_last = open_file_info->size;
    file_buffer->in_file = file_buffer->file_last ? 1: 0;
    file_buffer->last_buf = is_last_buffer;
    file_buffer->last_in_chain = 1;
    file_buffer->file->fd = open_file_info->fd;
    file_buffer->file->name = *file_path;
    file_buffer->file->log = log;
    file_buffer->file->directio = open_file_info->is_directio;

    return file_buffer;
}

///
/// @brief Deletes the provided header list.
/// @details Iterates over the header list and frees all the nodes' memory back to the NGX pool.
/// @param[in, out] headers_list
///
static void
delete_headers_list(ngx_list_t *headers_list)
{
    ngx_list_part_t *headers_iter = headers_list->part.next;
    ngx_list_part_t *header_to_del;

    while (headers_iter) {
        header_to_del = headers_iter;
        headers_iter = headers_iter->next;
        ngx_pfree(headers_list->pool, header_to_del->elts);
        header_to_del->elts = NULL;
        header_to_del->nelts = 0;
        ngx_pfree(headers_list->pool, header_to_del);
    }

    headers_list->part.nelts = 0;
    headers_list->last = &headers_list->part;
    headers_list->part.next = NULL;
}

ngx_int_t
ngx_http_cp_response_headers_sender(
    ngx_http_request_t *request,
    const ngx_uint_t response_code,
    const off_t content_length,
    const time_t last_modified_time,
    const unsigned int allow_ranges,
    const unsigned int keepalive
)
{
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Generating response headers: response code: %ui, content length: %O, last modified time: %T",
        response_code,
        content_length,
        last_modified_time
    );

    // Writes the custom response data onto the response headers.
    request->headers_out.status = response_code;
    request->headers_out.content_length_n = content_length;
    request->headers_out.last_modified_time = last_modified_time;
    request->allow_ranges = allow_ranges;
    request->keepalive = keepalive;

    if (ngx_http_set_content_type(request) != NGX_OK) {
        // Failed to get the header's type.
        write_dbg(DBG_LEVEL_WARNING, "Failed to set content type header");
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_DEBUG,"Successfully generated response headers, sending response headers");
    return ngx_http_send_header(request);
}

ngx_int_t
ngx_http_cp_file_response_sender(
    ngx_http_request_t *request,
    ngx_str_t *file_path,
    ngx_open_file_info_t *open_file_info,
    ngx_int_t is_main_request,
    ngx_log_t *log,
    ngx_pool_t *memory_pool
)
{
    ngx_int_t is_last_buffer;
    ngx_buf_t *file_buffer;
    ngx_int_t send_output_chain_result;
    ngx_chain_t *output_chain;

    write_dbg(DBG_LEVEL_DEBUG, "Trying to send file: %.*s", file_path->len, file_path->data);

    is_last_buffer = is_main_request ? 1: 0;

    // Allocates file's buffer and NGINX chain.
    file_buffer = allocate_file_buffer(memory_pool, open_file_info, is_last_buffer, file_path, log);

    output_chain = ngx_alloc_chain_link(memory_pool);
    output_chain->buf = file_buffer;
    output_chain->next = NULL;

    send_output_chain_result = ngx_http_output_filter(request, output_chain);

    ngx_pfree(memory_pool, file_buffer->file);
    ngx_pfree(memory_pool, file_buffer);

    return send_output_chain_result;
}

///
/// @brief Adds event ID to the provided NGINX request.
/// @param[in, out] request NGINX request.
/// 
void
ngx_add_event_id_to_header(ngx_http_request_t *request)
{
    u_char *uuid = (u_char *)get_web_response_uuid();
    ngx_uint_t uuid_size = get_web_response_uuid_size();
    static u_char uuid_key[] = { 'x', '_', 'e', 'v', 'e', 'n', 't', '_', 'i', 'd' };

    write_dbg(
        DBG_LEVEL_WARNING,
        "Adding instance ID to header. Incident ID: %s, Incident ID size: %d",
        uuid,
        uuid_size
    );
    push_header_to_list(
        &(request->headers_out.headers),
        sizeof(uuid_key),
        uuid_key,
        uuid_size,
        uuid
    );
}

ngx_int_t
ngx_http_cp_finalize_rejected_request(ngx_http_request_t *request)
{
    static u_char text_html[] = {'t', 'e', 'x', 't', '/', 'h', 't', 'm', 'l'};
    static size_t size_of_text_html = sizeof(text_html);
    ngx_int_t res_code, res;
    ngx_table_elt_t *location_header;
    ngx_chain_t out_chain[7]; // http://lxr.nginx.org/source/src/http/ngx_http_special_response.c#0772
    int send_response_custom_body = 1;

    write_dbg(DBG_LEVEL_TRACE, "Finalizing rejecting request");

    request->keepalive = 0;

    res_code = get_response_code();
    request->headers_out.status = res_code;
    request->headers_out.status_line.len = 0;

    if (res_code == 0) {
        // Response code was not provided, setting it to NGX_HTTP_CLOSE.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Response code was not provided. Returning default response: %d (NGX_HTTP_CLOSE)",
            NGX_HTTP_CLOSE
        );
        res_code = NGX_HTTP_CLOSE;
        request->headers_out.status = res_code;

        goto CUSTOM_RES_OUT;
    }

    if (get_response_code() == NGX_HTTP_TEMPORARY_REDIRECT) {
        // Handling redirect web response.
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Sending Redirect web response"
        );

        static u_char location_key[] = {'L', 'o', 'c', 'a', 't', 'i', 'o', 'n'};
        location_header  = push_header_to_list(
            &(request->headers_out.headers),
            sizeof(location_key),
            location_key,
            get_redirect_location_size(),
            get_redirect_location()
        );
        if (location_header == NULL) {
            // Failed to allocate header.
            write_dbg(DBG_LEVEL_ERROR, "Failed to allocate header");
            res_code = NGX_HTTP_CLOSE;
            goto CUSTOM_RES_OUT;
        }

        if (get_add_event_id()) {
            // Add event ID into the header.
            ngx_add_event_id_to_header(request);
        }

        request->keepalive = 1;
        goto CUSTOM_RES_OUT;
    }

    ngx_add_event_id_to_header(request);

    if (get_response_page_length() == 0) {
        // Page details were not provided.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Web response page details were not provided. Returning %d response code",
            get_response_code()
        );
        send_response_custom_body = 0;
    }

    // Writes the finalized rejected data into the headers.
    request->headers_out.content_type.len = size_of_text_html;
    request->headers_out.content_type_len = request->headers_out.content_type.len;
    request->headers_out.content_type.data = text_html;
    request->headers_out.content_length_n = get_response_page_length();

    delete_headers_list(&request->headers_out.headers);

    write_dbg(DBG_LEVEL_TRACE, "Sending response headers for rejected request");
    res = ngx_http_send_header(request);
    if (res == NGX_ERROR || res > NGX_OK) {
        // Failed to send response headers.
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Failed to send response headers (result: %d). Returning response code: %d",
            res,
            res_code
        );
        goto CUSTOM_RES_OUT;
    }
    write_dbg(
        DBG_LEVEL_TRACE,
        "Successfully sent response headers for rejected request."
        " Generating web response page for rejected request."
    );

    if (send_response_custom_body) {
        // Sending response custom body.
        if (get_response_page(request, &out_chain) != NGX_OK) {
            // Failed to generate custom response page.
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Failed to generate web response page. Returning response code: %d",
                get_response_code()
            );
            goto CUSTOM_RES_OUT;
        }
        write_dbg(DBG_LEVEL_TRACE, "Successfully generated web response page for rejected request");
        write_dbg(DBG_LEVEL_TRACE, "Sending web response body");
        ngx_int_t output_filter_result = ngx_http_output_filter(request, out_chain);
        if (output_filter_result != NGX_OK) {
            // Failed to send response body.
            write_dbg(DBG_LEVEL_WARNING, "Failed to send web response body");
        } else {
            write_dbg(DBG_LEVEL_TRACE, "Successfully sent web response body");
        }
    } else {
        out_chain[0].buf = ngx_calloc_buf(request->pool);
        if (out_chain[0].buf == NULL) {
            // Failed to send web response.
            write_dbg(DBG_LEVEL_WARNING, "Failed to send web response");
            return NGX_ERROR;
        }
        out_chain[0].buf->last_buf = 1;
        out_chain[0].next = NULL;
        ngx_http_output_filter(request, &out_chain[0]);
    }

CUSTOM_RES_OUT:
    ngx_http_finalize_request(request, res_code);
    return res_code;
}

///
/// @brief Frees modification list.
/// @param[in, out] modification_list NGINX modifications.
/// @param[in, out] pool NGINX pool.
///
static void
free_modifications_list(ngx_http_cp_modification_list *modification_list, ngx_pool_t *pool)
{
    ngx_http_cp_modification_list *next_modification;

    write_dbg(DBG_LEVEL_DEBUG, "Freeing modification list");

    while (modification_list) {
        next_modification = modification_list->next;
        ngx_pfree(pool, modification_list->modification_buffer);
        ngx_pfree(pool, modification_list);
        modification_list = next_modification;
    }
}

///
/// @brief Injects the provided buffer at the provided position into the original_buffer.
/// @param[in, out] original_buffer NGINX string that new data will be injected to.
/// @param[in] injection_pos Injection position on the original buffer.
/// @param[in] injected_buffer_size Injected buffer size.
/// @param[in, out] injection_buffer Injected buffer.
/// @param[in, out] pool NGINX pool.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
inject_buffer(
    ngx_str_t *original_buffer,
    const size_t injection_pos,
    const size_t injected_buffer_size,
    u_char *injection_buffer,
    ngx_pool_t *pool
)
{
    size_t new_buffer_len;

    if (injection_pos > original_buffer->len) {
        // Injection position is after original buffer's end position.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Injection position is after original buffer's end. Injection position: %u, buffer's size: %u",
            injection_pos,
            original_buffer->len
        );
        return NGX_ERROR;
    }

    // Allocates memory for a new buffer.
    new_buffer_len = original_buffer->len + injected_buffer_size;
    u_char *new_buffer_value = ngx_palloc(pool, new_buffer_len);
    if (new_buffer_value == NULL) {
        // Failed to allocate memory for a new buffer.
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate memory for a new buffer, size: %u", new_buffer_len);
        return NGX_ERROR;
    }

    // Copies the injected data onto the original buffer.
    ngx_memcpy(new_buffer_value, original_buffer->data, injection_pos);
    ngx_memcpy(new_buffer_value + injection_pos, injection_buffer, injected_buffer_size);
    if (injection_pos < original_buffer->len) {
        ngx_memcpy(
            new_buffer_value + injection_pos + injected_buffer_size,
            original_buffer->data + injection_pos,
            original_buffer->len - injection_pos
        );
    }

    original_buffer->len = new_buffer_len;

    ngx_pfree(pool, original_buffer->data);
    original_buffer->data = new_buffer_value;

    return NGX_OK;
}

///
/// @brief Inject modification into a header's value.
/// @param[in, out] header NGINX string that the modifications will be injected into.
/// @param[in] modification Modifications to inject.
/// @param[in, out] header_pool NGINX pool.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
inject_header_value(
    ngx_table_elt_t *header,
    ngx_http_cp_modification_list *modification,
    ngx_pool_t *header_pool
)
{
    if (modification->modification.injection_pos < 0) {
        // Injection position is after original buffer's end position.
        write_dbg(DBG_LEVEL_ASSERT, "Negative injection position: %d", modification->modification.injection_pos);
    }

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Injecting buffer into header's value. "
        "Header's index: %ui, original header's data: '%.*s' (size: %u): '%.*s' (size: %u), "
        "injection position: %ui, injected buffer: %s (size: %u)",
        modification->modification.orig_buff_index,
        header->key.len,
        header->key.data,
        header->key.len,
        header->value.len,
        header->value.data,
        header->value.len,
        modification->modification.injection_pos,
        modification->modification_buffer,
        modification->modification.injection_size
    );

    // Inject the modification's buffer into the header.
    ngx_int_t inject_buffer_result = inject_buffer(
        &header->value,
        modification->modification.injection_pos,
        modification->modification.injection_size,
        (u_char *)modification->modification_buffer,
        header_pool
    );
    if (inject_buffer_result != NGX_OK) return NGX_ERROR;

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Successfully injected header value. Header's value after injection: %.*s (size: %u)",
        header->value.len,
        header->value.data,
        header->value.len
    );

    return NGX_OK;
}

static ngx_table_elt_t *
push_header_to_list(
    ngx_list_t *headers_list,
    int16_t key_data_size,
    u_char *key_data,
    int16_t value_data_size,
    u_char *value_data
)
{
    ngx_table_elt_t *header = ngx_list_push(headers_list);
    if (header == NULL) {
        // Failed to allocate header.
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate header");
        return NULL;
    }

    header->hash = 1;
    header->key.data = key_data;
    header->key.len = key_data_size;
    header->value.data = value_data;
    header->value.len = value_data_size;

    return header;
}

///
/// @brief Validate header modification.
/// @details Modifications come in two nodes: The first one handles the key, the other handles the value.
/// This function validates that the second node (which is the next) that holds data exists and if their
/// data is valid.
/// @param[in, out] modification
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
validate_append_header_modification(ngx_http_cp_modification_list *modification)
{
    write_dbg(DBG_LEVEL_DEBUG, "Validating append header modification data");

    if (modification->next == NULL) {
        // Modification data value for the provided modification is missing.
        write_dbg(DBG_LEVEL_WARNING, "Error: Append header modification is missing modification data for value");
        return NGX_ERROR;
    }
    if (!modification->modification.is_header || !modification->next->modification.is_header) {
        // Modification key or value are not of type header and therefor aren't a proper header modification.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Error: Append header modification is missing modification data for %s",
            !modification->modification.is_header ? "key" : "value"
        );
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Append header modification data is valid");
    return NGX_OK;
}

///
/// @brief Append modification into the headers list.
/// @param[in, out] headers_list NGINX list.
/// @param[in, out] modification modification to append into the header list.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
append_header(ngx_list_t *headers_list, ngx_http_cp_modification_list *modification)
{
    ngx_http_cp_modification_list *key_modification = modification;
    ngx_http_cp_modification_list *value_modification = modification->next;

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Appending header: '%s' (size: %ui) : '%s' (size: %ui)",
        key_modification->modification_buffer,
        key_modification->modification.injection_size,
        value_modification->modification_buffer,
        value_modification->modification.injection_size
    );
    // Appending the header.
    ngx_table_elt_t *new_header = push_header_to_list(
        headers_list,
        key_modification->modification.injection_size,
        (u_char *)key_modification->modification_buffer,
        value_modification->modification.injection_size,
        (u_char *)value_modification->modification_buffer
    );
    if (new_header == NULL) return NGX_ERROR;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Successfully appended header. Key: '%.*s' (size: %u), value: '%.*s' (size: %u)",
        new_header->key.len,
        new_header->key.data,
        new_header->key.len,
        new_header->value.len,
        new_header->value.data,
        new_header->value.len
    );

    return NGX_OK;
}

///
/// @brief Modifies a header using the modification list.
/// @param[in, out] request NGINX request.
/// @param[in, out] headers headers NGINX list.
/// @param[in, out] headers_iterator NGINX CP header iterator.
/// @param[in, out] modification Modifications list.
/// @param[in] type Modification type.
/// @param[in] is_content_length A flag if the header is content length.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
perform_header_modification(
    ngx_http_request_t *request,
    ngx_list_t *headers,
    ngx_http_cp_list_iterator *headers_iterator,
    ngx_http_cp_modification_list *modification,
    ngx_http_modification_type_e type,
    ngx_flag_t is_content_length
)
{
    ngx_table_elt_t *injected_header;

    switch (type) {
        case APPEND: {
            // Appends a modification into the header.
            if (append_header(headers, modification) != NGX_OK) {
                // Failed to append the modification.
                write_dbg(DBG_LEVEL_ERROR, "Failed to append header");

                return NGX_ERROR;
            }
            break;
        }
        case INJECT: {
            // Injects a modification into the header.
            injected_header = get_list_element(headers_iterator, modification->modification.orig_buff_index);
            if (injected_header == NULL) {
                // No header found with the index.
                write_dbg(
                    DBG_LEVEL_ASSERT,
                    "No header found with index %ui",
                    modification->modification.orig_buff_index
                )
                return NGX_ERROR;
            }

            if (inject_header_value(injected_header, modification, headers->pool) != NGX_OK) {
                // Failed to inject a header value.
                write_dbg(DBG_LEVEL_ERROR, "Failed to inject header value");

                return NGX_ERROR;
            }
            break;
        }
        case REPLACE: {
            if (is_content_length == 1) {
                // Replacing Content-Length.
                write_dbg(DBG_LEVEL_DEBUG, "Content-Length will be replaced")
                ngx_http_clear_content_length(request);
            }
            break;
        }
        default:
            // Failed to get a known modificatino type.
            write_dbg(DBG_LEVEL_ASSERT, "Unknown modification type: %d", type);
    }

    return NGX_OK;
}

///
/// @brief Get the next modification from modification list.
/// @param[in, out] modification Modification list to get the next header from.
/// @param[in, out] type Modification type.
/// @return ngx_http_cp_modification_list
///      - #ngx_http_cp_modification_list pointer to the next element.
///      - #NULL if failed to get the next element.
///
static ngx_http_cp_modification_list *
get_next_header_modification(ngx_http_cp_modification_list *modification, ngx_http_modification_type_e type)
{
    switch (type) {
        case APPEND:
            return modification->next->next;
        case INJECT:
        case REPLACE:
            return modification->next;
        default:
            write_dbg(DBG_LEVEL_ASSERT, "Unknown modification type: %d", type);
    }

    return NULL;
}

///
/// @brief Free modifications.
/// @param[in, out] modification Modification to free.
/// @param[in, out] type Modification type.
/// @param[in, out] pool NGINX pool.
///
static void
free_header_modification(
    ngx_http_cp_modification_list *modification,
    ngx_http_modification_type_e type,
    ngx_pool_t *pool
)
{
    write_dbg(DBG_LEVEL_DEBUG, "Freeing header modification");

    switch (type) {
        case APPEND: {
            ngx_pfree(pool, modification->next->modification_buffer);
            ngx_pfree(pool, modification->next);
            ngx_pfree(pool, modification->modification_buffer);
            ngx_pfree(pool, modification);
            break;
        }
        case INJECT:
        case REPLACE: {
            ngx_pfree(pool, modification->modification_buffer);
            ngx_pfree(pool, modification);
            break;
        }
        default:
            write_dbg(DBG_LEVEL_ASSERT, "Unknown modification type: %d", type);
    }
}

ngx_int_t
ngx_http_cp_header_modifier(
    ngx_list_t *headers,
    ngx_http_cp_modification_list *modifications,
    ngx_http_request_t *request,
    ngx_flag_t is_content_length
)
{
    ngx_http_modification_type_e type;
    ngx_http_cp_modification_list *next_modification;
    ngx_http_cp_list_iterator headers_iterator;
    init_list_iterator(headers, &headers_iterator);

    while (modifications != NULL) {
        // Check if modification is a header.
        if (!modifications->modification.is_header) return NGX_OK;

        type = modifications->modification.mod_type;

        write_dbg(
            DBG_LEVEL_DEBUG,
            type == APPEND ?
            "Appending header" :
            type == REPLACE ?
            "Changing header's value" :
            "Injecting into header's value");

        if (type == APPEND && validate_append_header_modification(modifications) != NGX_OK) {
            // Modification is not of a valid append type.
            free_modifications_list(modifications, request->pool);
            return NGX_ERROR;
        }

        if (perform_header_modification(
            request,
            headers,
            &headers_iterator,
            modifications,
            type,
            is_content_length
        ) != NGX_OK) {
            // Failed to perform modification on header
            write_dbg(DBG_LEVEL_WARNING, "Failed to perform modification on header");

            free_modifications_list(modifications, request->pool);
            return NGX_ERROR;
        }
        next_modification = get_next_header_modification(modifications, type);
        free_header_modification(modifications, type, request->pool);
        modifications = next_modification;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_cp_body_modifier(
    ngx_chain_t *body_chain,
    ngx_http_cp_modification_list *curr_modification,
    ngx_pool_t *pool
)
{
    ngx_http_cp_modification_list *next_modification;
    ngx_uint_t cur_body_chunk = 0;
    ngx_chain_t *chain_iter;
    ngx_chain_t *injected_chain_elem;
    ngx_uint_t num_appended_elements;
    size_t cur_chunk_size = 0;

    for (chain_iter = body_chain; chain_iter; chain_iter = chain_iter->next, cur_body_chunk++) {
        // Iterates of the body chains
        if (curr_modification == NULL) return NGX_OK;
        if (curr_modification->modification.orig_buff_index != cur_body_chunk) continue;

        cur_chunk_size = body_chain->buf->last - body_chain->buf->pos;
        if (cur_chunk_size == 0) {
            write_dbg(DBG_LEVEL_TRACE, "No need to modify body chunk of size 0. Chunk index: %d", cur_body_chunk);
            continue;
        }

        write_dbg(
            DBG_LEVEL_DEBUG,
            "Handling current modification. "
            "Injection position: %d, injection size: %d, original buffer index: %d, modification buffer: %s",
            curr_modification->modification.injection_pos,
            curr_modification->modification.injection_size,
            curr_modification->modification.orig_buff_index,
            curr_modification->modification_buffer
        );
        // Create a chain element.
        injected_chain_elem = create_chain_elem(
            curr_modification->modification.injection_size,
            curr_modification->modification_buffer,
            pool
        );

        if (injected_chain_elem == NULL) {
            free_modifications_list(curr_modification, pool);
            return NGX_ERROR;
        }

        write_dbg(DBG_LEVEL_DEBUG, "Handling modification of chain element number %d", cur_body_chunk);
        // Handling modification of a chain element.
        if (curr_modification->modification.injection_pos == 0) {
            // Pre appends chain element.
            prepend_chain_elem(chain_iter, injected_chain_elem);
            chain_iter = chain_iter->next;
            num_appended_elements = 0;
        } else if (curr_modification->modification.injection_pos == chain_iter->buf->last - chain_iter->buf->pos + 1) {
            // Prepend a chain element.
            append_chain_elem(chain_iter, injected_chain_elem);
            chain_iter = chain_iter->next;
            num_appended_elements = 1;
        } else {
            if (split_chain_elem(chain_iter, curr_modification->modification.injection_pos, pool) != NGX_OK) {
                // Failed to iterate over the modification.
                free_modifications_list(curr_modification, pool);
                return NGX_ERROR;
            }

            append_chain_elem(chain_iter, injected_chain_elem);
            chain_iter = chain_iter->next->next;
            num_appended_elements = 2;
        }

        // Moves to the next modification element and frees the modifier.
        next_modification = curr_modification->next;
        ngx_pfree(pool, curr_modification);
        curr_modification = next_modification;

        cur_body_chunk += num_appended_elements;
    }
    return NGX_OK;
}
