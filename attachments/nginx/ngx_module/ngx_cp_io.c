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

/// @file ngx_cp_io.h
#include "ngx_cp_io.h"

#include <ngx_core.h>

#include <poll.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "ngx_cp_utils.h"
#include "ngx_cp_initializer.h"
#include "ngx_http_cp_attachment_module.h"
#include "ngx_cp_metric.h"

#define NGX_CP_CONF_DISABLED 0
#define NGX_CP_CONF_ENABLED 1

static const ngx_int_t inspection_irrelevant = INSPECTION_IRRELEVANT;

extern uint64_t metric_data[METRIC_TYPES_COUNT];

SharedMemoryIPC *nano_service_ipc = NULL;
int comm_socket = -1;

///
/// @brief Signals the nano service about new session to inspect.
/// @param[in] cur_session_id Session's Id.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///         - #NGX_HTTP_REQUEST_TIME_OUT
///
static ngx_int_t
ngx_http_cp_signal_to_service(uint32_t cur_session_id)
{
    int res = 0;
    int bytes_written = 0;
    struct timeval timeout = get_timeout_val_sec(1);
    int is_fail_open_disabled = (inspection_mode != NON_BLOCKING_THREAD);

    write_dbg(DBG_LEVEL_TRACE, "Sending signal to the service to notify about new session data to inspect");

    while (res >= 0) {
        res = write(comm_socket, ((char *)&cur_session_id) + bytes_written, sizeof(cur_session_id) - bytes_written);
        if (res > 0) {
            bytes_written += res;
            if (bytes_written == sizeof(cur_session_id)) break;
            continue;
        }

        if (res < 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to signal nano service, trying to restart communications");
            disconnect_communication();
            return NGX_ERROR;
        }

        if (!is_fail_open_disabled && is_timeout_reached(&timeout)) {
            write_dbg(DBG_LEVEL_WARNING, "Reached timeout during attempt to signal nano service");
            return NGX_HTTP_REQUEST_TIME_OUT;
        }
    }

    return NGX_OK;
}

///
/// @brief Signals and recieve signal to/from nano service about new session to inspect.
/// @param[in] cur_session_id Session's Id.
/// @param[in] chunk_type Chunk type that the attachment is waiting for a response from nano service.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///         - #NGX_HTTP_REQUEST_TIME_OUT
///         - #NGX_AGAIN
///
static ngx_int_t
ngx_http_cp_wait_for_service(uint32_t cur_session_id, ngx_http_chunk_type_e chunk_type)
{
    static int dbg_count = 0;
    static clock_t clock_start = (clock_t) 0;
    int res = 0;
    int bytes_read = 0;
    uint32_t reply_from_service;
    ngx_int_t retry;
    int is_fail_open_disabled = (inspection_mode != NON_BLOCKING_THREAD);
    ngx_uint_t timeout = chunk_type == HOLD_DATA ? fail_open_hold_timeout : fail_open_timeout;

    res = ngx_http_cp_signal_to_service(cur_session_id);
    if (res != NGX_OK) return res;

    write_dbg(DBG_LEVEL_TRACE, "Successfully signaled to the service! pending to receive ack");
    for (retry = 0; retry < 3; ) {
        // If inspection_mode is different from NON_BLOCKING_THREAD, then the loop will run indefinitely.
        if (!is_fail_open_disabled) {
            retry++;
        }
        struct pollfd s_poll;
        s_poll.fd = comm_socket;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        res = poll(&s_poll, 1, is_fail_open_disabled ? 150 : timeout);

        if (res < 0) {
            // Polling from the nano service has failed.
            dbg_count += 1;
            if (dbg_count > 50 && (((double)(clock() - clock_start)) / CLOCKS_PER_SEC) > 60) {
                write_dbg(DBG_LEVEL_WARNING, "Polling from nano service had fail");
                clock_start = clock();
                dbg_count = 0;
            } else {
                write_dbg(DBG_LEVEL_TRACE, "Polling from nano service had fail");
            }
            return NGX_ERROR;
        }

        if (res == 0) {
            // Polling from nano service has been timed out.
            continue;
        }

        res = read(comm_socket, ((char *)&reply_from_service) + bytes_read, sizeof(reply_from_service) - bytes_read);
        if (res <= 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to read ack from nano service");
            return NGX_ERROR;
        }

        bytes_read += res;
        if (bytes_read != sizeof(reply_from_service)) continue;
        bytes_read = 0;

        if (reply_from_service == cur_session_id) {
            // Read was successful and matches the current session Id.
            write_dbg(
                DBG_LEVEL_TRACE,
                "Received signal from nano service to the current session. Current session id: %d",
                cur_session_id
            );
            return NGX_OK;
        } else if (reply_from_service == CORRUPTED_SESSION_ID) {
            // Recieved corrupted session ID, returning error.
            write_dbg(
                DBG_LEVEL_WARNING,
                "Received signal from nano service regarding a corrupted session. Current session id: %d",
                cur_session_id
            );
            return NGX_ERROR;
        } else {
            // Recieved old session Id, attempting to poll again.
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Received signal from nano service regarding a previous session."
                " Current session id: %d, Signaled session id: %d",
                cur_session_id,
                reply_from_service
            );
            return NGX_AGAIN;
        }
    }

    write_dbg(DBG_LEVEL_WARNING, "Reached timeout during attempt to signal nano service");
    return NGX_HTTP_REQUEST_TIME_OUT;
}

///
/// @brief Send data to the nano service.
/// @param[in] fragments Data to send.
/// @param[in] fragments_sizes Data size.
/// @param[in] num_of_data_elem Number of elements in the data.
/// @param[in] cur_session_id Session's Id.
/// @param[in, out] was_waiting A pointer to an int
/// that symbolize if the function waited to send the data to the nano service.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
ngx_http_cp_send_data_to_service(
    char **fragments,
    const uint16_t *fragments_sizes,
    uint8_t num_of_data_elem,
    uint32_t cur_session_id,
    int *was_waiting,
    ngx_http_chunk_type_e chunk_type
)
{
    ngx_int_t max_retries;
    ngx_int_t res = NGX_OK;
    int err_code = 0;
    write_dbg(DBG_LEVEL_TRACE, "Sending session data chunk for inspection");

    for (max_retries = 5; max_retries > 0; max_retries--) {
        err_code = sendChunkedData(nano_service_ipc, fragments_sizes, (const char **)fragments, num_of_data_elem);
        if (res == NGX_OK && err_code == 0) {
            return NGX_OK;
        }

        write_dbg(DBG_LEVEL_DEBUG, "Failed to send data for inspection - %d attempts remained", max_retries - 1);

        if (was_waiting) {
            *was_waiting = 1;
        }

        res = ngx_http_cp_wait_for_service(cur_session_id, chunk_type);
        if (res != NGX_OK && res != NGX_AGAIN) return res;
    }

    switch(err_code)
    {
        case -1:
            write_dbg(DBG_LEVEL_WARNING, "Failed to send data for inspection - Corrupted shared memory");
            break;
        case -2:
            write_dbg(DBG_LEVEL_WARNING, "Failed to send data for inspection - Requested write size exceeds the write limit");
            break;
        case -3:
            write_dbg(DBG_LEVEL_WARNING, "Failed to send data for inspection - Cannot write to a full queue");
            break;
        case -4:
            write_dbg(DBG_LEVEL_WARNING, "Failed to send data for inspection - Attempted write to a location outside the queue");
            break;
        default:
            write_dbg(DBG_LEVEL_WARNING, "Failed to send data for inspection - Unknown error code %d", err_code);
            break;
    }
    return NGX_ERROR;
}

///
/// @brief Receieves data from service.
/// @returns ngx_http_cp_reply_from_service_t
///         - #A valid ngx_http_cp_reply_from_service_t pointer if valid.
///         - #NULL if failed.
///
static ngx_http_cp_reply_from_service_t *
ngx_http_cp_receive_data_from_service()
{
    ngx_int_t res, retry;
    const char *reply_data;
    uint16_t reply_size;

    write_dbg(DBG_LEVEL_TRACE, "Receiving verdict data from nano service");

    for (retry = 0; retry < 5; retry++) {
        if (!isDataAvailable(nano_service_ipc)) {
            usleep(1);
            continue;
        }
        res = receiveData(nano_service_ipc, &reply_size, &reply_data);
        if (res < 0 || reply_data == NULL) {
            write_dbg(
                DBG_LEVEL_TRACE,
                "Failed to receive verdict data - trying again (retry = %d) in 1 u-seconds",
                retry
            );

            usleep(1);
            continue;
        }

        return (ngx_http_cp_reply_from_service_t *)reply_data;
    }
    return NULL;
}

///
/// @brief Free data from nano service.
///
static void
free_data_from_service()
{
    popData(nano_service_ipc);
}

///
/// @brief Create a custom web response by the provided data
/// @details If web_response_type is set to REDIRECT_WEB_RESPONSE, it will set a redirect response.
/// @param[in] web_response_data Web response data.
///
static void
handle_custom_web_response(ngx_http_cp_web_response_data_t *web_response_data)
{
    ngx_str_t title;
    ngx_str_t body;
    ngx_str_t uuid;
    ngx_str_t redirect_location;

    uuid.len = web_response_data->uuid_size;

    if (web_response_data->web_repsonse_type == REDIRECT_WEB_RESPONSE) {
        // Settings a redirected web response.
        write_dbg(DBG_LEVEL_TRACE, "Preparing to set redirect web response");
        redirect_location.len = web_response_data->response_data.redirect_data.redirect_location_size;
        if (redirect_location.len > 0) {
            redirect_location.data = (u_char *)web_response_data->response_data.redirect_data.redirect_location;
        }
        uuid.data = (u_char *)web_response_data->response_data.redirect_data.redirect_location + redirect_location.len;
        set_redirect_response(&redirect_location, &uuid, web_response_data->response_data.redirect_data.add_event_id);
        return;
    }

    write_dbg(DBG_LEVEL_TRACE, "Preparing to set custom web response page");

    // Setting custom web response title's and body's length.
    title.len = web_response_data->response_data.custom_response_data.title_size;
    body.len = web_response_data->response_data.custom_response_data.body_size;

    if (title.len > 0 && body.len > 0) {
        // Setting custom web response title's and body's data.
        title.data = (u_char *)web_response_data->response_data.custom_response_data.data;
        body.data = (u_char *)web_response_data->response_data.custom_response_data.data + title.len;
        uuid.data = (u_char *)web_response_data->response_data.custom_response_data.data + title.len + body.len;
    }
    set_custom_response(&title, &body, &uuid, web_response_data->response_data.custom_response_data.response_code);
}

///
/// @brief Allocate a modifications list buffer.
/// @param[in, out] target Pointer to the allocated buffer.
/// @param[in] data_size Desired allocated size.
/// @param[in] data Session's Id.
/// @param[in, out] pool NGINX pool.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
create_modification_buffer(char **target, uint16_t data_size, char *data, ngx_pool_t *pool)
{
    *target = (char *)ngx_pcalloc(pool, data_size + 1);
    if (*target == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate modification buffer of size: %d", data_size);
        return NGX_ERROR;
    }

    snprintf(*target, data_size + 1, "%s", data);
    write_dbg(DBG_LEVEL_DEBUG, "Successfully created modification buffer: %s", *target);

    return NGX_OK;
}

///
/// @brief Create a modifications node.
/// @param[in] modification Modification data.
/// @param[in] request NGINX request.
/// @returns modification_node
///         - #ngx_http_cp_modification_list pointer on success.
///         - #NULL if the creation failed.
///
static ngx_http_cp_modification_list *
create_modification_node(ngx_http_cp_inject_data_t *modification, ngx_http_request_t *request)
{
    ngx_int_t res;
    ngx_http_cp_modification_list *modification_node = (ngx_http_cp_modification_list *)ngx_pcalloc(
        request->pool,
        sizeof(ngx_http_cp_modification_list)
    );
    if (modification_node == NULL) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to allocate modification node of size: %d",
            sizeof(ngx_http_cp_modification_list)
        );
        return NULL;
    }

    res = create_modification_buffer(
        &modification_node->modification_buffer,
        modification->injection_size,
        modification->data,
        request->pool
    );

    if (res != NGX_OK) {
        ngx_pfree(request->pool, modification_node);
        return NULL;
    }

    modification_node->next = NULL;
    modification_node->modification.is_header = modification->is_header;
    modification_node->modification.mod_type = modification->mod_type;
    modification_node->modification.injection_pos = modification->injection_pos;
    modification_node->modification.injection_size = modification->injection_size;
    modification_node->modification.orig_buff_index = modification->orig_buff_index;

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Successfully created modification node. "
        "Is header: %d, \
        Injection position: %d, \
        Injection size: %d, \
        Original buffer index: %d, \
        Data: %s, \
        Should change data: %d",
       modification_node->modification.is_header,
       modification_node->modification.injection_pos,
       modification_node->modification.injection_size,
       modification_node->modification.orig_buff_index,
       modification_node->modification_buffer,
       modification_node->modification.mod_type
   );

    return modification_node;
}

ngx_int_t
ngx_http_cp_is_reconf_needed()
{
    ngx_http_cp_reply_from_service_t *reply_p;
    ngx_int_t res;
    const char *reply_data;
    uint16_t reply_size;

    if (!nano_service_ipc) {
        write_dbg(DBG_LEVEL_DEBUG, "Communication with nano service is not ready yet");
        return NGX_ERROR;
    }

    res = receiveData(nano_service_ipc, &reply_size, &reply_data);
    if (res < 0 || reply_data == NULL) {
        write_dbg(DBG_LEVEL_DEBUG, "Reconf verdict was not found");
        return NGX_ERROR;
    }

    reply_p = (ngx_http_cp_reply_from_service_t *)reply_data;
    if (reply_p->verdict == TRAFFIC_VERDICT_RECONF) {
        write_dbg(DBG_LEVEL_DEBUG, "Verdict reconf was received from the nano service. Performing reconf on the nginx worker attachment");
        reset_attachment_config();
        free_data_from_service();
        return NGX_OK;
    }
    return NGX_ERROR;
}

ngx_int_t
ngx_http_cp_reply_receiver(
    ngx_int_t *expected_replies,
    ngx_http_cp_verdict_e *verdict,
    uint32_t cur_session_id,
    ngx_http_request_t *request,
    ngx_http_cp_modification_list **modification_list,
    ngx_http_chunk_type_e chunk_type
)
{
    ngx_http_cp_reply_from_service_t *reply_p;
    ngx_http_cp_modification_list *new_modification = NULL;
    ngx_http_cp_modification_list *current_modification = NULL;
    ngx_http_cp_inject_data_t *current_inject_data = NULL;
    ngx_int_t res;
    uint8_t modification_count;
    unsigned int modification_index;

    write_dbg(DBG_LEVEL_TRACE, "Receiving verdict replies for %d chunks of inspected data", *expected_replies);

    if (*expected_replies == 0) {
        *verdict = TRAFFIC_VERDICT_INSPECT;
        return NGX_OK;
    }

    do {
        res = ngx_http_cp_wait_for_service(cur_session_id, chunk_type);
    } while (res == NGX_AGAIN);

    if (res != NGX_OK) return NGX_ERROR;

    while (*expected_replies) {
        // For each expected replies, receive the reply from the nano service.
        reply_p = ngx_http_cp_receive_data_from_service();
        if (reply_p == NULL) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to get reply from the nano service");
            return NGX_ERROR;
        }

        if (reply_p->verdict != TRAFFIC_VERDICT_RECONF) {
            // Handling reconfiguration verdict.
            if (reply_p->session_id != cur_session_id) {
                write_dbg(DBG_LEVEL_DEBUG, "Ignoring verdict to an already handled request %d", reply_p->session_id);
                free_data_from_service();
                continue;
            }

            (*expected_replies)--;
        }

        *verdict = reply_p->verdict;

        write_dbg(DBG_LEVEL_TRACE, "Verdict %d received", *verdict);

        switch(*verdict) {
            case TRAFFIC_VERDICT_INJECT: {
                // Verdict inject received from the nano service.
                write_dbg(DBG_LEVEL_TRACE, "Verdict inject received from the nano service");
                updateMetricField(INJECT_VERDICTS_COUNT, 1);
                current_inject_data = reply_p->modify_data->inject_data;
                modification_count = reply_p->modification_count;
                for (modification_index = 0; modification_index < modification_count; modification_index++) {
                    // Go over the modifications and create nodes.
                    new_modification = create_modification_node(current_inject_data, request);
                    if (new_modification == NULL) {
                        write_dbg(DBG_LEVEL_WARNING, "Failed to create modification node");
                        while (*modification_list) {
                            current_modification = *modification_list;
                            *modification_list = (*modification_list)->next;
                            ngx_pfree(request->pool, current_modification->modification_buffer);
                            ngx_pfree(request->pool, current_modification);
                        }
                        return NGX_ERROR;
                    }
                    if (*modification_list == NULL) {
                        *modification_list = new_modification;
                        current_modification = *modification_list;
                    } else {
                        current_modification->next = new_modification;
                        current_modification = current_modification->next;
                    }
                    // Saving injected data.
                    current_inject_data = (ngx_http_cp_inject_data_t *)(
                            (char *)current_inject_data +
                            sizeof(ngx_http_cp_inject_data_t) +
                            current_inject_data->injection_size
                    );
                }
                *verdict = TRAFFIC_VERDICT_INSPECT;
                break;
            }

            case TRAFFIC_VERDICT_DROP: {
                // After a drop verdict no more replies will be sent, so we can leave the loop
                write_dbg(DBG_LEVEL_TRACE, "Verdict drop received from the nano service");

                updateMetricField(DROP_VERDICTS_COUNT, 1);
                handle_custom_web_response(reply_p->modify_data->web_response_data);

                *expected_replies = 0;
                free_data_from_service();
                while (*modification_list) {
                    current_modification = *modification_list;
                    *modification_list = (*modification_list)->next;
                    ngx_pfree(request->pool, current_modification->modification.data);
                    ngx_pfree(request->pool, current_modification);
                }
                return NGX_HTTP_FORBIDDEN;
            }

            case TRAFFIC_VERDICT_ACCEPT: {
                // After an accept verdict no more replies will be sent, so we can leave the loop
                write_dbg(DBG_LEVEL_TRACE, "Verdict accept received from the nano service");
                updateMetricField(ACCEPT_VERDICTS_COUNT, 1);
                *expected_replies = 0;
                free_data_from_service();
                return NGX_OK;
            }

            case TRAFFIC_VERDICT_IRRELEVANT: {
                // After an irrelevant verdict, ignore the verdict and continue to the next response.
                write_dbg(DBG_LEVEL_TRACE, "Verdict irrelevant received from the nano service");
                updateMetricField(IRRELEVANT_VERDICTS_COUNT, 1);
                break;
            }

            case TRAFFIC_VERDICT_RECONF: {
                // After a reconfiguration verdict, reset attachment config.
                write_dbg(DBG_LEVEL_TRACE, "Verdict reconf received from the nano service");
                updateMetricField(RECONF_VERDICTS_COUNT, 1);
                reset_attachment_config();
                break;
            }

            case TRAFFIC_VERDICT_INSPECT: {
                // After an irrelevant verdict, ignore the verdict and continue to the next response.
                write_dbg(DBG_LEVEL_TRACE, "Verdict inspect received from the nano service");
                updateMetricField(INSPECT_VERDICTS_COUNT, 1);
                break;
            }

            case TRAFFIC_VERDICT_WAIT: {
                // After a wait verdict, query the nano agent again to get an updated verdict.
                write_dbg(DBG_LEVEL_DEBUG, "Verdict wait received from the nano service");
                updateMetricField(HOLD_VERDICTS_COUNT, 1);
                break;
            }
        }

        free_data_from_service();
    }

    write_dbg(DBG_LEVEL_DEBUG, "No verdict received from the nano service");
    return NGX_OK;
}

///
/// @brief Set meta data fragment element data and size.
/// @param[in, out] meta_data_elems Fragments data array.
/// @param[in, out] meta_data_sizes Fragments data sizes array.
/// @param[in] data Data to set into the meta_data_elems array.
/// @param[in] size Size to be set into the meta_data_sizes array.
/// @param[in] idx Index of the arrays to set the data and size into.
///
static void
set_fragment_elem(char **meta_data_elems, uint16_t *meta_data_sizes, void *data, uint16_t size, uint idx)
{
    meta_data_elems[idx] = data;
    meta_data_sizes[idx] = size;
}

///
/// @brief Set meta data fragments identifiers.
/// @details The data identifiers will be set on the 0 and 1 slots of the array.
/// @param[in, out] meta_data_elems Fragments data array.
/// @param[in, out] meta_data_sizes Fragments data sizes array.
/// @param[in] data_type Data type identifier to be set.
/// @param[in] cur_request_id Request's Id.
///
static void
set_fragments_identifiers(
    char **meta_data_elems,
    uint16_t *meta_data_sizes,
    uint16_t *data_type,
    uint32_t *cur_request_id)
{
    set_fragment_elem(meta_data_elems, meta_data_sizes, data_type, sizeof(uint16_t), 0);
    set_fragment_elem(meta_data_elems, meta_data_sizes, cur_request_id, sizeof(uint32_t), 1);
}

///
/// @brief Convert sock address to a string.
/// @param[in, out] sockaddr Socker to convert.
/// @param[in, out] ip_addr Output location of the conversion.
///
static void
convert_sock_addr_to_string(const struct sockaddr *sa, char *ip_addr)
{
    void *ip = NULL;
    if (sa->sa_family == AF_INET) {
        ip = (void *) &(((struct sockaddr_in*)sa)->sin_addr);
    } else {
        ip = (void *)&(((struct sockaddr_in6*)sa)->sin6_addr);
    }

    inet_ntop(AF_INET, ip, ip_addr, INET6_ADDRSTRLEN);
}

ngx_int_t
ngx_http_cp_meta_data_sender(ngx_http_request_t *request, uint32_t cur_request_id, ngx_uint_t *num_messages_sent)
{
    char client_ip[INET6_ADDRSTRLEN];
    char listening_ip[INET6_ADDRSTRLEN];
    uint16_t client_ip_len;
    uint16_t listening_ip_len;
    uint16_t client_port;
    uint16_t chunck_type;
    uint16_t listening_port;
    ngx_int_t res;
    ngx_str_t ngx_parsed_host_str = ngx_string("host");
    ngx_str_t maybe_host = { 0, (u_char *)"" };
    ngx_str_t ngx_parsed_host = { 0, (u_char *)"" };
    ngx_str_t parsed_uri = { 0, (u_char *)"" };
    ngx_http_variable_value_t *ngx_var;
    char *fragments[META_DATA_COUNT + 2];
    uint16_t fragments_sizes[META_DATA_COUNT + 2];
    static int failure_count = 0;

    write_dbg(DBG_LEVEL_TRACE, "Sending request start meta data for inspection");

    convert_sock_addr_to_string(((struct sockaddr *)request->connection->sockaddr), client_ip);
    if(!is_inspection_required_for_source(client_ip)) return inspection_irrelevant;

    // Sets the fragments
    chunck_type = REQUEST_START;
    set_fragments_identifiers(fragments, fragments_sizes, &chunck_type, &cur_request_id);

    // Add protocol length to fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &request->http_protocol.len,
        sizeof(uint16_t),
        HTTP_PROTOCOL_SIZE + 2
    );
    // Add protocol data to fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        request->http_protocol.data,
        request->http_protocol.len,
        HTTP_PROTOCOL_DATA + 2
    );

    // Add method data length to fragments.
    set_fragment_elem(fragments, fragments_sizes, &request->method_name.len, sizeof(uint16_t), HTTP_METHOD_SIZE + 2);
    // Add method data to fragments
    set_fragment_elem(
        fragments,
        fragments_sizes,
        request->method_name.data,
        request->method_name.len,
        HTTP_METHOD_DATA + 2
    );

    if (request->headers_in.host != NULL) {
        maybe_host.len = request->headers_in.host->value.len;
        maybe_host.data = request->headers_in.host->value.data;
    }

    ngx_var = ngx_http_get_variable(request, &ngx_parsed_host_str, ngx_hash_key(ngx_parsed_host_str.data, ngx_parsed_host_str.len));
    if (ngx_var != NULL && !ngx_var->not_found && ngx_var->len != 0) {
        ngx_parsed_host.len = ngx_var->len;
        ngx_parsed_host.data = ngx_var->data;
    } else {
        ngx_parsed_host.len = maybe_host.len;
        ngx_parsed_host.data = maybe_host.data;
    }

    if (request->uri.len != 0) {
        parsed_uri.data = request->uri.data;
        parsed_uri.len = request->uri.len;
    } else {
        parsed_uri.data = request->unparsed_uri.data;
        parsed_uri.len = request->unparsed_uri.len;
    }

    // Add host data length to the fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &maybe_host.len,
        sizeof(uint16_t),
        HOST_NAME_SIZE + 2
    );
    // Add host data to the fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        maybe_host.data,
        maybe_host.len,
        HOST_NAME_DATA + 2
    );

    convert_sock_addr_to_string(((struct sockaddr *)request->connection->local_sockaddr), listening_ip);
    listening_ip_len = strlen(listening_ip);
    // Add listening IP metadata.
    set_fragment_elem(fragments, fragments_sizes, &listening_ip_len, sizeof(uint16_t), LISTENING_ADDR_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, listening_ip, listening_ip_len, LISTENING_ADDR_DATA + 2);

    // Add listening port data.
    listening_port = htons(((struct sockaddr_in *)request->connection->local_sockaddr)->sin_port);
    set_fragment_elem(fragments, fragments_sizes, &listening_port, sizeof(listening_port), LISTENING_PORT + 2);

    // Add URI data.
    set_fragment_elem(fragments, fragments_sizes, &request->unparsed_uri.len, sizeof(uint16_t), URI_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, request->unparsed_uri.data, request->unparsed_uri.len, URI_DATA + 2);

    // Add client IP data length.
    client_ip_len = strlen(client_ip);
    set_fragment_elem(fragments, fragments_sizes, &client_ip_len, sizeof(uint16_t), CLIENT_ADDR_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, client_ip, client_ip_len, CLIENT_ADDR_DATA + 2);

    // Add client IP data.
    client_port = htons(((struct sockaddr_in *)request->connection->sockaddr)->sin_port);
    set_fragment_elem(fragments, fragments_sizes, &client_port, sizeof(client_port), CLIENT_PORT + 2);

    // Add NGX parsed host data.
    set_fragment_elem(fragments, fragments_sizes, &ngx_parsed_host.len, sizeof(uint16_t), PARSED_HOST_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, ngx_parsed_host.data, ngx_parsed_host.len, PARSED_HOST_DATA + 2);

    // Add parsed URI data.
    set_fragment_elem(fragments, fragments_sizes, &parsed_uri.len, sizeof(uint16_t), PARSED_URI_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, parsed_uri.data, parsed_uri.len, PARSED_URI_DATA + 2);

    // Sends all the data to the nano service.
    res = ngx_http_cp_send_data_to_service(fragments, fragments_sizes, META_DATA_COUNT + 2, cur_request_id, NULL, fail_open_timeout);
    if (res != NGX_OK) {
        // Failed to send the metadata to nano service.
        if (res == NGX_ERROR && failure_count++ == 5) {
            disconnect_communication();
            failure_count = 0;
        }

        return res;
    }
    failure_count = 0;

    set_dbg_by_ctx(
        client_ip,
        listening_ip,
        (char *)request->unparsed_uri.data,
        (char *)(maybe_host.data),
        (char *)request->method_name.data,
        listening_port
    );

    *num_messages_sent = 1;
    return NGX_OK;
}

ngx_int_t
ngx_http_cp_end_transaction_sender(
    ngx_http_chunk_type_e end_transaction_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
)
{
    static const ngx_uint_t end_transaction_num_fragments = 2;

    char *fragments[end_transaction_num_fragments];
    uint16_t fragments_sizes[end_transaction_num_fragments];
    ngx_int_t res = NGX_ERROR;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Sending end %s event flag for inspection",
        end_transaction_type == REQUEST_END ? "request" : "response"
    );

    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&end_transaction_type, &cur_request_id);

    res = ngx_http_cp_send_data_to_service(fragments, fragments_sizes, end_transaction_num_fragments, cur_request_id, NULL, fail_open_timeout);
    if (res != NGX_OK) {
        return NGX_ERROR;
    }

    *num_messages_sent = 1;
    return NGX_OK;
}

ngx_int_t
ngx_http_cp_wait_sender(uint32_t cur_request_id, ngx_uint_t *num_messages_sent)
{
    static const ngx_uint_t end_transaction_num_fragments = 2;

    char *fragments[end_transaction_num_fragments];
    uint16_t fragments_sizes[end_transaction_num_fragments];
    ngx_http_chunk_type_e transaction_type = HOLD_DATA;
    ngx_int_t res;

    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&transaction_type, &cur_request_id);

    write_dbg(DBG_LEVEL_TRACE, "Sending wait event flag for inspection");

    res = ngx_http_cp_send_data_to_service(fragments, fragments_sizes, end_transaction_num_fragments, cur_request_id, NULL, fail_open_timeout);
    if (res != NGX_OK) {
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_TRACE, "Successfully sent wait event");
    *num_messages_sent = 1;
    return NGX_OK;
}

ngx_int_t
ngx_http_cp_res_code_sender(uint16_t response_code, uint32_t cur_req_id, ngx_uint_t *num_messages_sent)
{
    static const ngx_uint_t res_code_num_fragments = 3;

    char *fragments[res_code_num_fragments];
    uint16_t fragments_sizes[res_code_num_fragments];
    uint16_t chunck_type;

    write_dbg(DBG_LEVEL_TRACE, "Sending response code (%d) for inspection", response_code);

    chunck_type = RESPONSE_CODE;
    set_fragments_identifiers(fragments, fragments_sizes, &chunck_type, &cur_req_id);
    set_fragment_elem(fragments, fragments_sizes, &response_code, sizeof(uint16_t), 2);

    if (ngx_http_cp_send_data_to_service(fragments, fragments_sizes, res_code_num_fragments, cur_req_id, NULL, fail_open_hold_timeout) != NGX_OK) {
        return NGX_ERROR;
    }

    *num_messages_sent = 1;
    return NGX_OK;
}

ngx_int_t
ngx_http_cp_content_length_sender(uint64_t content_length_n, uint32_t cur_req_id, ngx_uint_t *num_messages_sent)
{
    static const ngx_uint_t content_length_num_fragments = 3;

    char *fragments[content_length_num_fragments];
    uint16_t fragments_sizes[content_length_num_fragments];
    uint16_t chunck_type;
    uint64_t content_length_val = content_length_n;

    write_dbg(DBG_LEVEL_TRACE, "Sending content length (%ld) to the intaker", content_length_n);

    chunck_type = CONTENT_LENGTH;
    set_fragments_identifiers(fragments, fragments_sizes, &chunck_type, &cur_req_id);
    set_fragment_elem(fragments, fragments_sizes, &content_length_val, sizeof(content_length_val), 2);

    if (ngx_http_cp_send_data_to_service(fragments, fragments_sizes, content_length_num_fragments, cur_req_id, NULL, fail_open_timeout) != NGX_OK) {
        return NGX_ERROR;
    }

    *num_messages_sent = 1;
    return NGX_OK;
}

///
/// @brief Create a header bulk.
/// @param[in, out] fragments Fragment data array.
/// @param[in, out] fragments_sizes Fragment data size array.
/// @param[in] header Header to add to the fragment array.
/// @param[in] index Index of the arrays to set the header into.
///
static inline void
add_header_to_bulk(char **fragments, uint16_t *fragments_sizes, ngx_table_elt_t *header, ngx_uint_t index)
{
    ngx_uint_t pos = index * HEADER_DATA_COUNT;
    set_fragment_elem(fragments, fragments_sizes, &header->key.len, sizeof(uint16_t), pos + HEADER_KEY_SIZE + 4);
    set_fragment_elem(fragments, fragments_sizes, header->key.data, header->key.len, pos + HEADER_KEY_DATA + 4);
    set_fragment_elem(fragments, fragments_sizes, &header->value.len, sizeof(uint16_t), pos + HEADER_VAL_SIZE + 4);
    set_fragment_elem(fragments, fragments_sizes, header->value.data, header->value.len, pos + HEADER_VAL_DATA + 4);
}

///
/// @brief Send a headers bulk to the nano service.
/// @param[in, out] data Data array.
/// @param[in, out] data_sizes Data size array.
/// @param[in] num_headers Number of headers to be sent.
/// @param[in] is_last_part Is the header last.
/// @param[in] bulk_part_index Index of the data bulk.
/// @param[in, out] num_of_bulks_sent Number of bulks that's been sent will be written here.
/// @param[in] cur_request_id Request's Id.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
send_header_bulk(
    char **data,
    uint16_t *data_sizes,
    const ngx_uint_t num_headers,
    uint8_t is_last_part,
    uint8_t bulk_part_index,
    ngx_uint_t *num_of_bulks_sent,
    uint32_t cur_request_id
)
{
    ngx_int_t res;
    set_fragment_elem(data, data_sizes, &is_last_part, sizeof(is_last_part), 2);
    set_fragment_elem(data, data_sizes, &bulk_part_index, sizeof(bulk_part_index), 3);

    res = ngx_http_cp_send_data_to_service(data, data_sizes, HEADER_DATA_COUNT * num_headers + 4, cur_request_id, NULL, fail_open_timeout);
    if (res != NGX_OK) {
        write_dbg(DBG_LEVEL_TRACE, "Failed to send bulk of %iu headers", num_headers);
        return NGX_ERROR;
    }

    (*num_of_bulks_sent)++;
    write_dbg(DBG_LEVEL_TRACE, "Successfully sent bulk of %iu headers", num_headers);
    return NGX_OK;
}

///
/// @brief Send an empty headers list to the nano service.
/// @param[in, out] sent_data Data array.
/// @param[in, out] sent_data_sizes Data size array.
/// @param[in, out] num_of_bulks_sent Number of bulks that's been sent will be written here.
/// @param[in] cur_request_id Request's Id.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
send_empty_header_list(
    char **sent_data,
    uint16_t *sent_data_sizes,
    ngx_uint_t *num_of_bulks_sent,
    uint32_t cur_request_id)
{
    static ngx_table_elt_t empty_header = {
        .hash = 1,
        .key = { .len = 0, .data = (u_char *)"" },
        .value = { .len = 0, .data = (u_char *)"" },
        .lowcase_key = NULL
    };

    add_header_to_bulk(sent_data, sent_data_sizes, &empty_header, 0);
    if(send_header_bulk(sent_data, sent_data_sizes, 1, 1, 0, num_of_bulks_sent, cur_request_id) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_cp_header_sender(
    ngx_list_part_t *headers_list,
    ngx_http_chunk_type_e header_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
)
{
    ngx_uint_t header_idx = 0;
    ngx_uint_t idx_in_bulk = 0;
    ngx_uint_t num_of_bulks_sent = 0;
    uint8_t part_count = 0;
    uint8_t bulk_part_idx = 0;
    ngx_int_t send_bulk_result;
    uint8_t is_last_part;
    ngx_list_part_t *headers_iter;
    ngx_table_elt_t *headers_to_inspect;
    ngx_table_elt_t *header;
    const ngx_uint_t max_bulk_size = 10;
    char *fragments[HEADER_DATA_COUNT * max_bulk_size + 4];
    uint16_t fragments_sizes[HEADER_DATA_COUNT * max_bulk_size + 4];

    write_dbg(
        DBG_LEVEL_TRACE,
        "Sending %s headers for inspection",
        header_type == REQUEST_HEADER ? "request" : "response"
    );

    // Sets fragments identifier to the provided body type.
    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&header_type, &cur_request_id);

    for (headers_iter = headers_list;  headers_iter ; headers_iter = headers_iter->next) {
        // Going over the header list.
        for (header_idx = 0 ; header_idx < headers_iter->nelts ; ++header_idx) {
            headers_to_inspect = headers_iter->elts;
            header = headers_to_inspect + header_idx;

            write_dbg(
                DBG_LEVEL_TRACE,
                "Sending current header (key: '%.*s', value: '%.*s') to inspection",
                header->key.len,
                header->key.data,
                header->value.len,
                header->value.data
            );

            is_last_part = (headers_iter->next == NULL && header_idx + 1 == headers_iter->nelts) ? 1 : 0;
            // Create a header bulk to send.
            add_header_to_bulk(fragments, fragments_sizes, header, idx_in_bulk);

            idx_in_bulk++;
            part_count++;
            if (idx_in_bulk < max_bulk_size && !is_last_part) continue;

            // Send the headers to the nano agent.
            send_bulk_result = send_header_bulk(
                fragments,
                fragments_sizes,
                idx_in_bulk,
                is_last_part,
                bulk_part_idx,
                &num_of_bulks_sent,
                cur_request_id
            );
            if (send_bulk_result != NGX_OK) return NGX_ERROR;

            if (is_last_part) break;

            idx_in_bulk = 0;
            bulk_part_idx = part_count;
        }
    }

    if (part_count == 0 && header_type == RESPONSE_HEADER) {
        // Handling an empty response header.
        write_dbg(DBG_LEVEL_TRACE, "Empty list of headers received. Sending last header message to nano service");
        if (send_empty_header_list(fragments, fragments_sizes, &num_of_bulks_sent, cur_request_id) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    *num_messages_sent = num_of_bulks_sent;

    write_dbg(DBG_LEVEL_TRACE, "Exit after inspection of %d headers", part_count);
    return NGX_OK;
}

ngx_int_t
ngx_http_cp_body_sender(
    ngx_chain_t *input,
    ngx_http_chunk_type_e body_type,
    ngx_http_cp_session_data *session_data,
    ngx_int_t *is_last_part,
    ngx_uint_t *num_messages_sent,
    ngx_chain_t **next_elem_to_inspect
)
{
    static const ngx_uint_t num_body_chunk_fragments = 5;

    ngx_chain_t *chain_iter = NULL;
    ngx_buf_t *buf;
    ngx_int_t num_parts_sent;
    ngx_int_t is_empty_chain = 1;
    ngx_int_t res = NGX_ERROR;
    uint8_t is_last_chunk;
    uint8_t part_count;
    char *fragments[num_body_chunk_fragments];
    uint16_t fragments_sizes[num_body_chunk_fragments];
    int was_waiting = 0;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Sending %s body chunk for inspection",
        body_type == REQUEST_BODY ? "request" : "response"
    );

    // Sets fragments identifier to the provided body type.
    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&body_type, &session_data->session_id);

    num_parts_sent = 0;
    part_count = 0;
    for (chain_iter = input; chain_iter; chain_iter = chain_iter->next) {
        // For each NGINX buffer, fragment the buffer and then send the fragments to the nano service.
        buf = chain_iter->buf;
        is_last_chunk = buf->last_buf ? 1 : 0;
        write_dbg(DBG_LEVEL_TRACE, "Sending last_buf: %d, part_count: %d", buf->last_buf ? 1: 0, part_count);

        if (buf->last - buf->pos > 0 || is_last_chunk) {
            // Setting the fragments, including in the case of the last chunk.
            set_fragment_elem(fragments, fragments_sizes, &is_last_chunk, sizeof(is_last_chunk), 2);
            set_fragment_elem(fragments, fragments_sizes, &part_count, sizeof(part_count), 3);
            set_fragment_elem(fragments, fragments_sizes, buf->pos, buf->last - buf->pos, 4);

            if (body_type == REQUEST_BODY) {
                session_data->processed_req_body_size = (buf->last - buf->pos);
            } else if (body_type == RESPONSE_BODY) {
                session_data->processed_res_body_size = (buf->last - buf->pos);
            }
            // Sending the data to the nano service.
            res = ngx_http_cp_send_data_to_service(fragments, fragments_sizes, num_body_chunk_fragments, session_data->session_id,
                &was_waiting, fail_open_timeout);

            if (res != NGX_OK) {
                // Failed to send the fragments to the nano service.
                return NGX_ERROR;
            }

            num_parts_sent++;
            is_empty_chain = 0;
        }

        part_count++;

        if (was_waiting) {
            break;
        }
    }

    *is_last_part = is_last_chunk;
    *num_messages_sent = num_parts_sent;

    *next_elem_to_inspect = chain_iter;

    return (!is_empty_chain && num_parts_sent == 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
ngx_http_cp_metric_data_sender()
{
    char *fragments;
    uint16_t fragments_sizes;
    uint16_t fragment_type;
    ngx_int_t res;

    write_dbg(DBG_LEVEL_DEBUG, "Sending metric data to service");

    fragment_type = METRIC_DATA_FROM_PLUGIN;
    ngx_http_cp_metric_data_t data_to_send;
    data_to_send.data_type = fragment_type;
    memcpy(data_to_send.data, metric_data, METRIC_TYPES_COUNT * sizeof(data_to_send.data[0]));
    fragments = (char *)&data_to_send;
    fragments_sizes = sizeof(ngx_http_cp_metric_data_t);

    res = ngx_http_cp_send_data_to_service(&fragments, &fragments_sizes, 1, 0, NULL, fail_open_timeout);
    reset_metric_data();
    return res;
}
