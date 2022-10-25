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
#ifndef __NGX_CP_IO_H__
#define __NGX_CP_IO_H__

#include <ngx_config.h>
#include <ngx_http.h>

#include <unistd.h>

#include "shmem_ipc.h"
#include "nginx_attachment_common.h"
#include "ngx_cp_custom_response.h"
#include "ngx_cp_hooks.h"

#define INSPECTION_IRRELEVANT NGX_DECLINED

extern SharedMemoryIPC *nano_service_ipc; ///< Nano service's IPC.
extern int comm_socket; ///< Communication socket.

///
/// @brief Receives nano service's response.
/// @details The function awaits for the expected_replies of replies from the nano service.
/// The recieved verdict is saved onto the verdict argument and depends on the reply
/// one of the ngx_int_t returns.
/// @param[in, out] expected_replies Amount of expected replies.
/// @param[in, out] verdict Value to save the verdict onto:
///         - #TRAFFIC_VERDICT_INSPECT
///         - #TRAFFIC_VERDICT_INJECT
///         - #TRAFFIC_VERDICT_DROP
///         - #TRAFFIC_VERDICT_ACCEPT
///         - #TRAFFIC_VERDICT_IRRELEVANT
///         - #TRAFFIC_VERDICT_RECONF
/// @param[in] cur_session_id Session's Id.
/// @param[in, out] request NGINX request.
/// @param[in] modification_list
/// @param[in] chunk_type Chunk type that the attachment is waiting for a response from nano service.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_reply_receiver(
    ngx_int_t *expected_replies,
    ngx_http_cp_verdict_e *verdict,
    uint32_t cur_session_id,
    ngx_http_request_t *request,
    ngx_http_cp_modification_list **modification_list,
    ngx_http_chunk_type_e chunk_type
);

///
/// @brief Sends meta data to the nano service.
/// @param[in, out] request NGINX request.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_meta_data_sender(
    ngx_http_request_t *request,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
);

///
/// @brief Sends end of a transaction to the nano service.
/// @param[in] end_transaction_type Sets the transaction type, can be of the values:
///         - #REQUEST_END
///         - #RESPONSE_END
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_end_transaction_sender(
    ngx_http_chunk_type_e end_transaction_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
);

///
/// @brief Sends response code to the nano service.
/// @param[in] response_code response code to send.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_res_code_sender(
    uint16_t response_code,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
);

///
/// @brief Sends content length to the nano service.
/// @param[in] content_length_n content length to send.
/// @param[in] cur_req_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_content_length_sender(
    uint64_t content_length_n,
    uint32_t cur_req_id,
    ngx_uint_t *num_messages_sent
);

///
/// @brief  Sends request/response headers to the nano service.
/// @param[in] headers Headers to be sent.
/// @param[in, out] header_type Sets the header type, can be of the values:
///         - #REQUEST_HEADER
///         - #RESPONSE_HEADER
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_header_sender(
    ngx_list_part_t *headers,
    ngx_http_chunk_type_e header_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent
);

///
/// @brief Sends request/response bodies to the nano service.
/// @param[in] input NGX chain.
/// @param[in] body_type Sets the body type, can be of the values:
///         - #REQUEST_BODY
///         - #RESPONSE_BODY
/// @param[in, out] session_data Session's data.
/// @param[in, out] is_last_part If the last part will be saved onto this parameter.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in, out] next_elem_to_inspect Next NGX chain to inspect.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_body_sender(
    ngx_chain_t *input,
    ngx_http_chunk_type_e body_type,
    ngx_http_cp_session_data *session_data,
    ngx_int_t *is_last_part,
    ngx_uint_t *num_messages_sent,
    ngx_chain_t **next_elem_to_inspect
);

///
/// @brief Sends HOLD_DATA request to the nano service.
/// @details HOLD_DATA request is a request that asks the nano service to provide with an updated verdict.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_wait_sender(uint32_t cur_request_id, ngx_uint_t *num_messages_sent);

///
/// @brief Checks if reconf is needed and reconfigs if necessary.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_is_reconf_needed();

///
/// @brief Sends metric data to the server.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_metric_data_sender();

///
/// @brief Updates session related metric fields.
/// @param[in] session_start_time Session's start time.
/// @param[in] req_proccesing_time Session's request processing time.
/// @param[in] res_proccesing_time Session's response processing time.
///
void ngx_http_cp_report_time_metrics(
    clock_t session_start_time,
    double req_proccesing_time,
    double res_proccesing_time
);

#endif // __NGX_CP_IO_H__
