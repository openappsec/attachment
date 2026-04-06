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

#include "shmem_ipc_2.h"
#include "nano_attachment_common.h"
#include "ngx_cp_custom_response.h"
#include "ngx_cp_hooks.h"

#define INSPECTION_IRRELEVANT NGX_DECLINED

extern SharedMemoryIPC *nano_service_ipc; ///< Nano service's IPC.
extern SharedMemoryIPC *nano_service_secondary_sync_ipc; ///< Secondary sync IPC.
extern int comm_socket; ///< Communication socket.
extern int secondary_comm_socket; ///< Secondary communication socket.
extern LoggingData logging_data; ///< Global logging data for shmem_ipc_2 (process-based)

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
/// @param[in] processed_body_size Processed body size to determinate number of retries from nano service.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_reply_receiver(
    ngx_int_t *expected_replies,
    ServiceVerdict *verdict,
    ngx_int_t *inspect_all_response_headers,
    uint32_t cur_session_id,
    ngx_http_request_t *request,
    ngx_http_cp_modification_list **modification_list,
    AttachmentDataType chunk_type,
    uint64_t processed_body_size,
    ngx_uint_t filter_mode
);

///
/// @brief Sends meta data to the nano service.
/// @param[in, out] request NGINX request.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] waf_tag WAF tag to be sent.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_meta_data_sender(
    ngx_http_request_t *request,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent,
    ngx_str_t *waf_tag
);

///
/// @brief Sends end of a transaction to the nano service.
/// @param[in] end_transaction_type Sets the transaction type, can be of the values:
///         - #REQUEST_END
///         - #RESPONSE_END
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_end_transaction_sender(
    AttachmentDataType end_transaction_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent,
    ngx_uint_t filter_mode
);

///
/// @brief Sends response code to the nano service.
/// @param[in] response_code response code to send.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_res_code_sender(
    uint16_t response_code,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent,
    ngx_uint_t filter_mode
);

///
/// @brief Sends content length to the nano service.
/// @param[in] content_length_n content length to send.
/// @param[in] cur_req_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_content_length_sender(
    uint64_t content_length_n,
    uint32_t cur_req_id,
    ngx_uint_t *num_messages_sent,
    ngx_uint_t filter_mode
);

///
/// @brief  Sends request/response headers to the nano service.
/// @param[in] headers Headers to be sent.
/// @param[in, out] header_type Sets the header type, can be of the values:
///         - #REQUEST_HEADER
///         - #RESPONSE_HEADER
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_header_sender(
    ngx_list_part_t *headers,
    AttachmentDataType header_type,
    uint32_t cur_request_id,
    ngx_uint_t *num_messages_sent,
    ngx_uint_t filter_mode
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
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_body_sender(
    ngx_chain_t *input,
    AttachmentDataType body_type,
    ngx_http_cp_session_data *session_data,
    ngx_int_t *part_number,
    ngx_int_t *is_last_part,
    ngx_uint_t *num_messages_sent,
    ngx_chain_t **next_elem_to_inspect,
    ngx_uint_t filter_mode
);

///
/// @brief Sends REQUEST_DELAYED_VERDICT request to the nano service.
/// @details REQUEST_DELAYED_VERDICT request is a request that asks the nano service to provide with an updated verdict.
/// @param[in] cur_request_id Request session's Id.
/// @param[in, out] num_messages_sent Number of messages sent will be saved onto this parameter.
/// @param[in] filter_mode Whether to use async mode (ASYNC_FILTER) or sync mode (SYNC_FILTER).
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_wait_sender(uint32_t cur_request_id, ngx_uint_t *num_messages_sent, ngx_uint_t filter_mode);

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

///
/// @brief Create a modifications node.
/// @param[in] modification Modification data.
/// @param[in] request NGINX request.
/// @returns modification_node
///         - #ngx_http_cp_modification_list pointer on success.
///         - #NULL if the creation failed.
///
ngx_http_cp_modification_list *
create_modification_node(HttpInjectData *modification, ngx_http_request_t *request);

///
/// @brief Convert socket address to string
/// @param[in] sa Socket address
/// @param[out] ip_addr String buffer to write IP address to
///
void
convert_sock_addr_to_string(const struct sockaddr *sa, char *ip_addr);

///
/// @brief Set fragments identifiers for data transmission
/// @param[in,out] meta_data_elems Fragments data array
/// @param[in,out] meta_data_sizes Fragments data sizes array
/// @param[in] data_type Data type identifier to be set
/// @param[in] cur_request_id Request's Id
///
void
set_fragments_identifiers(
    char **meta_data_elems,
    uint16_t *meta_data_sizes,
    uint16_t *data_type,
    uint32_t *cur_request_id);

void set_fragment_elem(char **meta_data_elems, uint16_t *meta_data_sizes, void *data, uint16_t size, uint idx);
void add_header_to_bulk(char **fragments, uint16_t *fragments_sizes, ngx_table_elt_t *header, ngx_uint_t index);

ngx_int_t handle_custom_response(HttpCustomResponseData *custom_response_data);
void handle_custom_web_response(HttpWebResponseData *web_response_data);

#endif // __NGX_CP_IO_H__
