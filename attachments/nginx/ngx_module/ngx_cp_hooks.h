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

/// @file ngx_cp_hooks.h
#ifndef __NGX_CP_HOOKS_H__
#define __NGX_CP_HOOKS_H__

#include <time.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <unistd.h>

#include "ngx_cp_http_parser.h"
#include "nano_attachment_common.h"
#include "ngx_cp_hook_threads.h"

#define SYNC_FILTER 0
#define ASYNC_FILTER 1

static const int registration_failure_weight = 2; ///< Registration failure weight.
static const int inspection_failure_weight = 1; ///< Inspection failure weight.
static const ngx_int_t METRIC_TIMEOUT_VAL = METRIC_PERIODIC_TIMEOUT;

/// @struct ngx_http_cp_session_data
/// @brief Holds all the session's information needed to communicate with the nano service.
/// @details Such as to save verdict and session ID between the request and the response
typedef struct ngx_http_cp_session_data {
    ngx_int_t              was_request_fully_inspected; ///< Holds if the request fully inspected.
    ServiceVerdict         verdict; ///< Holds the session's verdict from the Nano Service.
    uint32_t               session_id; ///< Current session's Id.
    ngx_int_t              remaining_messages_to_reply; ///< Remaining messages left for the agent to respond to.
    ngx_http_response_data response_data; ///< Holds session's response data.
    struct timespec        session_start_time; ///< Holds session's start time.
    double                 req_proccesing_time; ///< Holds session's request processing time.
    double                 res_proccesing_time; ///< Holds session's response processing time.
    uint64_t               processed_req_body_size; ///< Holds session's request body's size.
    uint64_t               processed_res_body_size; ///< Holds session's response body's size'.
    ngx_int_t              is_res_body_inspected; ///< Holds if the response body was inspected
    ngx_int_t              async_processing_needed; ///< Holds if async processing is needed in filters
    ngx_int_t              body_processed; ///< Holds if request body processing is complete
    ngx_int_t              initial_async_mode; ///< Initial async mode for this request (0=sync, 1=async, -1=unset)
} ngx_http_cp_session_data;

///
/// @brief Sends response body to the nano service.
/// @details Initiates all the needed context data and session data and calls the relevant threads
/// to communicate the response bodies to the nano service and fetch the response back to the NGINX.
/// @param[in, out] request NGINX request.
/// @param[in, out] input NGINX body chain.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_res_body_filter(ngx_http_request_t *request, ngx_chain_t *input);

///
/// @brief Sends request body to the nano service.
/// @details Initiates all the needed context data and session data and calls the relevant threads
/// to communicate the request bodies to the nano service and fetch the response back to the NGINX.
/// @param[in, out] request NGINX request.
/// @param[in, out] input_body_chain NGINX body chain.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_req_body_filter(ngx_http_request_t *request, ngx_chain_t *input_body_chain);

///
/// @brief Sends response headers to the nano service.
/// @details Initiates all the needed context data and session data and calls the relevant threads
/// to communicate the response headers to the nano service and fetch the response back to the NGINX.
/// @param[in, out] request NGINX request.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_res_header_filter(ngx_http_request_t *request);

///
/// @brief Sends request headers to the nano service.
/// @details Initiates all the needed context data and session data and calls the relevant threads
/// to communicate the request headers to the nano service and fetch the response back to the NGINX.
/// @param[in, out] request NGINX request.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t ngx_http_cp_req_header_handler(ngx_http_request_t *request);

///
/// @brief Sends a request to the nano service to update the verdict.
/// @note Should be called after the nano service provided the verdict TRAFFIC_VERDICT_DELAYED to get the updated verdict.
/// @param[in, out] request Event thread context to be updated.
/// @returns ngx_int_t
///         - #1 if request was properly communicated with the nano service and provided an updated response.
///         - #0 otherwise.
///
ngx_int_t ngx_http_cp_hold_verdict(struct ngx_http_cp_event_thread_ctx_t *ctx);

///
/// @brief Checks if transaction was timed out.
/// @param[in, out] ctx
/// @note ctx needs to be properly intialized.
/// @returns ngx_int_t
///         - #0 - Timed out did not occure.
///         - #1 - Timed out occured.
///
ngx_int_t was_transaction_timedout(ngx_http_cp_session_data *ctx);


///
/// @brief Enforces the sessions rate.
/// @returns ServiceVerdict
///         - #TRAFFIC_VERDICT_INSPECT
///         - #TRAFFIC_VERDICT_ACCEPT
///         - #TRAFFIC_VERDICT_DROP
///
ServiceVerdict enforce_sessions_rate();


///
/// @Updates request and response sizes metrics.
/// @param[in, out] request NGINX request.
/// @returns ngx_int_t
///         - #NGX_DECLINED
///
ngx_int_t ngx_http_cp_request_and_response_size_handler(ngx_http_request_t *request);

// Session management functions
ngx_http_cp_session_data *init_cp_session_data(ngx_http_request_t *request);
ngx_http_cp_session_data *recover_cp_session_data(ngx_http_request_t *request);

// Utility functions
void calcProcessingTime(ngx_http_cp_session_data *session_data_p, struct timespec *hook_time_begin, int is_req);
ngx_int_t ngx_http_cp_finalize_request_headers_hook(
    ngx_http_request_t *request,
    ngx_http_cp_session_data *session_data_p,
    ngx_http_cp_modification_list *modifications,
    ngx_int_t final_res);

// Sync and async handlers
ngx_int_t ngx_http_cp_req_header_handler_sync(ngx_http_request_t *request);
ngx_int_t ngx_http_cp_req_body_filter_sync(ngx_http_request_t *request, ngx_chain_t *request_body_chain);
ngx_int_t ngx_http_cp_res_body_filter_sync(ngx_http_request_t *request, ngx_chain_t *body_chain);
ngx_int_t ngx_http_cp_res_body_filter_core(ngx_http_request_t *request, ngx_chain_t *body_chain, int filter_mode);
ngx_int_t ngx_http_cp_res_header_filter_sync(ngx_http_request_t *request);
ngx_int_t ngx_http_cp_res_header_filter_core(ngx_http_request_t *request, int filter_mode);
ngx_int_t remove_server_header(ngx_http_request_t *r);
void fini_cp_session_data(ngx_http_cp_session_data *session_data);
ngx_int_t init_cp_session_original_body(ngx_http_cp_session_data *session_data, ngx_pool_t *pool);
ngx_int_t copy_compressed_to_original_buffers(ngx_chain_t *original_chain, ngx_chain_t *compressed_chain, ngx_pool_t *request_pool);

#ifdef NGINX_ASYNC_SUPPORTED
ngx_int_t ngx_http_cp_req_header_handler_async(ngx_http_request_t *request);
ngx_int_t ngx_http_cp_req_body_filter_async(ngx_http_request_t *request, ngx_chain_t *request_body_chain);
#endif

#endif // __NGX_CP_HOOKS_H__
