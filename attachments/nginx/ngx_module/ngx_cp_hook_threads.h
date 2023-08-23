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

/// @file ngx_cp_hook_threads.h
#ifndef __NGX_CP_HOOK_THREADS_H__
#define __NGX_CP_HOOK_THREADS_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <unistd.h>

typedef struct ngx_http_cp_session_data ngx_http_cp_session_data; ///< Holds per-session data.
typedef struct ngx_http_cp_modification_list ngx_http_cp_modification_list; ///< Holds per-session data modifications.

/// @struct ngx_http_cp_event_thread_ctx_t
/// @brief Holds all the information needed to communicate with the attachment service.
struct ngx_http_cp_event_thread_ctx_t
{
    ngx_http_request_t *request; ///< NGINX request.
    ngx_http_cp_session_data *session_data_p; ///< Provided session data.
    ngx_chain_t *chain; ///< only relevant to body filters

    /// Connection results with the attachment service
    /// - #NGX_OK
    /// - #NGX_ERROR
    ngx_int_t res;

    /// Sets if the context should return and not continue to the next filter.
    int should_return;

    /// Should context continue to the next filter.
    int should_return_next_filter;

    ngx_http_cp_modification_list *modifications; ///< Context's modification.
};

/// 
/// @brief Modifies already_registered value.
/// already_registered is a value that symbolize a successful registeration of the thread context with the nano service.
/// @param[in] value set registration with the nano service:
///         - #0 Thread is not registered with the nano service.
///         - #1 Thread is registered with the nano service.
/// @returns current registration status.
/// 
void set_already_registered(ngx_int_t value);

/// 
/// @brief Returns already_registered value.
/// already_registered is a value that symbolize a successful registeration of the thread context with the nano service.
/// @returns ngx_in_t get registration value with the nano service:
///         - #0 Thread is not registered with the nano service.
///         - #1 Thread is registered with the nano service.
/// 
ngx_int_t get_already_registered(void);

///
/// @brief Resets the registration timeout duration to its minimal value.
/// @returns NULL.
///
void reset_registration_timeout_duration(void);

///
/// @brief Resets the registration timeout.
/// The timeout is being reset to now + timeout duration, where the timeout duration gets doubled every reset.
/// The initial timeout duration is 100 msec, and the maximum is 3200 msec.
/// @returns NULL.
///
void reset_registration_timeout(void);

///
/// @brief Checks if registration timeout has elapsed.
/// @returns 1 if timeout has elapsed, 0 if not.
///
ngx_int_t is_registration_timeout_reached(void);

/// 
/// @brief Initates ngx_http_cp_event_thread_ctx_t struct.
/// @param[in, out] ctx  struct to initiate.
/// @param[in] request
/// @param[in] session_data_p
/// @param[in] chain
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void
init_thread_ctx(
    struct ngx_http_cp_event_thread_ctx_t *ctx,
    ngx_http_request_t *request,
    ngx_http_cp_session_data *session_data_p,
    ngx_chain_t *chain
);

/// 
/// @brief Registers the context against the nano agent.
/// @note _ctx needs to be properly initialized by init_thread_ctx().
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_registration_thread(void *_ctx);

/// 
/// @brief Sends request headers to the attachment's service.
/// @details Communicates with the attachment service by sending request headers to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx().
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_req_header_handler_thread(void *_ctx);

/// 
/// @brief Sends request body to the attachment's service.
/// @details Communicates with the attachment service by sending request body to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx() and ngx_chain_t needs of not NULL.
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_req_body_filter_thread(void *_ctx);

/// 
/// @brief Sends end request transmission to the attachment's service.
/// @details Communicates with the attachment service by sending request body to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx() and ngx_chain_t needs of not NULL.
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_req_end_transaction_thread(void *_ctx);

/// 
/// @brief Sends response headers to the attachment's service.
/// @details Communicates with the attachment service by sending response headers to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx().
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_res_header_filter_thread(void *_ctx);

/// 
/// @brief Sends response body to the attachment's service.
/// @details Communicates with the attachment service by sending response bodies to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx() and ngx_chain_t needs to be defined.
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// @return NULL.
/// 
void * ngx_http_cp_res_body_filter_thread(void *_ctx);

/// 
/// @brief Sends a request to the attachment's service to update the earlier provided "WAIT" verdict.
/// @details Communicates with the attachment service by sending a HOLD_DATA request to the attachment's service
/// and modifies _ctx by the received response.
/// @note _ctx needs to be properly initialized by init_thread_ctx() and 
/// be called after another call returned wait verdict.
/// @param[in, out] _ctx is of type ngx_http_cp_event_thread_ctx_t.
/// Modifies _ctx res to the following values: 
///      - #NGX_OK
///      - #NGX_ERROR
/// Modifies _ctx session data with an updated verdict.
/// @return NULL.
/// 
void * ngx_http_cp_hold_verdict_thread(void *_ctx);

/// 
/// @brief Check if transaction contains headers.
/// @param[in] headers ngx_http_headers_in_t struct.
/// @returns 1 if the transaction contains headers, otherwise 0.
/// 
ngx_int_t does_contain_body(ngx_http_headers_in_t *headers);

#endif // __NGX_CP_HOOK_THREADS_H__
