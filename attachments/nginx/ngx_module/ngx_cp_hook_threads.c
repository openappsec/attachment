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

/// @file ngx_cp_hook_threads.c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_files.h>
#include <ngx_string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "nginx_attachment_util.h"
#include "shmem_ipc.h"
#include "compression_utils.h"
#include "nginx_attachment_common.h"
#include "ngx_cp_io.h"
#include "ngx_cp_utils.h"
#include "ngx_cp_initializer.h"
#include "ngx_http_cp_attachment_module.h"
#include "ngx_cp_static_content.h"
#include "ngx_cp_compression.h"
#include "ngx_cp_http_parser.h"
#include "ngx_cp_hook_threads.h"
#include "ngx_cp_failing_state.h"
#include "ngx_cp_metric.h"
#include "ngx_cp_thread.h"
#include "ngx_cp_hooks.h"

///
/// @brief THREAD_CTX_RETURN, sets this session's context to _X value and set the context
/// to return without going to the next filter.
///
#define THREAD_CTX_RETURN(_X) do { ctx->res = (_X); ctx->should_return = 1;  return NULL; } while (0);

///
/// @brief THREAD_CTX_RETURN_NEXT_FILTER, sets this session's context to _X value and set the context
/// to be scanned by the next filter.
///
#define THREAD_CTX_RETURN_NEXT_FILTER() do { ctx->should_return_next_filter = 1; return NULL; } while (0);

static ngx_int_t already_registered = 0; ///< Registration status with the nano service.
static const ngx_int_t inspection_irrelevant = INSPECTION_IRRELEVANT;
extern struct timeval metric_timeout; ///< Holds per-session metric timeout.

#define MIN_REGISTRATION_DURATION_MSEC 100
#define MAX_REGISTRATION_DURATION_MSEC 3200
static uint current_registration_duration_msec = MIN_REGISTRATION_DURATION_MSEC;
static struct timeval registration_timeout = (struct timeval){0};

inline void
set_already_registered(ngx_int_t value)
{
    already_registered = value;
}

inline ngx_int_t
get_already_registered()
{
    return already_registered;
}

inline void
reset_registration_timeout(void)
{
    registration_timeout = get_timeout_val_msec(current_registration_duration_msec);
    if (current_registration_duration_msec < MAX_REGISTRATION_DURATION_MSEC)
        current_registration_duration_msec *= 2;
}

inline void
reset_registration_timeout_duration(void)
{
    current_registration_duration_msec = MIN_REGISTRATION_DURATION_MSEC;
}

inline ngx_int_t
is_registration_timeout_reached(void)
{
    return is_timeout_reached(&registration_timeout);
}

void
init_thread_ctx(
    struct ngx_http_cp_event_thread_ctx_t *ctx,
    ngx_http_request_t *request,
    ngx_http_cp_session_data *session_data_p,
    ngx_chain_t *chain)
{
    ctx->request = request;
    ctx->session_data_p = session_data_p;
    ctx->res = NGX_OK;
    ctx->should_return = 0;
    ctx->should_return_next_filter = 0;
    ctx->chain = chain;
    ctx->modifications = NULL;
}

void *
ngx_http_cp_registration_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_int_t res = ngx_cp_attachment_init_process(ctx->request);
    if (res == NGX_ABORT && get_already_registered()) {
        set_already_registered(0);
        disconnect_communication();
        reset_transparent_mode();
    }
    if (res != NGX_OK) {
        // failed to register to the attachment service.
        if (get_already_registered())
            handle_inspection_failure(registration_failure_weight, fail_mode_verdict, ctx->session_data_p);
        write_dbg(DBG_LEVEL_DEBUG, "Communication with nano service is not ready yet");
        THREAD_CTX_RETURN(NGX_OK);
    }

    return NULL;
}


///
/// @brief Sends end request header to the attachment's service.
/// @details Communicates with the attachment service by sending end request header 
/// to the attachment's service and returns verdict.
/// @param[in, out] session_data_p If the function returns NGX_OK, session data will be modified.
/// @param[in, out] request NGINX Request.
/// @param[in] modifications A list of this session's data modifications.
/// @return ngx_int_t of the following values:
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
end_req_header_handler(
    ngx_http_cp_session_data *session_data_p,
    ngx_http_request_t *request,
    ngx_http_cp_modification_list **modifications)
{
    ngx_uint_t num_messages_sent = 0;

    if (!does_contain_body(&(request->headers_in))) {
        if (ngx_http_cp_end_transaction_sender(REQUEST_END, session_data_p->session_id, &num_messages_sent) != NGX_OK) {
            write_dbg(
                DBG_LEVEL_WARNING,
                "Failed to send request end data to the nano service. Session ID: %d",
                session_data_p->session_id
            );
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            return fail_mode_verdict;
        }
        session_data_p->remaining_messages_to_reply += num_messages_sent;
    }
    // Fetch nano services' results.
    return ngx_http_cp_reply_receiver(
        &session_data_p->remaining_messages_to_reply,
        &session_data_p->verdict,
        session_data_p->session_id,
        request,
        modifications,
        REQUEST_END
    );
}

ngx_int_t
does_contain_body(ngx_http_headers_in_t *headers)
{
    return headers->chunked || (headers->content_length_n != (off_t)(-1) && headers->content_length_n > 0);
}

void *
ngx_http_cp_req_header_handler_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    ngx_int_t send_meta_data_result;
    ngx_uint_t num_messages_sent = 0;
    ngx_int_t send_header_result;

    send_meta_data_result = ngx_http_cp_meta_data_sender(request, session_data_p->session_id, &num_messages_sent);
    if (send_meta_data_result == inspection_irrelevant) {
        // Ignoring irrelevant requests.
        session_data_p->verdict = TRAFFIC_VERDICT_IRRELEVANT;
        write_dbg(DBG_LEVEL_DEBUG, "Ignoring non-interesting request. Session ID: %d", session_data_p->session_id);
        THREAD_CTX_RETURN(NGX_OK);
    }

    if (send_meta_data_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send request meta data to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        THREAD_CTX_RETURN(fail_mode_verdict);
    }
    session_data_p->remaining_messages_to_reply += num_messages_sent;

    if (is_timeout_reached(&metric_timeout)) {
        // Thread task was timed out.
        set_metric_cpu_usage();
        set_metric_memory_usage();
        if (ngx_http_cp_metric_data_sender() != NGX_OK) {
            write_dbg(DBG_LEVEL_DEBUG, "Failed to send metric data from the plugin to the service");
        }
        metric_timeout = get_timeout_val_sec(METRIC_TIMEOUT_VAL);
    }

    num_messages_sent = 0;
    send_header_result = ngx_http_cp_header_sender(
        &(request->headers_in.headers.part),
        REQUEST_HEADER,
        session_data_p->session_id,
        &num_messages_sent
    );
    if (send_header_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send request headers to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        THREAD_CTX_RETURN(fail_mode_verdict);
    }
    session_data_p->remaining_messages_to_reply += num_messages_sent;

    // Notify the nano service that we've reached the end of the request headers.
    ctx->res = end_req_header_handler(session_data_p, request, &ctx->modifications);

    // The caller function will continue and apply the modified ctx->modifications
    return NULL;
}

void *
ngx_http_cp_req_body_filter_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    ngx_int_t is_last_part;
    ngx_int_t send_body_result;
    ngx_uint_t num_messages_sent = 0;

    send_body_result = ngx_http_cp_body_sender(
        ctx->chain,
        REQUEST_BODY,
        session_data_p,
        &is_last_part,
        &num_messages_sent,
        &ctx->chain
    );

    if (send_body_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send request body data to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }
    session_data_p->remaining_messages_to_reply += num_messages_sent;

    // Fetch nano services' results.
    ctx->res = ngx_http_cp_reply_receiver(
        &session_data_p->remaining_messages_to_reply,
        &session_data_p->verdict,
        session_data_p->session_id,
        request,
        &ctx->modifications,
        REQUEST_BODY
    );

    if (is_last_part) session_data_p->was_request_fully_inspected = 1;

    return NULL;
}

void *
ngx_http_cp_req_end_transaction_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    ngx_uint_t num_messages_sent = 0;

    if (ngx_http_cp_end_transaction_sender(REQUEST_END, session_data_p->session_id, &num_messages_sent) != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send request end data to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }

    session_data_p->remaining_messages_to_reply += num_messages_sent;

    if (session_data_p->verdict != TRAFFIC_VERDICT_ACCEPT &&
        session_data_p->verdict != TRAFFIC_VERDICT_DROP) {
        // Fetch nano services' results.
        ctx->res = ngx_http_cp_reply_receiver(
            &session_data_p->remaining_messages_to_reply,
            &session_data_p->verdict,
            session_data_p->session_id,
            request,
            &ctx->modifications,
            REQUEST_END
        );
    }

    return NULL;
}

void *
ngx_http_cp_res_header_filter_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    ngx_int_t set_response_content_encoding_res;
    ngx_int_t send_res_code_result;
    ngx_int_t send_content_length_result;
    ngx_int_t send_header_result;
    ngx_uint_t num_messages_sent = 0;

    // Sends response code to the nano service.
    send_res_code_result = ngx_http_cp_res_code_sender(
        request->headers_out.status,
        session_data_p->session_id,
        &num_messages_sent
    );
    if (send_res_code_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send response meta data to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }

    session_data_p->remaining_messages_to_reply += num_messages_sent;
    num_messages_sent = 0;

    // Sends response content length to the nano service.
    send_content_length_result = ngx_http_cp_content_length_sender(
        request->headers_out.content_length_n,
        session_data_p->session_id,
        &num_messages_sent
    );
    if (send_content_length_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send headers content length to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }

    session_data_p->remaining_messages_to_reply += num_messages_sent;
    
    // Sets response body's content encoding.
    set_response_content_encoding_res = set_response_content_encoding(
        &session_data_p->response_data.original_compression_type,
        request->headers_out.content_encoding
    );
    if (set_response_content_encoding_res != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to set response body's content encoding. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }
    session_data_p->response_data.new_compression_type = session_data_p->response_data.original_compression_type;

    // Sends response headers to the nano service.
    num_messages_sent = 0;
    send_header_result = ngx_http_cp_header_sender(
        &request->headers_out.headers.part,
        RESPONSE_HEADER,
        session_data_p->session_id,
        &num_messages_sent
    );
    if (send_header_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send response headers to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }

    session_data_p->remaining_messages_to_reply += num_messages_sent;

    // Fetch nano services' results.
    ctx->res = ngx_http_cp_reply_receiver(
        &session_data_p->remaining_messages_to_reply,
        &session_data_p->verdict,
        session_data_p->session_id,
        request,
        &ctx->modifications,
        RESPONSE_HEADER
    );

    return NULL;
}

void *
ngx_http_cp_res_body_filter_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;
    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    ngx_int_t send_body_result;
    ngx_uint_t num_messages_sent = 0;
    ngx_int_t is_last_response_part = 0;

    // Send response body data to the nano service.
    send_body_result = ngx_http_cp_body_sender(
        ctx->chain,
        RESPONSE_BODY,
        session_data_p,
        &is_last_response_part,
        &num_messages_sent,
        &ctx->chain
    );
    if (send_body_result != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send response body data to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }
    session_data_p->remaining_messages_to_reply += num_messages_sent;

    num_messages_sent = 0;
    if (is_last_response_part) {
        // Signals the nano service that the transaction reached the end.
        if (ngx_http_cp_end_transaction_sender(RESPONSE_END, session_data_p->session_id, &num_messages_sent) != NGX_OK) {
            write_dbg(
                DBG_LEVEL_WARNING,
                "Failed to send response end data to the nano service. Session ID: %d",
                session_data_p->session_id
            );
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            if (fail_mode_verdict == NGX_OK) {
                THREAD_CTX_RETURN_NEXT_FILTER();
            }
            THREAD_CTX_RETURN(NGX_ERROR);
        }
        session_data_p->remaining_messages_to_reply++;
    }

    // Fetch nano services' results.
    ctx->res = ngx_http_cp_reply_receiver(
        &session_data_p->remaining_messages_to_reply,
        &session_data_p->verdict,
        session_data_p->session_id,
        request,
        &ctx->modifications,
        RESPONSE_BODY
    );

    return NULL;
}

void *
ngx_http_cp_hold_verdict_thread(void *_ctx)
{
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)_ctx;

    ngx_http_request_t *request = ctx->request;
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;

    ngx_uint_t num_messages_sent = 0;

    if (ngx_http_cp_wait_sender(session_data_p->session_id, &num_messages_sent) != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to send inspect wait request to the nano service. Session ID: %d",
            session_data_p->session_id
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_hold_verdict, session_data_p);
        if (fail_mode_hold_verdict == NGX_OK) {
            THREAD_CTX_RETURN_NEXT_FILTER();
        }
        THREAD_CTX_RETURN(NGX_ERROR);
    }
    session_data_p->remaining_messages_to_reply += num_messages_sent;

    ctx->res = ngx_http_cp_reply_receiver(
        &session_data_p->remaining_messages_to_reply,
        &session_data_p->verdict,
        session_data_p->session_id,
        request,
        &ctx->modifications,
        HOLD_DATA
    );

    write_dbg(
        DBG_LEVEL_TRACE,
        "Successfully receivied response to wait from the nano service. Session ID: %d",
        session_data_p->session_id
    );

    return NULL;
}
