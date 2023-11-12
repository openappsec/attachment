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

/// @file ngx_cp_hooks.c
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

extern ngx_module_t ngx_http_cp_attachment_module; ///< CP Attachment module

static const ngx_int_t not_a_static_resource = NOT_A_STATIC_RESOURCE;

struct timeval metric_timeout = {0,0};

static const uint one_minute = 60;

///
/// @brief Initates a session data pointer.
/// @param[in] request NGINX request.
/// @return
///         - #ngx_http_cp_session_data pointer if everything was initiated properly.
///         - #NULL
///
static ngx_http_cp_session_data *
init_cp_session_data(ngx_http_request_t *request)
{
    static uint32_t session_id = 1;

    write_dbg(DBG_LEVEL_TRACE, "Initializing new session data ctx for session ID %d", session_id);

    // session data is used to save verdict and session ID between the request and the response
    ngx_http_cp_session_data *session_data;

    session_data = (ngx_http_cp_session_data *)ngx_pcalloc(request->pool, sizeof(ngx_http_cp_session_data));
    if (session_data == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate session data memory for session ID %d\n", session_id);
        return NULL;
    }

    session_data->was_request_fully_inspected = 0;
    session_data->verdict = TRAFFIC_VERDICT_INSPECT;
    session_data->session_id = (session_id << 1) | 1U; // Prevent collision with Squid sessions
    session_id++;
    session_data->remaining_messages_to_reply = 0;
    session_data->response_data.response_data_status = NGX_OK;
    if (!metric_timeout.tv_sec) {
        metric_timeout = get_timeout_val_sec(METRIC_TIMEOUT_VAL);
    }
    clock_gettime(CLOCK_REALTIME, &session_data->session_start_time);
    session_data->req_proccesing_time = 0;
    session_data->res_proccesing_time = 0;
    session_data->processed_req_body_size = 0;
    session_data->processed_req_body_size = 0;

    ngx_http_set_ctx(request, session_data, ngx_http_cp_attachment_module);

    return session_data;
}

///
/// @brief Finalize a session data, make sure all the memory is properly released.
/// @param[in] session_data Pointer to the session structure to be finalized.
///
static void
fini_cp_session_data(ngx_http_cp_session_data *session_data)
{
    if (session_data->response_data.compression_stream != NULL) {
        finiCompressionStream(session_data->response_data.compression_stream);
        session_data->response_data.compression_stream = NULL;
    }
    if (session_data->response_data.decompression_stream != NULL) {
        finiCompressionStream(session_data->response_data.decompression_stream);
        session_data->response_data.decompression_stream = NULL;
    }
}

///
/// @brief Recovers a session data pointer.
/// @param[in] request NGINX request.
/// @return
///         - #ngx_http_cp_session_data pointer if everything was initiated properly.
///         - #NULL
///
static ngx_http_cp_session_data *
recover_cp_session_data(ngx_http_request_t *request)
{
    return (ngx_http_cp_session_data *)ngx_http_get_module_ctx(request, ngx_http_cp_attachment_module);
}

ngx_int_t
was_transaction_timedout(ngx_http_cp_session_data *ctx)
{
    if (req_max_proccessing_ms_time && ctx->req_proccesing_time >= (double)req_max_proccessing_ms_time*1000) {
        updateMetricField(REQ_PROCCESSING_TIMEOUT, 1);
    } else if (res_max_proccessing_ms_time && ctx->res_proccesing_time >= (double)res_max_proccessing_ms_time*1000) {
        updateMetricField(RES_PROCCESSING_TIMEOUT, 1);
    } else {
        return 0;
    }
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Reached timeout during transaction inspection. "
        "Returning fail-%s verdict (%s), req_proccesing_time=%lf, res_proccesing_time=%lf",
        fail_mode_verdict == NGX_OK ? "open" : "close",
        fail_mode_verdict == NGX_OK ? "Accept" : "Drop",
        ctx->req_proccesing_time,
        ctx->res_proccesing_time
    );

    handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, ctx);

    return 1;
}

ngx_int_t
ngx_http_cp_hold_verdict(struct ngx_http_cp_event_thread_ctx_t *ctx)
{
    ngx_http_cp_session_data *session_data_p = ctx->session_data_p;
    for (uint i = 0; i < 3; i++) {
        sleep(1);
        int res = ngx_cp_run_in_thread_timeout(
            ngx_http_cp_hold_verdict_thread,
            (void *)ctx,
            waiting_for_verdict_thread_timeout_msec,
            "ngx_http_cp_hold_verdict_thread"
        );

        if (!res) {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "ngx_http_cp_hold_verdict_thread failed at attempt number=%d",
                i
            );
            continue;
        }

        if (session_data_p->verdict != TRAFFIC_VERDICT_WAIT) {
            // Verdict was updated.
            write_dbg(
                DBG_LEVEL_DEBUG,
                "finished ngx_http_cp_hold_verdict successfully. new verdict=%d",
                session_data_p->verdict
            );
            return 1;
        }
    }
    write_dbg(DBG_LEVEL_TRACE, "Handling Failure with fail %s mode", fail_mode_hold_verdict == NGX_OK ? "open" : "close");
    handle_inspection_failure(inspection_failure_weight, fail_mode_hold_verdict, session_data_p);
    session_data_p->verdict = fail_mode_hold_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
    return 0;
}

ngx_http_cp_verdict_e
enforce_sessions_rate()
{
    ngx_http_cp_sessions_per_minute_limit *sessions_limit = get_periodic_sessions_limit_info();
    ngx_http_cp_verdict_e verdict = get_sessions_per_minute_limit_verdict();
    unsigned int max_sessions = get_max_sessions_per_minute();

    unsigned int curr_real_second = (unsigned int)(time(NULL));
    unsigned int curr_real_periodic_second = curr_real_second % 60;
    unsigned int seconds_since_last_session = curr_real_second - sessions_limit->last_session_time;

    unsigned int expired_session;
    unsigned int periodic_expired_session;
    unsigned int i;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Handling new session. Number of last minute sessions: %u ",
        sessions_limit->last_minute_sessions_sum
    );

    if (seconds_since_last_session > one_minute) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Resetting all session monitoring data after more then one minute had passed since then last session"
        );
        memset(sessions_limit->sessions_per_second, 0, sizeof(sessions_limit->sessions_per_second));
        sessions_limit->last_minute_sessions_sum = 0;
        sessions_limit->last_session_time = curr_real_second;
    } else if (seconds_since_last_session != 0) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Passed %u seconds since last session. Cleaning sessions limit array",
            seconds_since_last_session
        );
        expired_session = curr_real_second;
        for (i = 0; i < seconds_since_last_session; i++) {
            periodic_expired_session = expired_session % 60;
            sessions_limit->last_minute_sessions_sum -= sessions_limit->sessions_per_second[periodic_expired_session];
            sessions_limit->sessions_per_second[periodic_expired_session] = 0;
            expired_session--;
        }
        sessions_limit->last_session_time = curr_real_second;
    }

    sessions_limit->sessions_per_second[curr_real_periodic_second]++;
    sessions_limit->last_minute_sessions_sum++;

    if (max_sessions != 0 &&
        sessions_limit->last_minute_sessions_sum > max_sessions
    ) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Exceeded session rate limit, Returning default verdict. Limit: %u, Verdict: %s",
            max_sessions,
            verdict == TRAFFIC_VERDICT_ACCEPT ? "Accept" : "Drop"
        );
        return verdict;
    }

    return TRAFFIC_VERDICT_INSPECT;
}

///
/// @brief Handles the final part of request headers.
/// @param[in] request NGINX request.
/// @param[in, out] session_data_p Session's data.
/// @param[in] modifications Modification list
/// @param[in] final_res
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_HTTP_FORBIDDEN
///         - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_finalize_request_headers_hook(
    ngx_http_request_t *request,
    ngx_http_cp_session_data *session_data_p,
    ngx_http_cp_modification_list *modifications,
    ngx_int_t final_res)
{
    int request_body_exists = does_contain_body(&(request->headers_in));

    if (final_res == NGX_HTTP_FORBIDDEN) {
        handle_inspection_success(session_data_p);
        return ngx_http_cp_finalize_rejected_request(request);
    }

    if (final_res != NGX_OK) {
        write_dbg(DBG_LEVEL_TRACE, "Handling Failure with fail %s mode", fail_mode_verdict == NGX_OK ? "open" : "close");
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        return fail_mode_verdict;
    }

    if (modifications == NULL) {
        handle_inspection_success(session_data_p);
        if (!request_body_exists) session_data_p->was_request_fully_inspected = 1;
        return NGX_OK;
    }

    if (ngx_http_cp_header_modifier(&(request->headers_in.headers), modifications, request, 0) != NGX_OK) {
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        return fail_mode_verdict;
    }

    handle_inspection_success(session_data_p);
    if (!request_body_exists) session_data_p->was_request_fully_inspected = 1;

    return NGX_OK;
}

///
/// @brief Handles the final part of request headers.
/// @details Calculates the processing time using the hook_time_begin
/// and adds it into the relevantsession_data_p's field.
/// @param[in, out] session_data_p Session's data.
/// @param[in] hook_time_begin The time that the hook started.
/// @param[in] is_req Is calculating request or response processing time.
///         - #0 - Calculates response processing time.
///         - #1 - Calculates request processing time.
///
void
calcProcessingTime(ngx_http_cp_session_data *session_data_p, struct timespec *hook_time_begin, int is_req)
{
    struct timespec hook_time_end;
    clock_gettime(CLOCK_REALTIME, &hook_time_end);

    double begin_usec = (hook_time_begin->tv_sec * 1000000) + (hook_time_begin->tv_nsec / 1000);
    double end_usec = (hook_time_end.tv_sec * 1000000) + (hook_time_end.tv_nsec / 1000);
    double elapsed = end_usec - begin_usec;
    if (is_req) {
        session_data_p->req_proccesing_time += elapsed;
    } else {
        session_data_p->res_proccesing_time += elapsed;
    }
}

///
/// @brief Calculates the size of a request.
/// @details Calculates the size of a given request according to headers
/// and body parts lengths.
/// @param[in] request NGINX request.
/// @return the calculated size of the request.
///
static uint64_t
calc_request_size(ngx_http_request_t *request)
{
    uint64_t  request_size = 0;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    static const uint64_t  max_expected_request_size = 100ULL * 1024 * 1024;

    // Calculate the size of request headers
    for (part = &request->headers_in.headers.part; part != NULL; part = part->next) {
        header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            request_size += header[i].key.len + header[i].value.len + 2; // 2 bytes for CRLF
        }
    }
    request_size += 2;

    // Calculate the size of the request body
    if (request->request_body && request->request_body->buf) {
        request_size += ngx_buf_size(request->request_body->buf);
    }
    write_dbg(DBG_LEVEL_TRACE, "Request size %d", request_size);
    if (request_size > max_expected_request_size) {
        write_dbg(DBG_LEVEL_WARNING, "Request size is higher than expected: %d", request_size);
    }
    return request_size;
}

///
/// @brief Calculates the size of a response.
/// @details Calculates the size of a response according to Content-Length
/// header if available or according to header and body parts lengths if it
/// is not available.
/// @param[in] request NGINX request.
/// @return the calculated size of the response.
///
static uint64_t
calc_response_size(ngx_http_request_t *request)
{
    uint64_t response_size = 0;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;

    // Calculate the size of response headers
    for (part = &request->headers_out.headers.part; part != NULL; part = part->next) {
        header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            response_size += header[i].key.len + header[i].value.len + 2; // 2 bytes for CRLF
        }
    }
    response_size += 2;

    // Calculate the size of the request body
    if (request->headers_out.content_length_n != -1) {
        // If Content-Length header is set, use it
        response_size += request->headers_out.content_length_n;
    } else {
        // Otherwise, iterate through response buffers and add their sizes
        ngx_chain_t *chain = request->out;
        for (chain = request->out; chain != NULL ; chain = chain->next) {
            if (chain->buf) response_size += ngx_buf_size(chain->buf);
        }
    }

    write_dbg(DBG_LEVEL_TRACE, "Response size %d", response_size);
    return response_size;
}

ngx_int_t
ngx_http_cp_req_header_handler(ngx_http_request_t *request)
{
    ngx_http_cp_session_data *session_data_p;
    ngx_int_t handle_static_resource_result;
    ngx_http_cp_verdict_e sessions_per_minute_verdict;
    struct ngx_http_cp_event_thread_ctx_t ctx;
    struct timespec hook_time_begin;
    int res;
    static int is_failure_state_initialized = 0;
    static int is_metric_data_initialized = 0;

    clock_gettime(CLOCK_REALTIME, &hook_time_begin);

    if (is_failure_state_initialized == 0) {
        reset_transparent_mode();
        is_failure_state_initialized = 1;
    }

    if (is_metric_data_initialized == 0) {
        reset_metric_data();
        is_metric_data_initialized = 1;
    }

    set_current_session_id(0);
    reset_dbg_ctx();
    write_dbg(DBG_LEVEL_DEBUG, "Request headers received");

    updateMetricField(REQUEST_OVERALL_SIZE_COUNT, calc_request_size(request));
    if (is_in_transparent_mode()) {
        updateMetricField(TRANSPARENTS_COUNT, 1);
        return fail_mode_verdict;
    }

    if (is_ngx_cp_attachment_disabled(request)) {
        write_dbg(DBG_LEVEL_TRACE, "Ignoring inspection of request on a disabled location");
        return NGX_OK;
    }

    session_data_p = init_cp_session_data(request);
    if (session_data_p == NULL) return NGX_OK;

    set_current_session_id(session_data_p->session_id);
    write_dbg(DBG_LEVEL_DEBUG, "Request header filter handling session ID: %d", session_data_p->session_id);

    init_thread_ctx(&ctx, request, session_data_p, NULL);

    sessions_per_minute_verdict = enforce_sessions_rate();
    if (sessions_per_minute_verdict != TRAFFIC_VERDICT_INSPECT) {
        session_data_p->verdict = sessions_per_minute_verdict;
        return sessions_per_minute_verdict == TRAFFIC_VERDICT_ACCEPT ? NGX_OK : NGX_ERROR;
    }

    if (!get_already_registered() || !isIpcReady()) {
        if (is_registration_timeout_reached()) {
            write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_registration_thread");
            reset_registration_timeout();
            res = ngx_cp_run_in_thread_timeout(
                ngx_http_cp_registration_thread,
                (void *)&ctx,
                registration_thread_timeout_msec,
                "ngx_http_cp_registration_thread"
            );
        } else {
            res = 0;
            write_dbg(DBG_LEVEL_DEBUG, "Attachment registration has recently started, wait for timeout");
        }

        if (!res) {
            // failed to execute thread task, or it timed out
            session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            write_dbg(
                DBG_LEVEL_DEBUG,
                "registraton thread failed, returning default fail mode verdict. Session id: %d, verdict: %s",
                session_data_p->session_id,
                session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
            );
            updateMetricField(REG_THREAD_TIMEOUT, 1);

            return fail_mode_verdict;
        }
        write_dbg(
            DBG_LEVEL_DEBUG,
            "finished ngx_http_cp_registration_thread successfully. return=%d res=%d",
            ctx.should_return,
            ctx.res
        );
        if (ctx.should_return) {
            session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
            return ctx.res;
        }
    }

    set_already_registered(1);
    reset_registration_timeout_duration();

    if (handle_shmem_corruption() == NGX_ERROR) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Shared memory is corrupted, returning default fail mode verdict. Session id: %d, verdict: %s",
            session_data_p->session_id,
            session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
        );
        return fail_mode_verdict;
    }

    handle_static_resource_result = handle_static_resource_request(
        session_data_p->session_id,
        &session_data_p->verdict,
        request
    );
    if (handle_static_resource_result != not_a_static_resource) return handle_static_resource_result;
    write_dbg(DBG_LEVEL_DEBUG, "Request header filter handling session ID: %d", session_data_p->session_id);

    write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_req_header_handler_thread");
    res = ngx_cp_run_in_thread_timeout(
        ngx_http_cp_req_header_handler_thread,
        (void *)&ctx,
        req_header_thread_timeout_msec,
        "ngx_http_cp_req_header_handler_thread"
    );
    if (!res) {
        // failed to execute thread task, or it timed out
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "req_header_handler thread failed, returning default fail mode verdict. Session id: %d, verdict: %s",
            session_data_p->session_id,
            session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
        );
        updateMetricField(REQ_HEADER_THREAD_TIMEOUT, 1);

        return fail_mode_verdict;
    }
    write_dbg(
        DBG_LEVEL_DEBUG,
        "finished ngx_http_cp_req_header_handler_thread successfully. return=%d res=%d",
        ctx.should_return,
        ctx.res
    );

    if (session_data_p->verdict == TRAFFIC_VERDICT_WAIT) {
        res = ngx_http_cp_hold_verdict(&ctx);
        if (!res) {
            session_data_p->verdict = fail_mode_hold_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            updateMetricField(HOLD_THREAD_TIMEOUT, 1);
            return fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        }
    }

    calcProcessingTime(session_data_p, &hook_time_begin, 1);
    if (ctx.should_return) {
        return ctx.res;
    }

    // There's no body for inspection
    return ngx_http_cp_finalize_request_headers_hook(
        request,
        session_data_p,
        ctx.modifications,
        ctx.res
    );
}

ngx_int_t
ngx_http_cp_req_body_filter(ngx_http_request_t *request, ngx_chain_t *request_body_chain)
{
    struct ngx_http_cp_event_thread_ctx_t ctx;
    ngx_http_cp_session_data *session_data_p = recover_cp_session_data(request);
    ngx_int_t final_res;
    int res;
    ngx_chain_t *chain_elem = NULL;
    struct timespec hook_time_begin;

    if (session_data_p == NULL) return ngx_http_next_request_body_filter(request, request_body_chain);

    write_dbg(DBG_LEVEL_DEBUG, "Request body received");

    set_current_session_id(0);

    if (!isIpcReady()) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "IPC is uninitialized. Skipping inspection of current request. Session id: %d",
            session_data_p->session_id
        );
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_request_body_filter(request, request_body_chain);
        }
        return NGX_HTTP_FORBIDDEN;
    }
    set_current_session_id(session_data_p->session_id);
    write_dbg(DBG_LEVEL_TRACE, "Request body filter handling session ID: %d", session_data_p->session_id);

    if (is_in_transparent_mode()) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_request_body_filter(request, request_body_chain);
        }
        return NGX_HTTP_FORBIDDEN;
    }

    if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) {
        write_dbg(DBG_LEVEL_TRACE, "Dropping already inspected request body");
        return NGX_HTTP_FORBIDDEN;
    }

    if (session_data_p->verdict != TRAFFIC_VERDICT_INSPECT) {
        write_dbg(DBG_LEVEL_TRACE, "skipping already inspected request body");
        return ngx_http_next_request_body_filter(request, request_body_chain);
    }

    if (request_body_chain == NULL) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "No body chunks were received for inspection. Session ID: %d",
            session_data_p->session_id
        );
        return ngx_http_next_request_body_filter(request, request_body_chain);
    }

    if (was_transaction_timedout(session_data_p)) {
        if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) {
            return NGX_HTTP_FORBIDDEN;
        }
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        return ngx_http_next_request_body_filter(request, request_body_chain);
    }

    init_thread_ctx(&ctx, request, session_data_p, request_body_chain);

    write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_req_body_filter_thread");
    // Open threads while unprocessed chain elements still exist, up to num of elements in the chain iterations
    for (chain_elem = ctx.chain; chain_elem != NULL && ctx.chain; chain_elem = chain_elem->next) {
        // Notify if zero-size buf is marked as "memory". This should never happen but if it does we want to know.
        if (chain_elem->buf && chain_elem->buf->pos &&
            (chain_elem->buf->last - chain_elem->buf->pos == 0) && chain_elem->buf->memory == 1) {
            write_dbg(DBG_LEVEL_WARNING,
                "Warning: encountered request body chain element of size 0 with memory flag enabled");
        }
        clock_gettime(CLOCK_REALTIME, &hook_time_begin);
        res = ngx_cp_run_in_thread_timeout(
            ngx_http_cp_req_body_filter_thread,
            (void *)&ctx,
            req_body_thread_timeout_msec,
            "ngx_http_cp_req_body_filter_thread"
        );
        if (!res || ctx.res == NGX_ERROR) {
            // failed to execute thread task, or it timed out
            session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            write_dbg(
                DBG_LEVEL_DEBUG,
                "req_body_filter thread failed, returning default fail mode verdict. "
                "thread execution result: %d, nano service reply: %d, Session id: %d, verdict: %s",
                res,
                ctx.res,
                session_data_p->session_id,
                session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
            );
            updateMetricField(REQ_BODY_THREAD_TIMEOUT, 1);
            updateMetricField(AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_req_body_size);
            updateMetricField(MAX_REQ_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_req_body_size);
            updateMetricField(MIN_REQ_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_req_body_size);

            return fail_mode_verdict == NGX_OK ? ngx_http_next_request_body_filter(request, request_body_chain) : NGX_ERROR;
        }
        write_dbg(
            DBG_LEVEL_DEBUG,
            "finished ngx_http_cp_req_body_filter_thread successfully. return=%d next_filter=%d res=%d",
            ctx.should_return,
            ctx.should_return_next_filter,
            ctx.res
        );

        if (session_data_p->verdict == TRAFFIC_VERDICT_WAIT) {
            res = ngx_http_cp_hold_verdict(&ctx);
            if (!res) {
                session_data_p->verdict = fail_mode_hold_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                updateMetricField(HOLD_THREAD_TIMEOUT, 1);
                return fail_mode_verdict == NGX_OK ? ngx_http_next_request_body_filter(request, request_body_chain) : NGX_ERROR;
            }
        }

        if (session_data_p->was_request_fully_inspected) {
            res = ngx_cp_run_in_thread_timeout(
                ngx_http_cp_req_end_transaction_thread,
                (void *)&ctx,
                req_body_thread_timeout_msec,
                "ngx_http_cp_req_end_transaction_thread"
            );
            if (!res) {
                // failed to execute thread task, or it timed out
                session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "req_end_transaction thread failed, returning default fail mode verdict. Session id: %d, verdict: %s",
                    session_data_p->session_id,
                    session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
                );
                updateMetricField(REQ_BODY_THREAD_TIMEOUT, 1);
                return fail_mode_verdict == NGX_OK ? ngx_http_next_request_body_filter(request, request_body_chain) : NGX_ERROR;
            }

            write_dbg(
                DBG_LEVEL_DEBUG,
                "finished ngx_http_cp_req_end_transaction_thread successfully. return=%d next_filter=%d res=%d",
                ctx.should_return,
                ctx.should_return_next_filter,
                ctx.res
            );
        }

        calcProcessingTime(session_data_p, &hook_time_begin, 1);
        if (ctx.should_return_next_filter) {
            return ngx_http_next_request_body_filter(request, request_body_chain);
        }

        if (ctx.should_return) {
            return ctx.res;
        }
        if (was_transaction_timedout(session_data_p)) {
            session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            return ngx_http_next_request_body_filter(request, request_body_chain);
        }
    }

    if (ctx.chain) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        write_dbg(
            DBG_LEVEL_WARNING,
            "Could not complete inspection of all body chain elements, returning default fail mode verdict. "
            "Session id: %d, verdict: %s",
            session_data_p->session_id,
            session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
        );
        return fail_mode_verdict == NGX_OK ? ngx_http_next_request_body_filter(request, request_body_chain) : NGX_ERROR;
    }

    final_res = ctx.res;

    if (final_res == NGX_HTTP_FORBIDDEN) {
        handle_inspection_success(session_data_p);
        return ngx_http_cp_finalize_rejected_request(request);
    }

    if (final_res != NGX_OK) {
        write_dbg(DBG_LEVEL_TRACE, "Handling Failure with fail %s mode", fail_mode_verdict == NGX_OK ? "open" : "close");
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_request_body_filter(request, request_body_chain);
        }
        return NGX_ERROR;
    }

    if (ctx.modifications != NULL) {
        write_dbg(DBG_LEVEL_TRACE, "Handling request headers modification");
        if (ngx_http_cp_header_modifier(
            &(request->headers_in.headers),
            ctx.modifications,
            request,
            0
        ) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to modify request headers");
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            if (fail_mode_verdict == NGX_OK) {
                return ngx_http_next_request_body_filter(request, request_body_chain);
            }
            return NGX_ERROR;
        }

        write_dbg(DBG_LEVEL_TRACE, "Handling request body modification");
        if (ngx_http_cp_body_modifier(request_body_chain, ctx.modifications, request->pool) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to modify request body");
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            if (fail_mode_verdict == NGX_OK) {
                return ngx_http_next_request_body_filter(request, request_body_chain);
            }
            return NGX_ERROR;
        }
    }

    handle_inspection_success(session_data_p);
    return ngx_http_next_request_body_filter(request, request_body_chain);
}

ngx_int_t
ngx_http_cp_res_header_filter(ngx_http_request_t *request)
{
    struct ngx_http_cp_event_thread_ctx_t ctx;
    ngx_http_cp_session_data *session_data_p;
    struct timespec hook_time_begin;
    clock_gettime(CLOCK_REALTIME, &hook_time_begin);

    set_current_session_id(0);

    session_data_p = recover_cp_session_data(request);

    if (session_data_p == NULL) return ngx_http_next_response_header_filter(request);

    set_current_session_id(session_data_p->session_id);

    write_dbg(DBG_LEVEL_DEBUG, "Response header filter handling session ID: %d", session_data_p->session_id);

    updateMetricField(RESPONSE_OVERALL_SIZE_COUNT, calc_response_size(request));

    if (!isIpcReady()) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "IPC is uninitialized. Skipping inspection of current request. Session id: %d",
            session_data_p->session_id
        );
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_header_filter(request);
        }
        return NGX_ERROR;
    }

    if (is_in_transparent_mode()) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_header_filter(request);
        }
        return NGX_ERROR;
    }

    if (session_data_p->verdict != TRAFFIC_VERDICT_INSPECT) {
        write_dbg(DBG_LEVEL_TRACE, "Skipping already inspected response header");
        return ngx_http_next_response_header_filter(request);
    }

    if (was_transaction_timedout(session_data_p)) {
        if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) {
            return NGX_ERROR;
        }
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        return ngx_http_next_response_header_filter(request);
    }

    if (!session_data_p->was_request_fully_inspected) {
        write_dbg(DBG_LEVEL_DEBUG, "Skipping response header of request that was not fully inspected");

        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        updateMetricField(REQ_FAILED_TO_REACH_UPSTREAM, 1);
        session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
        return ngx_http_next_response_header_filter(request);
    }

    init_thread_ctx(&ctx, request, session_data_p, NULL);

    write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_res_header_filter");
    if (!ngx_cp_run_in_thread_timeout(
        ngx_http_cp_res_header_filter_thread,
        (void*)&ctx,
        res_header_thread_timeout_msec,
        "ngx_http_cp_res_header_filter_thread")
    ) {
        // failed to execute thread task, or it timed out
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "res_header_filter thread failed, returning default fail mode verdict. Session id: %d, verdict: %s",
            session_data_p->session_id,
            session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
        );
        updateMetricField(RES_HEADER_THREAD_TIMEOUT, 1);

        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_header_filter(request);
        }
        return NGX_ERROR;
    }
    write_dbg(DBG_LEVEL_DEBUG, "finished ngx_http_cp_res_header_filter_thread succesfully. return=%d next_filter=%d res=%d",
        ctx.should_return, ctx.should_return_next_filter, ctx.res);

    calcProcessingTime(session_data_p, &hook_time_begin, 0);

    if (ctx.should_return_next_filter) {
        return ngx_http_next_response_header_filter(request);
    }

    ngx_int_t final_res = ctx.res;

    if (final_res == NGX_HTTP_FORBIDDEN) {
        handle_inspection_success(session_data_p);
        return ngx_http_cp_finalize_rejected_request(request);
    }

    if (final_res != NGX_OK) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Handling Failure with fail %s mode",
            fail_mode_verdict == NGX_OK ? "open" : "close"
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_header_filter(request);
        }
        return NGX_ERROR;
    }

    if (ctx.modifications != NULL) {
        write_dbg(DBG_LEVEL_TRACE, "Handling response headers modification");
        if (ngx_http_cp_header_modifier(&(request->headers_out.headers), ctx.modifications, request, 1) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to modify request headers");
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            if (fail_mode_verdict == NGX_OK) {
                return ngx_http_next_response_header_filter(request);
            }
            return NGX_ERROR;
        }
    }

    handle_inspection_success(session_data_p);
    return ngx_http_next_response_header_filter(request);
}

ngx_int_t
ngx_http_cp_res_body_filter(ngx_http_request_t *request, ngx_chain_t *body_chain)
{
    struct ngx_http_cp_event_thread_ctx_t ctx;
    ngx_http_cp_session_data *session_data_p;
    ngx_chain_t *original_compressed_body = NULL;
    ngx_int_t compression_result;
    ngx_chain_t *chain_elem = NULL;
    ngx_int_t final_res;
    int is_last_decompressed_part = 0;
    struct timespec hook_time_begin;

    set_current_session_id(0);

    session_data_p = recover_cp_session_data(request);
    if (session_data_p == NULL) return ngx_http_next_response_body_filter(request, body_chain);

    set_current_session_id(session_data_p->session_id);
    write_dbg(DBG_LEVEL_DEBUG, "Response body filter handling response ID: %d", session_data_p->session_id);

    if (!isIpcReady()) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "IPC is uninitialized. Skipping inspection of current request. Session id: %d",
            session_data_p->session_id
        );
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        fini_cp_session_data(session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_body_filter(request, body_chain);
        }
        return NGX_ERROR;
    }


    if (session_data_p->response_data.response_data_status != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "skipping session with corrupted compression");
        updateMetricField(CORRUPTED_ZIP_SKIPPED_SESSION_COUNT, 1);
        if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) request->keepalive = 0;
        return ngx_http_next_response_body_filter(request, body_chain);
    }

    if (
        session_data_p->verdict != TRAFFIC_VERDICT_INSPECT &&
        (
            session_data_p->verdict != TRAFFIC_VERDICT_ACCEPT ||
            session_data_p->response_data.new_compression_type == NO_COMPRESSION ||
            session_data_p->response_data.num_body_chunk == 0
        )
    ) {
        write_dbg(DBG_LEVEL_TRACE, "skipping already inspected session");
        if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) request->keepalive = 0;
        return ngx_http_next_response_body_filter(request, body_chain);
    }

    session_data_p->response_data.num_body_chunk++;

    if (body_chain == NULL) {
       write_dbg(
           DBG_LEVEL_TRACE,
           "No body chunks were received for inspection. Session ID: %d",
           session_data_p->session_id
       );
       return ngx_http_next_response_body_filter(request, body_chain);
    }

    if (body_chain->buf->pos != NULL && session_data_p->response_data.new_compression_type != NO_COMPRESSION) {
        // Decompress and re-compress non-empty buffer to maintain consistent compression stream
        original_compressed_body = ngx_alloc_chain_link(request->pool);
        ngx_memset(original_compressed_body, 0, sizeof(ngx_chain_t));

        if (session_data_p->response_data.decompression_stream == NULL) {
            session_data_p->response_data.decompression_stream = initCompressionStream();
        }

        compression_result = decompress_body(
            session_data_p->response_data.decompression_stream,
            RESPONSE_BODY,
            &is_last_decompressed_part,
            &body_chain,
            &original_compressed_body,
            request->pool
        );

        if (compression_result != NGX_OK) {
            copy_chain_buffers(body_chain, original_compressed_body);
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            fini_cp_session_data(session_data_p);
            session_data_p->response_data.response_data_status = NGX_ERROR;
            return fail_mode_verdict == NGX_OK ?
                ngx_http_next_response_body_filter(request, body_chain) :
                NGX_ERROR;
        }
    }

    if (session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT) {
        if (session_data_p->response_data.compression_stream == NULL) {
            session_data_p->response_data.compression_stream = initCompressionStream();
        }

        compression_result = compress_body(
            session_data_p->response_data.compression_stream,
            session_data_p->response_data.new_compression_type,
            RESPONSE_BODY,
            is_last_decompressed_part,
            &body_chain,
            NULL,
            request->pool
        );
        if (compression_result != NGX_OK) {
            // Failed to compress body.
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            fini_cp_session_data(session_data_p);
            session_data_p->response_data.response_data_status = NGX_ERROR;
            return fail_mode_verdict == NGX_OK ?
                ngx_http_next_response_body_filter(request, body_chain) :
                NGX_ERROR;
        }

        return ngx_http_next_response_body_filter(request, body_chain);
    }

    if (was_transaction_timedout(session_data_p)) {
        // Session was timed out.
        if (session_data_p->verdict == TRAFFIC_VERDICT_DROP) {
            return NGX_ERROR;
        }
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        fini_cp_session_data(session_data_p);
        return ngx_http_next_response_body_filter(request, body_chain);
    }

    if (is_in_transparent_mode()) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        fini_cp_session_data(session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_body_filter(request, body_chain);
        }
        return NGX_ERROR;
    }

    if (!session_data_p->was_request_fully_inspected) {
        write_dbg(DBG_LEVEL_DEBUG, "Skipping response body of request that was not fully inspected");

        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        updateMetricField(REQ_FAILED_TO_REACH_UPSTREAM, 1);
        session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
        fini_cp_session_data(session_data_p);
        return ngx_http_next_response_body_filter(request, body_chain);
    }

    init_thread_ctx(&ctx, request, session_data_p,
        original_compressed_body == NULL ? body_chain : original_compressed_body);

    write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_res_body_filter_thread");
    // Open threads while unprocessed chain elements still exist, up to num of elements in the chain iterations
    for (chain_elem = ctx.chain; chain_elem != NULL && ctx.chain; chain_elem = chain_elem->next) {
        // Notify if zero-size buf is marked as "memory". This should never happen but if it does we want to know.
        if (chain_elem->buf && chain_elem->buf->pos &&
            (chain_elem->buf->last - chain_elem->buf->pos == 0) && chain_elem->buf->memory == 1) {
            write_dbg(DBG_LEVEL_WARNING,
                "Warning: encountered response body chain element of size 0 with memory flag enabled");
        }
        clock_gettime(CLOCK_REALTIME, &hook_time_begin);
        if (!ngx_cp_run_in_thread_timeout(
            ngx_http_cp_res_body_filter_thread,
            (void*)&ctx,
            res_body_thread_timeout_msec,
            "ngx_http_cp_res_body_filter_thread")
        ) {
            // failed to execute thread task, or it timed out
            session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            fini_cp_session_data(session_data_p);
            write_dbg(
                DBG_LEVEL_DEBUG,
                "res_body_filter thread failed, returning default fail mode verdict. Session id: %d, verdict: %s",
                session_data_p->session_id,
                session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
            );

            updateMetricField(RES_BODY_THREAD_TIMEOUT, 1);
            updateMetricField(AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_res_body_size);
            updateMetricField(MAX_RES_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_res_body_size);
            updateMetricField(MIN_RES_BODY_SIZE_UPON_TIMEOUT, session_data_p->processed_res_body_size);

            if (fail_mode_verdict == NGX_OK) {
                return ngx_http_next_response_body_filter(request, body_chain);
            }
            return NGX_ERROR;
        }
        write_dbg(
            DBG_LEVEL_DEBUG,
            "finished ngx_http_cp_res_body_filter_thread successfully. return=%d next_filter=%d res=%d",
            ctx.should_return,
            ctx.should_return_next_filter,
            ctx.res
        );

        calcProcessingTime(session_data_p, &hook_time_begin, 0);

        if (ctx.should_return) {
            return ctx.res;
        }

        if (ctx.should_return_next_filter) {
            return ngx_http_next_response_body_filter(request, body_chain);
        }
        if (was_transaction_timedout(session_data_p)) {
            session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
            fini_cp_session_data(session_data_p);
            return ngx_http_next_response_body_filter(request, body_chain);
        }
    }

    if (ctx.chain) {
        session_data_p->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        fini_cp_session_data(session_data_p);
        write_dbg(
            DBG_LEVEL_WARNING,
            "Could not complete inspection of all body chain elements, returning default fail mode verdict. "
            "Session id: %d, verdict: %s",
            session_data_p->session_id,
            session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT ? "accept" : "drop"
        );
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_body_filter(request, body_chain);
        }
        return NGX_ERROR;
    }

    final_res = ctx.res;

    if (final_res == NGX_HTTP_FORBIDDEN) {
        handle_inspection_success(session_data_p);
        return ngx_http_cp_finalize_rejected_request(request);
    }

    if (final_res != NGX_OK) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Handling Failure with fail %s mode",
            fail_mode_verdict == NGX_OK ? "open" : "close"
        );
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
        if (fail_mode_verdict == NGX_OK) {
            return ngx_http_next_response_body_filter(request, body_chain);
        }
        return NGX_ERROR;
    }

    if (ctx.modifications) {
        write_dbg(DBG_LEVEL_TRACE, "Handling response body modification");
        if (ngx_http_cp_body_modifier(body_chain, ctx.modifications, request->pool) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to modify response body");

            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            if (fail_mode_verdict == NGX_OK) {
                return ngx_http_next_response_body_filter(request, body_chain);
            }
            return NGX_ERROR;
        }
    }

    if (
        session_data_p->verdict == TRAFFIC_VERDICT_ACCEPT &&
        session_data_p->response_data.num_body_chunk == 1 &&
        !ctx.modifications
    ) {
        session_data_p->response_data.new_compression_type = NO_COMPRESSION;
        if (original_compressed_body) {
            copy_chain_buffers(body_chain, original_compressed_body);
        }
        return ngx_http_next_response_body_filter(request, body_chain);
    }

    if (session_data_p->response_data.new_compression_type != NO_COMPRESSION) {
        if (session_data_p->response_data.compression_stream == NULL) {
            session_data_p->response_data.compression_stream = initCompressionStream();
        }

        compression_result = compress_body(
            session_data_p->response_data.compression_stream,
            session_data_p->response_data.new_compression_type,
            RESPONSE_BODY,
            is_last_decompressed_part,
            &body_chain,
            NULL,
            request->pool
        );
        if (compression_result != NGX_OK) {
            handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, session_data_p);
            session_data_p->response_data.response_data_status = NGX_ERROR;
            fini_cp_session_data(session_data_p);
            return fail_mode_verdict == NGX_OK ?
                ngx_http_next_response_body_filter(request, body_chain) :
                NGX_ERROR;
        }
    }

    return ngx_http_next_response_body_filter(request, body_chain);
}
