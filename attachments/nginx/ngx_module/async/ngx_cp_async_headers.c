#include "ngx_cp_async_headers.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <errno.h>
#include <stddef.h>

#include "ngx_cp_async_core.h"
#include "ngx_cp_async_ctx_validation.h"
#include "ngx_cp_async_sender.h"
#include "../ngx_cp_hooks.h"
#include "../ngx_cp_initializer.h"
#include "../ngx_http_cp_attachment_module.h"
#include "../ngx_cp_utils.h"
#include "../ngx_cp_failing_state.h"
#include "../ngx_cp_metric.h"
#include "../ngx_cp_thread.h"
#include "../ngx_cp_static_content.h"
#include "../ngx_cp_utils.h"
#include "../ngx_cp_custom_response.h"

extern ngx_int_t is_initialized;
extern ngx_int_t should_register_to_nano_service;

ngx_int_t
ngx_http_cp_res_header_filter_async(ngx_http_request_t *request)
{
    ngx_http_cp_session_data *session_data_p;

    if (remove_res_server_header) remove_server_header(request);

    session_data_p = recover_cp_session_data(request);
    if (session_data_p == NULL) {
        write_dbg(DBG_LEVEL_DEBUG, "No session data - passing through to next filter");
        return ngx_http_next_response_header_filter(request);
    }

    set_current_session_id(session_data_p->session_id);

    return ngx_http_cp_res_header_filter_core(request, ASYNC_FILTER);
}

ngx_int_t
ngx_http_cp_req_header_handler_async(ngx_http_request_t *request)
{
    ngx_http_cp_session_data *session_data_p;
    ngx_http_cp_async_ctx_t *ctx;
    ngx_int_t handle_static_resource_result;
    ServiceVerdict sessions_per_minute_verdict;
    ngx_cp_attachment_conf_t *conf;
    ngx_int_t final_res;
    struct timespec hook_time_begin;
    
    static int is_failure_state_initialized = 0;
    static int is_metric_data_initialized = 0;
    
    write_dbg(DBG_LEVEL_DEBUG, "Async request header handler handling a new request");

    clock_gettime(CLOCK_REALTIME, &hook_time_begin);
    if (is_async_mode_enabled && !is_initialized) {
        ngx_cp_async_init();
    }

    if (is_failure_state_initialized == 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Initializing failure state");
        reset_transparent_mode();
        is_failure_state_initialized = 1;
    }
    
    if (is_metric_data_initialized == 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Initializing metric data");
        reset_metric_data();
        is_metric_data_initialized = 1;
    }
    
    set_current_session_id(0);
    reset_dbg_ctx();
    
    if (is_in_transparent_mode()) {
        write_dbg(DBG_LEVEL_DEBUG, "In transparent mode - updating metrics and returning");
        updateMetricField(TRANSPARENTS_COUNT, 1);
        return fail_mode_verdict == NGX_OK ? NGX_DECLINED : NGX_ERROR;
    }
    
    if (is_ngx_cp_attachment_disabled(request)) {
        write_dbg(DBG_LEVEL_DEBUG, "Ignoring inspection of request on a disabled location");
        return NGX_DECLINED;
    }
    
    conf = ngx_http_get_module_loc_conf(request, ngx_http_cp_attachment_module);
    if (conf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to get module configuration");
        return NGX_DECLINED;
    }
    
    session_data_p = ngx_http_get_module_ctx(request, ngx_http_cp_attachment_module);
    if (session_data_p == NULL) {
        write_dbg(DBG_LEVEL_DEBUG, "No existing session data - initializing new session");
        session_data_p = init_cp_session_data(request);
        if (session_data_p == NULL) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to initialize session data");
            return NGX_DECLINED;
        }
    }

    set_current_session_id(session_data_p->session_id);
    write_dbg(DBG_LEVEL_DEBUG, "Async request header filter handling session ID: %d", session_data_p->session_id);
    session_data_p->initial_async_mode = 1;
    if (!is_async_mode_enabled) {
        write_dbg(DBG_LEVEL_WARNING, "Async mode is not enabled for request");
        return NGX_DECLINED;
    }

    sessions_per_minute_verdict = enforce_sessions_rate();
    if (sessions_per_minute_verdict != TRAFFIC_VERDICT_INSPECT) {
        session_data_p->verdict = sessions_per_minute_verdict;
        return sessions_per_minute_verdict == TRAFFIC_VERDICT_ACCEPT ? NGX_DECLINED : NGX_ERROR;
    }

    // Do immediate blocking registration (same as sync version)
    if (!get_already_registered() || !isIpcReady()) {
        struct ngx_http_cp_event_thread_ctx_t ctx;
        int res;
        
        init_thread_ctx(&ctx, request, session_data_p, NULL);
        ctx.waf_tag = conf->waf_tag;

        if (should_register_to_nano_service || is_registration_timeout_reached()) {
            write_dbg(DBG_LEVEL_DEBUG, "spawn ngx_http_cp_registration_thread");
            set_unregistered();
            reset_registration_timeout();
            res = ngx_cp_run_in_thread_timeout(
                ngx_http_cp_registration_thread,
                (void *)&ctx,
                ngx_max(registration_thread_timeout_msec, 200),
                "ngx_http_cp_registration_thread"
            );
            should_register_to_nano_service = 0;
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

            return fail_mode_verdict == NGX_OK ? NGX_DECLINED : fail_mode_verdict;
        }
        write_dbg(
            DBG_LEVEL_DEBUG,
            "finished ngx_http_cp_registration_thread successfully. return=%d res=%d",
            ctx.should_return,
            ctx.res
        );
        if (ctx.should_return) {
            session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
            return ctx.res == NGX_OK ? NGX_DECLINED : ctx.res;
        }

        if (ngx_cp_async_setup_verdict_event_handler() != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to set up verdict event handler for session %d", session_data_p->session_id);
            return fail_mode_verdict == NGX_OK ? NGX_DECLINED : fail_mode_verdict;
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
        return fail_mode_verdict == NGX_OK ? NGX_DECLINED : fail_mode_verdict;
    }

    ctx = ngx_cp_async_find_ctx(session_data_p->session_id);
    if (ctx != NULL) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Found existing async context for session %d - stage: %d, header_declined: %d", 
            session_data_p->session_id,
            ctx->stage, ctx->header_declined
        );
        
        if (ctx->header_declined) {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Header already declined for body processing - returning NGX_DECLINED again for session %d", 
                session_data_p->session_id
            );
            return NGX_DECLINED;
        }
        
        return ngx_cp_async_continue_processing(ctx);
    }
    
    if (
        session_data_p->async_processing_needed == 0
        && (session_data_p->verdict != TRAFFIC_VERDICT_INSPECT || session_data_p->was_request_fully_inspected)
    ) {
        write_dbg(DBG_LEVEL_DEBUG, "Async processing already completed for session %d - allowing to pass through", session_data_p->session_id);
        SAFE_DESTROY_CTX(ctx);
        return NGX_DECLINED;
    }

    
    handle_static_resource_result = handle_static_resource_request(
        session_data_p->session_id,
        &session_data_p->verdict,
        request
    );

    if (handle_static_resource_result != NOT_A_STATIC_RESOURCE) {
        write_dbg(DBG_LEVEL_DEBUG, "Static resource handled - result: %d", handle_static_resource_result);
        return handle_static_resource_result;
    }
    
    ctx = ngx_cp_async_create_ctx(request, session_data_p);
    if (ctx == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to create async context - allowing request to continue");
        return NGX_DECLINED;
    }
    
    ctx->waf_tag.data = conf->waf_tag.data;
    ctx->waf_tag.len = conf->waf_tag.len;
    
    ngx_cp_async_add_ctx(ctx);
    final_res = ngx_cp_async_start_agent_communication(ctx);
    
    session_data_p->async_processing_needed = 1;
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Async processing started with result: %d for session %d", 
        final_res,
        session_data_p->session_id
    );
    
    if (final_res == NGX_AGAIN) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Holding request until verdict received for session %d",
            session_data_p->session_id
        );
        ngx_cp_async_start_deadline_timer(ctx, ngx_max(req_header_thread_timeout_msec, async_header_timeout_ms));
        ctx->waiting = 1;
        
        if (!ctx->request_ref_incremented && ctx->request->http_version == NGX_HTTP_VERSION_20) {
            ctx->request->main->count++;
            ctx->request_ref_incremented = 1;
            write_dbg(DBG_LEVEL_DEBUG, "Incremented request main reference count for HTTP/2 session %d", session_data_p->session_id);
        }
        
        return NGX_DONE;
    } else if (final_res == NGX_DECLINED) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Async processing completed immediately - allowing request to continue for session %d",
            session_data_p->session_id
        );
        return NGX_DECLINED;
    } else {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Async processing failed - fail-open request for session %d",
            session_data_p->session_id
        );
        return final_res;
    }
}
