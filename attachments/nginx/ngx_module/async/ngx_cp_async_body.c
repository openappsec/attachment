#include "ngx_cp_async_body.h"

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
#include "../ngx_cp_utils.h"

ngx_int_t
ngx_http_cp_req_body_filter_async(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_cp_session_data *sd = recover_cp_session_data(r);
    ngx_http_cp_async_ctx_t *ctx;

    write_dbg(DBG_LEVEL_DEBUG, "=== ASYNC REQUEST BODY FILTER START ===");

    print_buffer_chain(in, "outgoing", 32, DBG_LEVEL_TRACE);
    if (!sd->initial_async_mode || (sd->initial_async_mode && !is_async_mode_enabled)) {
        write_dbg(DBG_LEVEL_WARNING, "Async mode not initialized or changed - passing through");
        return ngx_http_next_request_body_filter(r, in);
    }

    if (!isIpcReady() || !sd->async_processing_needed) {
        write_dbg(DBG_LEVEL_DEBUG, "No async processing needed - passing through");
        return ngx_http_next_request_body_filter(r, in);
    }

    ctx = ngx_cp_async_find_ctx(sd->session_id);
    if (!ctx) {
        write_dbg(DBG_LEVEL_DEBUG, "No async ctx; pass-through session %d", sd->session_id);
        return ngx_http_next_request_body_filter(r, in);
    }

    if (sd->verdict != TRAFFIC_VERDICT_INSPECT) {
        write_dbg(DBG_LEVEL_DEBUG, "Request already inspected; applying verdict for session %d", sd->session_id);
        SAFE_DESTROY_CTX(ctx);
        return sd->verdict == TRAFFIC_VERDICT_ACCEPT ? ngx_http_next_request_body_filter(r, in) : NGX_HTTP_FORBIDDEN;
    }

    if (ngx_cp_async_ctx_get_flow_error_safe(ctx)) {
        write_dbg(DBG_LEVEL_DEBUG, "Flow error detected for session %d", ngx_cp_async_ctx_get_session_id_safe(ctx));
        SAFE_DESTROY_CTX(ctx);
        return ngx_http_next_request_body_filter(r, in);
    }

    write_dbg(DBG_LEVEL_DEBUG, "Found async context for session %d - processing body", sd->session_id);

    if (!ctx->body_phase_started){
        r->request_body->filter_need_buffering = 1;
        r->request_body_no_buffering = 0;
        ctx->body_phase_started = 1;
    }

    if (ngx_cp_async_ctx_get_released_safe(ctx) && ngx_cp_async_ctx_get_queue_head_safe(ctx)) {
        write_dbg(DBG_LEVEL_DEBUG, "Agent released; forwarding queued body for session %d", ngx_cp_async_ctx_get_session_id_safe(ctx));
        ngx_int_t rc = ngx_http_next_request_body_filter(r, ctx->queue_head);
        queue_free(r, ctx);
        ctx->queue_head = ctx->queue_tail = NULL;
        SAFE_DESTROY_CTX(ctx);
        return rc;
    }

    if (!ctx->req_seq && ctx->queue_head && !in) {
        write_dbg(DBG_LEVEL_DEBUG, "Forwarding queued body (no new data) for session %d", ctx->session_id);
        ngx_int_t rc = ngx_http_next_request_body_filter(r, ctx->queue_head);
        queue_free(r, ctx);
        ctx->queue_head = ctx->queue_tail = NULL;
        return rc;
    }

    if (in) {
        write_dbg(DBG_LEVEL_DEBUG, "New body chunk received for session %d", ctx->session_id);

        if (chain_add_copy(r, ctx, in) != NGX_OK) {
            write_dbg(DBG_LEVEL_ERROR, "Queue copy failed; session %d", ctx->session_id);
            ctx->session_data->async_processing_needed = 0;
            queue_free(r, ctx);
            ctx->queue_head = ctx->queue_tail = NULL;
            SAFE_DESTROY_CTX(ctx);
            return NGX_ERROR;
        }

        for (ngx_chain_t *cl = in; cl; cl = cl->next) {
            ngx_buf_t *b = cl->buf;
            if (b == NULL) continue;

            ngx_uint_t nmsgs = 0;
            ngx_int_t rc = NGX_OK;
            if (ngx_cp_async_send_single_body_chunk_nonblocking(ctx, cl, &nmsgs) != NGX_OK) {
                write_dbg(DBG_LEVEL_DEBUG, "IPC send failed; fail-safe pass-through session %d", ctx->session_id);
                if (ctx->queue_head) {
                    rc = ngx_http_next_request_body_filter(r, ctx->queue_head);
                    ctx->session_data->async_processing_needed = 0;
                    queue_free(r, ctx);
                    ctx->queue_head = ctx->queue_tail = NULL;
                }
                SAFE_DESTROY_CTX(ctx);
                return rc;
            }
            ctx->req_seq += nmsgs;
            sd->remaining_messages_to_reply += nmsgs;

            if (b->last_buf) {
                if (ngx_cp_async_send_end_transaction_nonblocking(ctx, &nmsgs) != NGX_OK) {
                    write_dbg(DBG_LEVEL_DEBUG, "IPC send failed; fail-safe pass-through session %d", ctx->session_id);
                    if (ctx->queue_head) {
                        rc = ngx_http_next_request_body_filter(r, ctx->queue_head);
                        queue_free(r, ctx);
                        ctx->queue_head = ctx->queue_tail = NULL;
                    }
                    SAFE_DESTROY_CTX(ctx);
                    return rc;
                }
                ctx->req_seen_last = 1;
                ctx->req_seq += nmsgs;
                sd->remaining_messages_to_reply += nmsgs;
                write_dbg(DBG_LEVEL_DEBUG, "Seen last body chunk for session %d", ctx->session_id);
            }
        }
        
        write_dbg(DBG_LEVEL_DEBUG, "Queued body chunk and waiting for verdict; session %d", ctx->session_id);
        if (ctx->req_seen_last == 1) {
            write_dbg(DBG_LEVEL_DEBUG, "Last chunk sent; waiting for release; session %d", ctx->session_id);
            ngx_cp_async_start_deadline_timer(ctx, ngx_max(req_max_proccessing_ms_time, async_body_stage_timeout));
            ctx->waiting  = 1;
            
            if (!ctx->request_ref_incremented && r->http_version == NGX_HTTP_VERSION_20) {
                r->main->count++;
                ctx->request_ref_incremented = 1;
                write_dbg(DBG_LEVEL_DEBUG, "Incremented request main reference count for HTTP/2 session %d", ctx->session_id);
            }
            
            return NGX_DONE;
        }
        return ngx_http_next_request_body_filter(r, NULL);
    }

    write_dbg(DBG_LEVEL_DEBUG, "No new input; pass-through session %d", ctx->session_id);
    return ngx_http_next_request_body_filter(r, in);
}
