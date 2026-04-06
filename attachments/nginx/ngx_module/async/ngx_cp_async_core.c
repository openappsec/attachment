#include "ngx_cp_async_core.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ngx_cp_async_types.h"
#include "ngx_cp_async_ctx_validation.h"
#include "ngx_cp_async_sender.h"
#include "../ngx_cp_hooks.h"
#include "../ngx_cp_utils.h"
#include "../ngx_cp_initializer.h"
#include "../ngx_cp_failing_state.h"
#include "../ngx_cp_metric.h"
#include "../ngx_cp_io.h"
#include "../ngx_cp_static_content.h"
#include "../ngx_http_cp_attachment_module.h"
#include "../ngx_cp_thread.h"

#define CP_ASYNC_CTX_BUCKETS 2048 ///< Hash table buckets for better distribution

static ngx_http_cp_async_ctx_t *ctx_buckets[CP_ASYNC_CTX_BUCKETS] = {NULL};
ngx_uint_t context_count = 0;

static ngx_uint_t pending_inspection_chunks = 0;
static ngx_event_t backpressure_drain_event;
static ngx_event_t async_cleanup_event;
static ngx_int_t backpressure_event_initialized = 0;
static ngx_int_t cleanup_event_initialized = 0;

// Event-driven IPC infrastructure
static ngx_connection_t *ipc_verdict_conn = NULL; // Connection obtained via ngx_get_connection

// Global epoll instance for backpressure handling (created once, reused)
static int g_backpressure_epoll_fd = -1;
static int g_backpressure_registered_socket = -1;  ///< Track which socket is registered

ngx_int_t should_register_to_nano_service = 1;
ngx_int_t is_initialized = 0;
ngx_uint_t async_backpressure_threshold = 10;
ngx_msec_t async_header_timeout_ms = 1000; // Default 1s for headers/meta_data/end_transaction
ngx_msec_t async_body_stage_timeout = 5000; // Default 5s for body stage
ngx_msec_t async_wait_verdict_timeout_ms = 50; // Default 50ms for wait verdict polling
ngx_msec_t async_signal_timeout_ms = 10; // Default 10ms for service signal timeout
ngx_msec_t async_context_cleanup_timeout_ms = 300000; // Default 5 minutes for context cleanup

// forward declaration
static ngx_int_t ngx_cp_async_handle_wait_verdict(ngx_http_cp_async_ctx_t *ctx, const char *stage_name);
static void ngx_cp_async_verdict_event_handler(ngx_event_t *ev);
static void ngx_cp_async_transition_after_wait(ngx_http_cp_async_ctx_t *ctx);
static void cp_async_posted_resume(ngx_http_request_t *r);
static void cp_async_resume_event_handler(ngx_event_t *ev);
static void cp_async_post_request(ngx_http_cp_async_ctx_t *ctx);
static void ngx_cp_async_context_cleanup_handler(ngx_event_t *ev);
static void ngx_cp_async_backpressure_drain_handler(ngx_event_t *ev);
static void ngx_cp_async_cleanup_handler(ngx_event_t *ev);
static void ngx_cp_async_cleanup_impl(void);
static void ngx_cp_async_cancel_deadline_timer(ngx_http_cp_async_ctx_t *ctx);
static ngx_int_t drain_ipc_queue(ngx_uint_t *verdicts_drained);
static ngx_int_t is_verdict_final(ServiceVerdict verdict);
static ngx_int_t ngx_cp_async_apply_verdict_for_stage(ngx_http_cp_async_ctx_t *ctx);
static ngx_int_t ngx_cp_async_apply_verdict(ngx_http_cp_async_ctx_t *ctx, HttpReplyFromService *reply_p);
static ssize_t drain_comm_socket_fully(int sock);
static ngx_int_t is_verdict_drop_or_custom(ServiceVerdict verdict);

///
/// @brief Increment the global pending inspection chunks counter
/// @param[in] session_id Session ID for logging purposes
/// @param[in] chunk_type Description of chunk type being sent
///
void
ngx_cp_async_increment_pending_chunks(uint32_t session_id, const char *chunk_type)
{
    pending_inspection_chunks++;
    write_dbg(DBG_LEVEL_DEBUG, "Incremented pending chunks to %d for session %d (%s)", 
              pending_inspection_chunks, session_id, chunk_type);
    
    if (
        pending_inspection_chunks >= async_backpressure_threshold && 
        backpressure_event_initialized && 
        !backpressure_drain_event.posted &&
        nano_service_ipc != NULL
    ) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Backpressure threshold %d reached (%d pending chunks) - posting drain event", 
            async_backpressure_threshold,
            pending_inspection_chunks
        );
        ngx_post_event(&backpressure_drain_event, &ngx_posted_events);
    }
}

///
/// @brief Decrement the global pending inspection chunks counter
/// @param[in] session_id Session ID for logging purposes
/// @param[in] verdict_type Description of verdict type being processed
///
void
ngx_cp_async_decrement_pending_chunks(uint32_t session_id, const char *verdict_type)
{
    if (pending_inspection_chunks > 0) {
        pending_inspection_chunks--;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Decremented pending chunks to %d for session %d (%s)", 
            pending_inspection_chunks,
            session_id,
            verdict_type
        );
    } else {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Attempted to decrement pending chunks below zero for session %d (%s)",
            session_id,
            verdict_type
        );
    }
}

///
/// @brief Post backpressure drain event if conditions are met
///
void
ngx_cp_async_post_backpressure_drain_event(void)
{
    if (backpressure_event_initialized && !backpressure_drain_event.posted && nano_service_ipc != NULL) {
        ngx_post_event(&backpressure_drain_event, &ngx_posted_events);
    }
}

///
/// @brief Reset the global pending inspection chunks counter
///
static inline void
ngx_cp_async_reset_pending_chunks(void)
{
    if (pending_inspection_chunks > 0) {
        write_dbg(
            DBG_LEVEL_INFO,
            "Resetting pending chunks from %d to 0 (IPC disconnect/reset)",
            pending_inspection_chunks
        );

        if (backpressure_event_initialized && backpressure_drain_event.posted) {
            ngx_delete_posted_event(&backpressure_drain_event);
            write_dbg(DBG_LEVEL_INFO, "Backpressure: cancelled pending drain event due to reset");
        }
    }
    pending_inspection_chunks = 0;
}

#define ASYNC_STAGE_TRANSITION(ctx, new_stage) do { \
    if ((new_stage) == NGX_CP_ASYNC_STAGE_COMPLETE) { \
        if (ctx->deadline_event.timer_set) { \
            ngx_del_timer(&ctx->deadline_event); \
            write_dbg(DBG_LEVEL_DEBUG, "Auto-cancelled deadline timer during transition to complete for session %d", ctx->session_id); \
        } \
        if (ctx->cleanup_event.timer_set) { \
            ngx_del_timer(&ctx->cleanup_event); \
            write_dbg(DBG_LEVEL_DEBUG, "Auto-cancelled cleanup timer during transition to complete for session %d", ctx->session_id); \
        } \
        if (ctx->agent_event.timer_set) { \
            ngx_del_timer(&ctx->agent_event); \
            write_dbg(DBG_LEVEL_DEBUG, "Auto-cancelled agent signal timer during transition to complete for session %d", ctx->session_id); \
        } \
    } \
    ctx->stage = new_stage; \
} while(0)

///
/// @brief Hash function for session IDs using Knuth's multiplicative method
/// @param[in] session_id Session ID to hash
/// @return Hash bucket index
///
static ngx_uint_t
cp_async_ctx_hash(uint32_t session_id)
{
    // Knuth's multiplicative hash with golden ratio constant
    static const uint32_t KNUTH_CONSTANT = 2654435761U; // (sqrt(5) - 1) / 2 * 2^32
    return (session_id * KNUTH_CONSTANT) % CP_ASYNC_CTX_BUCKETS;
}

///
/// @brief Initialize async timeout configuration from environment variables
///
static void ngx_cp_async_init_timeout_config(void) {
    char *env_value;
    
    env_value = getenv("CP_ASYNC_HEADER_TIMEOUT_MS");
    if (env_value != NULL) {
        ngx_uint_t timeout = (ngx_uint_t)atoi(env_value);
        if (timeout >= 100 && timeout <= 30000) { // 100ms to 30s range
            async_header_timeout_ms = (ngx_msec_t)timeout;
            write_dbg(DBG_LEVEL_INFO, "Header timeout configuration set to %dms from environment", async_header_timeout_ms);
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Invalid header timeout %d from environment, using default %dms", timeout, async_header_timeout_ms);
        }
    }
    
    env_value = getenv("CP_ASYNC_WAIT_VERDICT_TIMEOUT_MS");
    if (env_value != NULL) {
        ngx_uint_t timeout = (ngx_uint_t)atoi(env_value);
        if (timeout >= 50 && timeout <= 10000) { // 50ms to 10s range
            async_wait_verdict_timeout_ms = (ngx_msec_t)timeout;
            write_dbg(DBG_LEVEL_INFO, "Wait verdict timeout configuration set to %dms from environment", async_wait_verdict_timeout_ms);
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Invalid wait verdict timeout %d from environment, using default %dms", timeout, async_wait_verdict_timeout_ms);
        }
    }
        
    env_value = getenv("CP_ASYNC_BODY_STAGE_TIMEOUT_MS");
    if (env_value != NULL) {
        ngx_uint_t timeout = (ngx_uint_t)atoi(env_value);
        if (timeout >= 1000 && timeout <= 600000) { // 1s to 10min range
            async_body_stage_timeout = (ngx_msec_t)timeout;
            write_dbg(DBG_LEVEL_INFO, "Body stage timeout configuration set to %dms from environment", async_body_stage_timeout);
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Invalid body stage timeout %d from environment, using default %dms", timeout, async_body_stage_timeout);
        }
    }
    
    env_value = getenv("CP_ASYNC_CONTEXT_CLEANUP_TIMEOUT_MS");
    if (env_value != NULL) {
        ngx_uint_t timeout = (ngx_uint_t)atoi(env_value);
        if (timeout >= 10000 && timeout <= 300000) {
            async_context_cleanup_timeout_ms = (ngx_msec_t)timeout;
            write_dbg(DBG_LEVEL_INFO, "Context cleanup timeout configuration set to %dms from environment", async_context_cleanup_timeout_ms);
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Invalid context cleanup timeout %d from environment, using default %dms", timeout, async_context_cleanup_timeout_ms);
        }
    }

    env_value = getenv("CP_ASYNC_SIGNAL_TIMEOUT_MS");
    if (env_value != NULL) {
        ngx_uint_t timeout = (ngx_uint_t)atoi(env_value);
        if (timeout >= 1 && timeout <= 1000) { // 1ms to 1s range
            async_signal_timeout_ms = (ngx_msec_t)timeout;
            write_dbg(DBG_LEVEL_INFO, "Signal timeout configuration set to %dms from environment", async_signal_timeout_ms);
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Invalid signal timeout %d from environment, using default %dms", timeout, async_signal_timeout_ms);
        }
    }

    write_dbg(
        DBG_LEVEL_INFO,
        "Timeout configuration summary: header=%dms, wait_verdict=%dms, first_wait_verdict=%dms, signal=%dms, context_cleanup=%dms", 
        async_header_timeout_ms,
        async_wait_verdict_timeout_ms,
        req_max_proccessing_ms_time,
        async_signal_timeout_ms,
        async_context_cleanup_timeout_ms
    );
}

ngx_int_t
ngx_cp_async_setup_verdict_event_handler(void)
{
    if (comm_socket < 0) {
        write_dbg(DBG_LEVEL_ERROR, "Cannot set up verdict event handler - communication socket unavailable after re-initialization");
        return NGX_ERROR;
    }

    // If there is a stale managed connection, free it before recreating
    if (ipc_verdict_conn) {
        write_dbg(DBG_LEVEL_INFO, "Cleaning up stale verdict event handler (fd: %d)", ipc_verdict_conn->fd);
        if (ipc_verdict_conn->read && ipc_verdict_conn->read->active) {
            ngx_del_event(ipc_verdict_conn->read, NGX_READ_EVENT, 0);
        }
        ngx_free_connection(ipc_verdict_conn);
        ipc_verdict_conn = NULL;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Setting up verdict event handler for communication socket %d", comm_socket);
    
    if (ngx_nonblocking(comm_socket) != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to set communication socket as nonblocking");
        return NGX_ERROR;
    }

    ngx_connection_t *c = ngx_get_connection(comm_socket, ngx_cycle ? ngx_cycle->log : NULL);
    if (c == NULL) {
        write_dbg(DBG_LEVEL_ERROR, "Failed to get connection for verdict socket %d", comm_socket);
        return NGX_ERROR;
    }

    ngx_event_t *rev = c->read;
    rev->handler = ngx_cp_async_verdict_event_handler;
    rev->data = c;
    rev->log = ngx_cycle ? ngx_cycle->log : NULL;
    rev->cancelable = 1;

    if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
        write_dbg(DBG_LEVEL_ERROR, "Failed to add verdict event to event system");
        ngx_free_connection(c);
        return NGX_ERROR;
    }

    ipc_verdict_conn = c;
    write_dbg(DBG_LEVEL_INFO, "Added verdict notification socket %d to event system", comm_socket);
    return NGX_OK;
}

void
disable_ipc_verdict_event_handler()
{
    if (ipc_verdict_conn) {
        if (ipc_verdict_conn->read && ipc_verdict_conn->read->active) {
            ngx_del_event(ipc_verdict_conn->read, NGX_READ_EVENT, 0);
            write_dbg(DBG_LEVEL_INFO, "Disabled verdict event handler for socket %d", ipc_verdict_conn->fd);
        }
        ngx_free_connection(ipc_verdict_conn);
        ipc_verdict_conn = NULL;
    }
    ngx_cp_async_reset_pending_chunks();

    ngx_cp_async_cleanup();

    should_register_to_nano_service = 1;
}

void
enable_ipc_verdict_event_handler()
{
    ngx_cp_async_setup_verdict_event_handler();
    ngx_cp_async_reset_pending_chunks();
}

ngx_int_t
ngx_cp_async_init()
{
    if (is_initialized) {
        write_dbg(DBG_LEVEL_INFO, "Async system already initialized - skipping re-initialization");
        return NGX_OK;
    }
    is_initialized = 1;
    ngx_uint_t i;
        
    write_dbg(DBG_LEVEL_INFO, "Initializing event-driven async system");
    
    ngx_cp_async_init_timeout_config();
    
    for (i = 0; i < CP_ASYNC_CTX_BUCKETS; i++) {
        ctx_buckets[i] = NULL;
    }
    context_count = 0;
    
    ngx_cp_async_reset_pending_chunks();
    
    if (!backpressure_event_initialized) {
        ngx_memzero(&backpressure_drain_event, sizeof(ngx_event_t));
        backpressure_drain_event.handler = ngx_cp_async_backpressure_drain_handler;
        backpressure_drain_event.data = NULL;
        backpressure_drain_event.log = ngx_cycle ? ngx_cycle->log : NULL;
        backpressure_drain_event.cancelable = 1;
        backpressure_event_initialized = 1;
        write_dbg(DBG_LEVEL_INFO, "Initialized drain event with threshold %d", async_backpressure_threshold);
    }
    
    if (!cleanup_event_initialized) {
        ngx_memzero(&async_cleanup_event, sizeof(ngx_event_t));
        async_cleanup_event.handler = ngx_cp_async_cleanup_handler;
        async_cleanup_event.data = NULL;
        async_cleanup_event.log = ngx_cycle ? ngx_cycle->log : NULL;
        async_cleanup_event.cancelable = 1;
        cleanup_event_initialized = 1;
        write_dbg(DBG_LEVEL_DEBUG, "Initialized cleanup event");
    }
    
    if (g_backpressure_epoll_fd < 0) {
        g_backpressure_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (g_backpressure_epoll_fd < 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to create global epoll fd: %s", strerror(errno));
        } else {
            write_dbg(DBG_LEVEL_INFO, "Created global epoll fd %d", g_backpressure_epoll_fd);
        }
        g_backpressure_registered_socket = -1;
    }
    
    if (ipc_verdict_conn) {
        if (ipc_verdict_conn->read && ipc_verdict_conn->read->active) {
            ngx_del_event(ipc_verdict_conn->read, NGX_READ_EVENT, 0);
        }
        ngx_free_connection(ipc_verdict_conn);
        ipc_verdict_conn = NULL;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Initialization: comm_socket=%d during initialization", comm_socket);

    if (comm_socket >= 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Setting up communication socket %d for async notifications during init", comm_socket);
        if (ngx_cp_async_setup_verdict_event_handler() == NGX_OK) {
            write_dbg(DBG_LEVEL_DEBUG, "Successfully set up verdict event handler during initialization");
        } else {
            write_dbg(DBG_LEVEL_WARNING, "Failed to set up verdict event handler during initialization");
        }
    } else {
        write_dbg(DBG_LEVEL_WARNING, "Communication socket not available during initialization - will set up later");
    }

    write_dbg(DBG_LEVEL_INFO, "Event-driven async system initialized successfully");
    return NGX_OK;
}

static void
ngx_cp_async_cancel_timers(ngx_http_cp_async_ctx_t *ctx)
{
    write_dbg(DBG_LEVEL_DEBUG, "Cancelling timers for session %d", ctx->session_id);

    if (ctx->agent_event.timer_set) {
        ngx_del_timer(&ctx->agent_event);
    }
    if (ctx->cleanup_event.timer_set) {
        ngx_del_timer(&ctx->cleanup_event);
    }
    if (ctx->resume_event.timer_set) {
        ngx_del_timer(&ctx->resume_event);
    }
    if (ctx->agent_event.posted) {
        ngx_delete_posted_event(&ctx->agent_event);
    }
    if (ctx->cleanup_event.posted) {
        ngx_delete_posted_event(&ctx->cleanup_event);
    }
    if (ctx->resume_event.posted) {
        ngx_delete_posted_event(&ctx->resume_event);
    }

    ngx_cp_async_cancel_deadline_timer(ctx);
}

static void
ngx_cp_async_cleanup_handler(ngx_event_t *ev)
{
    (void)ev;
    ngx_cp_async_cleanup_impl();
}

static void
ngx_cp_async_cleanup_impl()
{
    ngx_uint_t i;
    ngx_http_cp_async_ctx_t *ctx, *next;

    write_dbg(DBG_LEVEL_DEBUG, "Cleaning up event-driven async system");

    if (ipc_verdict_conn) {
        if (ipc_verdict_conn->read && ipc_verdict_conn->read->active) {
            ngx_del_event(ipc_verdict_conn->read, NGX_READ_EVENT, 0);
        }
        ngx_free_connection(ipc_verdict_conn);
        ipc_verdict_conn = NULL;
        write_dbg(DBG_LEVEL_DEBUG, "Removed verdict event/connection from event system");
    }
    
    for (i = 0; i < CP_ASYNC_CTX_BUCKETS; i++) {
        ctx = ctx_buckets[i];
        while (ctx != NULL) {
            next = ctx->map_next;
            
            if (ngx_cp_async_ctx_is_valid(ctx)) {
                ngx_http_request_t *request = ngx_cp_async_ctx_get_request_safe(ctx);
                request->keepalive = 0;
                ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                ctx->session_data->remaining_messages_to_reply = 0;
                ctx->session_data->async_processing_needed = 0;
                ctx->header_declined = 1;
                ctx->req_seq = 0;

                ngx_cp_async_cancel_timers(ctx);

                if (ngx_cp_async_ctx_get_stage_safe(ctx) == NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT) {
                    ctx->stage = NGX_CP_ASYNC_STAGE_BODY;
                }

                if (ngx_cp_async_ctx_get_stage_safe(ctx) != NGX_CP_ASYNC_STAGE_BODY) {
                    ctx->flow_error = 1;
                    ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                }
 
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "Releasing session %d with verdict %d (fail_mode=%s)", 
                    ctx->session_id, 
                    ctx->session_data->verdict,
                    fail_mode_verdict == NGX_OK ? "open" : "closed"
                );

                ngx_cp_async_event_handler(&ctx->agent_event);
                ctx->flow_error = 1;
            } else {
                write_dbg(DBG_LEVEL_DEBUG, "Cleaning up async context for session %d", ctx->session_id);
                SAFE_DESTROY_CTX(ctx);
            }
            ctx = next;
        }
    }
    context_count = 0;
    
    ngx_cp_async_reset_pending_chunks();
    
    if (backpressure_event_initialized) {
        if (backpressure_drain_event.posted) {
            ngx_delete_posted_event(&backpressure_drain_event);
        }
        backpressure_event_initialized = 0;
        write_dbg(DBG_LEVEL_DEBUG, "Cleaned up drain event");
    }
    
    if (cleanup_event_initialized) {
        if (async_cleanup_event.posted) {
            ngx_delete_posted_event(&async_cleanup_event);
        }
        cleanup_event_initialized = 0;
        write_dbg(DBG_LEVEL_DEBUG, "Cleaned up posted cleanup event");
    }
    
    if (g_backpressure_epoll_fd >= 0) {
        close(g_backpressure_epoll_fd);
        g_backpressure_epoll_fd = -1;
        g_backpressure_registered_socket = -1;
        write_dbg(DBG_LEVEL_DEBUG, "Closed global epoll fd");
    }
    
    is_initialized = 0;
    write_dbg(DBG_LEVEL_DEBUG, "Event-driven async system cleanup complete");
}

void
ngx_cp_async_cleanup()
{
    if (cleanup_event_initialized && !async_cleanup_event.posted) {
        ngx_post_event(&async_cleanup_event, &ngx_posted_events);
    }
}

ngx_http_cp_async_ctx_t *
ngx_cp_async_create_ctx(ngx_http_request_t *request, ngx_http_cp_session_data *session_data)
{
    ngx_http_cp_async_ctx_t *ctx;
    ngx_pool_cleanup_t *cln;
    
    if (request == NULL || session_data == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Invalid parameters for async context creation");
        return NULL;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Creating simplified async context for session %d", session_data->session_id);
    
    ctx = ngx_pcalloc(request->pool, sizeof(ngx_http_cp_async_ctx_t));
    if (ctx == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate async context");
        return NULL;
    }
    
    ctx->request = request;
    ctx->session_data = session_data;
    ctx->session_id = session_data->session_id;
    ctx->stage = NGX_CP_ASYNC_STAGE_INIT;
    ctx->modifications = NULL;
    ctx->map_next = NULL;
    
    ctx->req_seen_last = 0;
    ctx->req_seq = 0;
    ctx->waiting = 0;
    ctx->released = 0;
    ctx->body_phase_started = 0;
    ctx->queue_head = NULL;
    ctx->queue_tail = NULL;

    ctx->meta_data_sent = 0;
    ctx->headers_sent = 0;
    ctx->end_transaction_sent = 0;
    ctx->header_declined = 0;
    
    ctx->waf_tag.data = NULL;
    ctx->waf_tag.len = 0;
    ctx->first_wait_verdict_encountered = 0;
    ctx->flow_error = 0;
    ctx->request_ref_incremented = 0;
    
    ngx_memzero(&ctx->agent_event, sizeof(ngx_event_t));
    ctx->agent_event.handler = ngx_cp_async_event_handler;
    ctx->agent_event.data = ctx;
    ctx->agent_event.log = request->connection->log;
    ctx->agent_event.cancelable = 1;

    ngx_memzero(&ctx->cleanup_event, sizeof(ngx_event_t));
    ctx->cleanup_event.handler = ngx_cp_async_context_cleanup_handler;
    ctx->cleanup_event.data = ctx;
    ctx->cleanup_event.log = request->connection->log;
    ctx->cleanup_event.cancelable = 1;

    ngx_memzero(&ctx->resume_event, sizeof(ngx_event_t));
    ctx->resume_event.handler = cp_async_resume_event_handler;
    ctx->resume_event.data = ctx;
    ctx->resume_event.log = request->connection->log;
    ctx->resume_event.cancelable = 1;
    
    cln = ngx_pool_cleanup_add(request->pool, 0);
    if (cln == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to add cleanup handler for async context");
        return NULL;
    }
    
    cln->handler = (ngx_pool_cleanup_pt) ngx_cp_async_destroy_ctx;
    cln->data = ctx;
    
    clock_gettime(CLOCK_REALTIME, &ctx->start_time);
    
    ngx_add_timer(&ctx->cleanup_event, async_context_cleanup_timeout_ms);
    
    write_dbg(DBG_LEVEL_DEBUG, "Simplified async context created successfully for session %d with %dms cleanup timeout", 
              session_data->session_id, async_context_cleanup_timeout_ms);
    
    write_dbg(DBG_LEVEL_DEBUG, "Context cleanup timer started for session %d - will trigger in %dms", 
              session_data->session_id, async_context_cleanup_timeout_ms);
    
    return ctx;
}

void
ngx_cp_async_destroy_ctx(ngx_http_cp_async_ctx_t *ctx)
{
    uint32_t session_id;
    
    if (ctx == NULL) {
        return;
    }
    
    session_id = ctx->session_id;
    
    write_dbg(DBG_LEVEL_DEBUG, "Destroying async context for session %d", session_id);

    ngx_cp_async_nullify_ctx_refs(ctx);
    ngx_cp_async_cancel_timers(ctx);
    ngx_cp_async_remove_ctx(ctx);

    write_dbg(DBG_LEVEL_DEBUG, "Simplified async context destroyed for session %d", session_id);
}

ngx_http_cp_async_ctx_t *
ngx_cp_async_find_ctx(uint32_t session_id)
{
    ngx_uint_t bucket = cp_async_ctx_hash(session_id);
    ngx_http_cp_async_ctx_t *ctx = ctx_buckets[bucket];
    
    while (ctx != NULL) {
        if (ctx->session_id == session_id) {
            return ctx;
        }
        ctx = ctx->map_next;
    }
    
    return NULL;
}

ngx_int_t
ngx_cp_async_add_ctx(ngx_http_cp_async_ctx_t *ctx)
{
    ngx_uint_t bucket;
    
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    
    bucket = cp_async_ctx_hash(ctx->session_id);
    
    ctx->map_next = ctx_buckets[bucket];
    
    ctx_buckets[bucket] = ctx;
    context_count++;
    
    write_dbg(DBG_LEVEL_DEBUG, "Added async context to hash bucket %d for session %d", bucket, ctx->session_id);
    return NGX_OK;
}

void
ngx_cp_async_remove_ctx(ngx_http_cp_async_ctx_t *ctx)
{
    ngx_uint_t bucket;
    ngx_http_cp_async_ctx_t *current, *prev;
    
    if (ctx == NULL) {
        return;
    }
    
    bucket = cp_async_ctx_hash(ctx->session_id);
    current = ctx_buckets[bucket];
    prev = NULL;
    
    while (current != NULL) {
        if (current == ctx) {
            if (prev == NULL) {
                ctx_buckets[bucket] = current->map_next;
            } else {
                prev->map_next = current->map_next;
            }
            context_count--;
            write_dbg(DBG_LEVEL_DEBUG, "Removed async context from hash bucket %d for session %d", bucket, ctx->session_id);
            return;
        }
        prev = current;
        current = current->map_next;
    }
}

///
/// @brief Generic wait verdict handler for all wait stages
/// @param[in] ctx Async context
/// @param[in] stage_name Stage name for logging
/// @return NGX_OK, NGX_AGAIN, NGX_HTTP_FORBIDDEN, or NGX_ERROR
///
static ngx_int_t
ngx_cp_async_handle_wait_verdict(ngx_http_cp_async_ctx_t *ctx, const char *stage_name)
{
    ngx_uint_t num_messages_sent = 0;
    ngx_int_t rc;
    uint32_t session_id;
    ngx_http_cp_session_data *session_data;
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    if (session_id == 0) {
        write_dbg(DBG_LEVEL_ERROR, "Handle wait verdict: invalid session ID for %s", stage_name);
        return NGX_ERROR;
    }
    
    session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    if (session_data == NULL) {
        write_dbg(DBG_LEVEL_ERROR, "Handle wait verdict: invalid session data for %s session %d", stage_name, session_id);
        return NGX_ERROR;
    }
    
    if (ngx_cp_async_ctx_get_flow_error_safe(ctx)) {
        write_dbg(DBG_LEVEL_ERROR, "Flow error flag set, skipping wait verdict for %s", stage_name);
        session_data->verdict = fail_mode_hold_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        updateMetricField(HOLD_THREAD_TIMEOUT, 1);
        ctx->session_data->remaining_messages_to_reply = 0;
        ctx->session_data->async_processing_needed = 0;
        ctx->header_declined = 1;
        ctx->req_seq = 0;
        ngx_cp_async_cancel_timers(ctx);
        ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_BODY);
        ngx_cp_async_event_handler(&ctx->agent_event);
        return NGX_AGAIN;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Polling for %s verdict update for session %d", 
        stage_name,
        session_id
    );
    
    if (session_data->verdict != TRAFFIC_VERDICT_DELAYED) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "%s verdict resolved to %d for session %d - processing immediately",
            stage_name,
            session_data->verdict,
            session_id
        );

        ngx_cp_async_transition_after_wait(ctx);
        ngx_cp_async_event_handler(&ctx->agent_event);
        return NGX_AGAIN;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "%s verdict still WAIT for session %d - continuing to wait", 
        stage_name,
        session_id
    );
    
    rc = ngx_cp_async_wait_signal_sender(ctx, &num_messages_sent);
    if (rc != NGX_OK && rc != NGX_HTTP_REQUEST_TIME_OUT) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send %s wait signal for session %d", stage_name, session_id);
        session_data->verdict = fail_mode_hold_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        updateMetricField(HOLD_THREAD_TIMEOUT, 1);
        ctx->session_data->remaining_messages_to_reply = 0;
        ctx->session_data->async_processing_needed = 0;
        ctx->header_declined = 1;
        ctx->req_seq = 0;
        ngx_cp_async_cancel_timers(ctx);
        ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_BODY);
        ngx_cp_async_event_handler(&ctx->agent_event);
        return NGX_AGAIN;
    }

    ngx_add_timer(&ctx->agent_event, async_wait_verdict_timeout_ms);
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Scheduled next %s verdict check in %dms for session %d",
        stage_name,
        async_wait_verdict_timeout_ms,
        session_id
    );

    return NGX_AGAIN;
}

///
/// @brief Helper function to transition to next stage after wait verdict resolves
/// @param[in] ctx Async context
///
static void
ngx_cp_async_transition_after_wait(ngx_http_cp_async_ctx_t *ctx)
{
    uint32_t session_id;
    ngx_http_cp_session_data *session_data;
    ngx_cp_async_stage_t stage;
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    if (session_id == 0) {
        write_dbg(DBG_LEVEL_ERROR, "Transition after wait: invalid session ID");
        return;
    }
    
    if (ngx_cp_async_ctx_get_flow_error_safe(ctx)) {
        write_dbg(DBG_LEVEL_ERROR, "Flow error flag set, skipping transition after wait");
        return;
    }
    
    session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    if (session_data == NULL) {
        write_dbg(DBG_LEVEL_ERROR, "Transition after wait: invalid session data for session %d", session_id);
        return;
    }
    
    if (session_data->verdict == TRAFFIC_VERDICT_DELAYED) {
        write_dbg(DBG_LEVEL_DEBUG, "Still in WAIT verdict - no stage transition for session %d", session_id);
        return;
    }
    
    stage = ngx_cp_async_ctx_get_stage_safe(ctx);
    switch (stage) {
        case NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT:
            if (is_verdict_drop_or_custom(session_data->verdict)) {
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
            } else {
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_END_TRANSACTION);
            }
            break;
            
        case NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT:
            if (ctx->body_phase_started) {
                write_dbg(DBG_LEVEL_DEBUG, "Transitioning to BODY stage for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_BODY);
            } else {
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
            }
            break;
            
        case NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT:
            if (is_verdict_drop_or_custom(session_data->verdict)) {
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
            } else {
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_BODY);
            }
            break;            
        default:
            write_dbg(DBG_LEVEL_WARNING, "Unknown wait stage %d for session %d", stage, session_id);
            ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
            break;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Transitioned to stage %d after wait verdict for session %d",
        ngx_cp_async_ctx_get_stage_safe(ctx),
        session_id
    );
}

void
ngx_cp_async_event_handler(ngx_event_t *ev)
{
    ngx_http_cp_async_ctx_t *ctx;
    ngx_int_t rc;
    uint32_t session_id;
    
    ctx = (ngx_http_cp_async_ctx_t *) ev->data;
    
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Event handler called with invalid/destroyed context - ignoring");
        return;
    }
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    if (session_id == 0) {
        write_dbg(DBG_LEVEL_WARNING, "Event handler: invalid session ID - ignoring");
        return;
    }

    ngx_cp_async_stage_t stage = ngx_cp_async_ctx_get_stage_safe(ctx);
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Entered main event handler for session %u, stage %d (load: %d)", 
        session_id,
        (int)stage,
        context_count
    );

    set_current_session_id(session_id);
    rc = ngx_cp_async_continue_processing(ctx);
    write_dbg(DBG_LEVEL_DEBUG, "Stage processing returned: %d for session %d", rc, session_id);
    
    if (rc == NGX_AGAIN) {
        write_dbg(DBG_LEVEL_DEBUG, "Stage processing yielded - expecting further events for session %d", session_id);
        return;
    }

    ngx_http_request_t *request = ngx_cp_async_ctx_get_request_safe(ctx);
    if (request == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Event handler: invalid request for session %d - cannot finalize", session_id);
        return;
    }

    ngx_http_cp_session_data *session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    ServiceVerdict verdict = session_data ? session_data->verdict : TRAFFIC_VERDICT_ACCEPT;
    
    if (is_verdict_drop_or_custom(verdict)) {
        write_dbg(DBG_LEVEL_DEBUG, "Request blocked - dropping session %d", session_id);            
        request->keepalive = 0;
        SAFE_DESTROY_CTX(ctx);
        ctx = NULL;
        ngx_http_cp_finalize_rejected_request(request, 0);
    } else if (rc == NGX_DECLINED) {
        ngx_cp_async_cancel_deadline_timer(ctx);
        ngx_int_t is_waiting = ctx->waiting;
        if (stage == NGX_CP_ASYNC_STAGE_COMPLETE) {
            SAFE_DESTROY_CTX(ctx);
            ctx = NULL;
        }

        if (is_waiting) {
            write_dbg(DBG_LEVEL_DEBUG, "Resuming session %d", session_id);
            if (ctx) {
                ctx->waiting = 0;
            }

            ngx_http_core_run_phases(request);
        }
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Event handler complete for session %d", session_id);
}

///
/// @brief Deadline timeout handler - triggers fail-safe when stage deadline is exceeded
/// @param[in] ev Deadline timeout event  
///
static void
ngx_cp_async_deadline_handler(ngx_event_t *ev)
{
    ngx_http_cp_async_ctx_t *ctx;
    const char *stage_name;
    ngx_int_t verdict_to_apply;
    ngx_int_t fail_mode_to_use;
    uint32_t session_id;
    ngx_cp_async_stage_t stage;
    
    ctx = (ngx_http_cp_async_ctx_t *) ev->data;
    
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Deadline timer fired for invalid/destroyed context - ignoring stale timer");
        return;
    }
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    stage = ngx_cp_async_ctx_get_stage_safe(ctx);
    
    if (stage == NGX_CP_ASYNC_STAGE_COMPLETE) {
        write_dbg(DBG_LEVEL_WARNING, "Deadline timer fired for session %d already in COMPLETE stage - ignoring stale timer", session_id);
        return;
    }
    
    if (ngx_cp_async_ctx_get_flow_error_safe(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Deadline timer fired for session %d with flow error flag set - ignoring", session_id);
        return;
    }
    
    switch (stage) {
        case NGX_CP_ASYNC_STAGE_META_DATA:
            stage_name = "meta-data"; 
            fail_mode_to_use = fail_mode_verdict;
            break;
        case NGX_CP_ASYNC_STAGE_HEADERS:
        case NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT:
            stage_name = "headers"; 
            fail_mode_to_use = (stage == NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT) ? 
                               fail_mode_hold_verdict
                               : fail_mode_verdict;
            break;
        case NGX_CP_ASYNC_STAGE_END_TRANSACTION:
        case NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT:
            stage_name = "end-transaction"; 
            fail_mode_to_use = (stage == NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT) ? 
                               fail_mode_hold_verdict
                               : fail_mode_verdict;
            break;
        case NGX_CP_ASYNC_STAGE_BODY:
            stage_name = "body";
            fail_mode_to_use = fail_mode_verdict;
            break;
        case NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT:
            stage_name = "body";
            fail_mode_to_use = fail_mode_hold_verdict;
            break;
        default:
            stage_name = "unknown"; 
            fail_mode_to_use = fail_mode_verdict;
            break;
    }
    
    verdict_to_apply = fail_mode_to_use == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Deadline exceeded for session %d during %s stage - applying fail-safe verdict %d (fail_mode=%s)",
        session_id,
        stage_name,
        verdict_to_apply,
        (fail_mode_to_use == fail_mode_hold_verdict) ? "hold" : "regular"
    );

    ngx_http_cp_session_data *session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    if (session_data != NULL) {
        session_data->verdict = verdict_to_apply;
        session_data->remaining_messages_to_reply = 0;
        session_data->async_processing_needed = 0;
    }
    
    ctx->header_declined = 1;
    updateMetricField(REQ_HEADER_THREAD_TIMEOUT, 1);
    
    ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Deadline timeout: forcing completion for session %d with fail-safe verdict %d",
        session_id,
        verdict_to_apply
    );

    ngx_cp_async_event_handler(&ctx->agent_event);
}

///
/// @brief Start deadline timer for current stage with specified timeout
/// @param[in] ctx Async context
/// @param[in] timeout_ms Timeout in milliseconds
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t
ngx_cp_async_start_deadline_timer(ngx_http_cp_async_ctx_t *ctx, ngx_msec_t timeout_ms)
{
    if (ctx->deadline_event.timer_set) {
        ngx_del_timer(&ctx->deadline_event);
    }
    
    if (ctx->deadline_event.handler == NULL) {
        ctx->deadline_event.handler = ngx_cp_async_deadline_handler;
        ctx->deadline_event.data = ctx;
        ctx->deadline_event.log = ctx->request->connection->log;
        ctx->deadline_event.cancelable = 1;
    }
    
    ngx_add_timer(&ctx->deadline_event, timeout_ms);
    
    write_dbg(
        DBG_LEVEL_DEBUG, "Started deadline timer: %dms for session %d stage %d",
        timeout_ms,
        ctx->session_id, ctx->stage
    );

    return NGX_OK;
}

///
/// @brief Cancel deadline timer
/// @param[in] ctx Async context
///
static void
ngx_cp_async_cancel_deadline_timer(ngx_http_cp_async_ctx_t *ctx)
{
    if (ctx->deadline_event.timer_set) {
        ngx_del_timer(&ctx->deadline_event);
        write_dbg(DBG_LEVEL_DEBUG, "Cancelled deadline timer for session %d", ctx->session_id);
    }
}

///
/// @brief Context cleanup timeout handler - automatically destroys stale contexts
/// @details Automatically destroys contexts that remain active beyond the cleanup timeout
///          to prevent memory leaks and dangling pointers
/// @param[in] ev Cleanup timeout event  
///
static void
ngx_cp_async_context_cleanup_handler(ngx_event_t *ev)
{
    ngx_http_cp_async_ctx_t *ctx;
    struct timespec current_time;
    ngx_uint_t age_seconds;
    uint32_t session_id;
    ngx_cp_async_stage_t stage;
    
    ctx = (ngx_http_cp_async_ctx_t *) ev->data;
    
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Context cleanup timer fired for invalid/destroyed context - ignoring stale timer");
        return;
    }
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    stage = ngx_cp_async_ctx_get_stage_safe(ctx);
    
    if (stage == NGX_CP_ASYNC_STAGE_COMPLETE) {
        write_dbg(DBG_LEVEL_DEBUG, "Context cleanup timer fired for session %d already in COMPLETE stage - allowing normal cleanup", session_id);
        return;
    }
    
    clock_gettime(CLOCK_REALTIME, &current_time);
    age_seconds = (ngx_uint_t)(current_time.tv_sec - ctx->start_time.tv_sec);
    
    write_dbg(
        DBG_LEVEL_WARNING,
        "Context cleanup timeout: session %d has been active for %d seconds (stage: %d) - forcing cleanup to prevent memory leak",
        session_id,
        age_seconds,
        stage
    );
    
    ctx->flow_error = 1;
    
    ngx_http_cp_session_data *session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    if (session_data != NULL) {
        session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        session_data->remaining_messages_to_reply = 0;
        session_data->async_processing_needed = 0;
    }
    
    ctx->header_declined = 1;
        
    ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
    
    write_dbg(
        DBG_LEVEL_WARNING,
        "Context cleanup timeout: forcing completion for session %d after %d seconds with fail-safe verdict %d",
        session_id,
        age_seconds,
        session_data ? (int)session_data->verdict : -1
    );

    ngx_cp_async_event_handler(&ctx->agent_event);
}

static void
ngx_cp_async_verdict_event_handler(ngx_event_t *ev)
{
    ngx_uint_t verdicts_processed = 0;
    ssize_t socket_bytes_drained;
    (void) ev;

    if (!is_async_mode_enabled) {
        write_dbg(DBG_LEVEL_INFO, "Async mode disabled - cleaning up verdict event handler");
        if (ipc_verdict_conn) {
            write_dbg(DBG_LEVEL_INFO, "Cleaning up stale verdict event handler (fd: %d)", ipc_verdict_conn->fd);
            if (ipc_verdict_conn->read && ipc_verdict_conn->read->active) {
                ngx_del_event(ipc_verdict_conn->read, NGX_READ_EVENT, 0);
            }
            ngx_free_connection(ipc_verdict_conn);
            ipc_verdict_conn = NULL;
        }
        return;
    }

    // Socket is just a "doorbell" - actual data is in shared memory
    socket_bytes_drained = drain_comm_socket_fully(comm_socket);
    if (socket_bytes_drained == -1) {
        write_dbg(DBG_LEVEL_ERROR, "Agent disconnected - cleaning up verdict event handler");
        disable_ipc_verdict_event_handler();
        return;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Socket notification received, drained %zd bytes - processing IPC queue",
        socket_bytes_drained
    );
    
    if (drain_ipc_queue(&verdicts_processed) != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "IPC queue drain failed");
        return;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG, 
        "Verdict event handler complete: processed %d verdicts, pending chunks: %d", 
        verdicts_processed,
        pending_inspection_chunks
    );
}

///
/// @brief Drain IPC queue aggressively in tight loop
/// @param[out] verdicts_drained Counter for drained verdicts
/// @return NGX_OK on success
///
static ngx_int_t
drain_ipc_queue(ngx_uint_t *verdicts_drained)
{
    ngx_http_cp_async_ctx_t *ctx;
    HttpReplyFromService *reply_p;
    const char *reply_data;
    uint16_t reply_size;
    ngx_int_t res;
    
    while (nano_service_ipc && isDataAvailable(nano_service_ipc)) {
        res = receiveData(nano_service_ipc, &reply_size, &reply_data);
        if (res < 0 || reply_data == NULL) {
            write_dbg(DBG_LEVEL_WARNING, "Async backpressure: failed to receive verdict data from IPC");
            return NGX_ERROR;
        }
        
        reply_p = (HttpReplyFromService *)reply_data;
        (*verdicts_drained)++;
            
        if (reply_p->verdict == TRAFFIC_VERDICT_RECONF) {
            write_dbg(DBG_LEVEL_WARNING, "Received reconf verdict");
            popData(nano_service_ipc);
            reset_attachment_config();
            continue;
        }

        ctx = ngx_cp_async_find_ctx(reply_p->session_id);
        if (ctx == NULL) {
            popData(nano_service_ipc);
            ngx_cp_async_decrement_pending_chunks(reply_p->session_id, "backpressure_orphaned");
            continue;
        }
        
        if (!ngx_cp_async_ctx_is_valid(ctx)) {
            popData(nano_service_ipc);
            ngx_cp_async_decrement_pending_chunks(reply_p->session_id, "backpressure_invalid_ctx");
            continue;
        }
        
        if (ngx_cp_async_ctx_get_flow_error_safe(ctx)) {
            popData(nano_service_ipc);
            ngx_cp_async_decrement_pending_chunks(reply_p->session_id, "backpressure_flow_error");
            continue;
        }
        
        res = ngx_cp_async_apply_verdict(ctx, reply_p);
        if (popData(nano_service_ipc) != 0) {
            write_dbg(DBG_LEVEL_WARNING, "Async backpressure: failed to pop verdict data from IPC");
            return NGX_ERROR;
        }
        ngx_cp_async_decrement_pending_chunks(reply_p->session_id, "backpressure_drained");
        
        if (res != NGX_OK) {
            write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: failed to apply verdict for session %d", reply_p->session_id);
        }
    }
    
    return NGX_OK;
}

///
/// @brief Drain comm socket completely (non-blocking, edge-triggered correct)
/// @param[in] sock Socket to drain
/// @return Number of bytes drained, or -1 if socket disconnected
///
static ssize_t
drain_comm_socket_fully(int sock)
{
    static char drain_buf[4096];
    ssize_t total_drained = 0;
    ssize_t n;
    
    while ((n = read(sock, drain_buf, sizeof(drain_buf))) > 0) {
        total_drained += n;
    }
    
    if (n == 0) {
        write_dbg(DBG_LEVEL_WARNING, "Async backpressure: socket disconnected (EOF) - agent connection lost");
        return -1;
    }
    
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        write_dbg(DBG_LEVEL_WARNING, "Async backpressure: socket drain error: %s", strerror(errno));
    }
    
    return total_drained;
}

///
/// @brief Backpressure drain event handler - actively waits for and processes all pending verdicts
/// @details Optimized with:
///   - Reusable global epoll fd (no create/close overhead)
///   - Non-blocking socket with full drain (EPOLLET-correct)
///   - Minimal epoll_ctl calls (only when socket changes)
///   - Aggressive IPC queue draining in tight loops
///   - Large socket drain buffer (4KB)
/// @param[in] ev Posted event (unused)
///
static void
ngx_cp_async_backpressure_drain_handler(ngx_event_t *ev)
{
    ngx_uint_t verdicts_drained = 0;
    ngx_uint_t initial_pending_chunks = pending_inspection_chunks;
    struct epoll_event epoll_event;
    struct epoll_event events[1];
    int epoll_result;
    ngx_uint_t iterations = 0;
    const int epoll_timeout_ms = 50;
    const ngx_uint_t max_drain_iterations = 100;
    
    (void)ev;
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Async backpressure: starting drain handler with %d pending chunks", 
        pending_inspection_chunks
    );
    
    if (nano_service_ipc == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Async backpressure: IPC not available - aborting drain");
        return;
    }
    
    if (comm_socket < 0) {
        write_dbg(DBG_LEVEL_WARNING, "Async backpressure: communication socket invalid - aborting drain");
        return;
    }
    
    if (g_backpressure_epoll_fd < 0) {
        write_dbg(DBG_LEVEL_WARNING, "Async backpressure: global epoll fd not initialized - falling back to immediate drain");
        goto drain_immediate;
    }
    
    if (g_backpressure_registered_socket != comm_socket) {
        if (g_backpressure_registered_socket >= 0) {
            epoll_ctl(g_backpressure_epoll_fd, EPOLL_CTL_DEL, g_backpressure_registered_socket, NULL);
            write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: removed old socket %d from epoll", g_backpressure_registered_socket);
        }
        
        epoll_event.events = EPOLLIN | EPOLLET;
        epoll_event.data.fd = comm_socket;
        if (epoll_ctl(g_backpressure_epoll_fd, EPOLL_CTL_ADD, comm_socket, &epoll_event) < 0) {
            write_dbg(DBG_LEVEL_WARNING, "Async backpressure: failed to add communication socket to epoll: %s", strerror(errno));
            g_backpressure_registered_socket = -1;
            goto drain_immediate;
        }
        
        g_backpressure_registered_socket = comm_socket;
        write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: registered socket %d with epoll fd %d", comm_socket, g_backpressure_epoll_fd);
    }

    while (pending_inspection_chunks > 0 || iterations < max_drain_iterations) {
        iterations++;
        
        if (drain_ipc_queue(&verdicts_drained) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Async backpressure: IPC drain failed at iteration %d", iterations);
            break;
        }
        
        if (pending_inspection_chunks == 0) {
            write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: all pending chunks processed after %d iterations", iterations);
            break;
        }
        
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Async backpressure: waiting for more verdicts (iteration %d, pending: %d)...",
            iterations,
            pending_inspection_chunks
        );
        
        epoll_result = epoll_wait(g_backpressure_epoll_fd, events, 1, epoll_timeout_ms);
        if (epoll_result < 0) {
            if (errno == EINTR) {
                write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: epoll_wait interrupted, continuing");
                continue;
            }
            write_dbg(DBG_LEVEL_WARNING, "Async backpressure: epoll_wait failed: %s", strerror(errno));
            break;
        } else if (epoll_result == 0) {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Async backpressure: epoll_wait timeout after %dms (iteration %d, pending: %d)",
                epoll_timeout_ms,
                iterations,
                pending_inspection_chunks
            );
            break;
        } else {
            ssize_t drained_bytes = drain_comm_socket_fully(comm_socket);
            if (drained_bytes == -1) {
                write_dbg(
                    DBG_LEVEL_ERROR,
                    "ASYNC_BACKPRESSURE: Agent disconnected during backpressure drain (iteration %d) - aborting",
                    iterations
                );
                disable_ipc_verdict_event_handler();
                return;
            }
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Async backpressure: socket notification received, drained %zd bytes (iteration %d)",
                drained_bytes,
                iterations
            );
        }
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Async backpressure: drain complete after %d iterations - processed %d verdicts, pending chunks: %d -> %d",
        iterations,
        verdicts_drained,
        initial_pending_chunks,
        pending_inspection_chunks
    );
    return;
    
drain_immediate:
    write_dbg(DBG_LEVEL_DEBUG, "Async backpressure: immediate drain mode (no epoll)");
    drain_ipc_queue(&verdicts_drained);
    
    write_dbg(
        DBG_LEVEL_WARNING,
        "Async backpressure: immediate drain complete - processed %d verdicts, pending chunks: %d -> %d",
        verdicts_drained,
        initial_pending_chunks,
        pending_inspection_chunks
    );
}

ngx_int_t
ngx_cp_async_start_agent_communication(ngx_http_cp_async_ctx_t *ctx)
{
    write_dbg(DBG_LEVEL_DEBUG, "Starting agent communication for session %d", ctx->session_id);

    // Registration is now done synchronously in the handler, so go directly to meta data stage
    write_dbg(DBG_LEVEL_DEBUG, "Registration completed synchronously - proceeding to meta data stage for session %d", ctx->session_id);
    ctx->stage = NGX_CP_ASYNC_STAGE_META_DATA;
    
    if (handle_shmem_corruption() == NGX_ERROR) {
        write_dbg(DBG_LEVEL_WARNING, "Shared memory corrupted for session %d", ctx->session_id);
        ctx->flow_error = 1;
        ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        return fail_mode_verdict == NGX_OK ? NGX_DECLINED : fail_mode_verdict;
    }
    
    return ngx_cp_async_continue_processing(ctx);
}

void
queue_free(ngx_http_request_t *r, ngx_http_cp_async_ctx_t *ctx)
{
    ngx_chain_t *cl = ctx->queue_head, *ln;
    while (cl) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }
    ctx->queue_head = ctx->queue_tail = NULL;
}

ngx_int_t
chain_add_copy(ngx_http_request_t *request, ngx_http_cp_async_ctx_t *ctx, ngx_chain_t *in)
{
    if (in == NULL) return NGX_OK;

    ngx_chain_t *cl, **ll = (ctx->queue_tail ? &ctx->queue_tail->next : &ctx->queue_head);

    /* copy links (NOT buffers) */
    if (ngx_chain_add_copy(request->pool, ll, in) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->queue_tail == NULL) {
        for (cl = ctx->queue_head; cl && cl->next; cl = cl->next) { /* find tail */
            /* no-op */
        }
        ctx->queue_tail = cl ? cl : ctx->queue_head;
    } else {
        for (cl = ctx->queue_tail; cl && cl->next; cl = cl->next) {
            /* no-op */
        }
        ctx->queue_tail = cl;
    }

    return NGX_OK;
}

static void
cp_async_resume_event_handler(ngx_event_t *ev)
{
    ngx_http_cp_async_ctx_t *ctx = (ngx_http_cp_async_ctx_t *) ev->data;
    ngx_http_request_t *r;
    uint32_t session_id;
    
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Resume event handler called with invalid/destroyed context");
        return;
    }
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    r = ngx_cp_async_ctx_get_request_safe(ctx);
    
    if (r == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Resume event handler: no request for session %d", session_id);
        return;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Resume event handler for session %d", session_id);
    
    cp_async_posted_resume(r);
}

static void
cp_async_posted_resume(ngx_http_request_t *r) 
{
    ngx_http_cp_session_data *sd = recover_cp_session_data(r);
    ngx_http_cp_async_ctx_t *ctx;
    
    if (sd == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Posted resume: no session data");
        return;
    }
    
    ctx = ngx_cp_async_find_ctx(sd->session_id);
    if (ctx == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Posted resume: no async context for session %d", sd->session_id);
        return;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Posted resume for session %d", ctx->session_id);

    if (ctx->queue_head) {
        write_dbg(DBG_LEVEL_DEBUG, "Posted resume: forwarding queued body for session %d", ctx->session_id);
        ngx_int_t rc = ngx_http_next_request_body_filter(r, ctx->queue_head);
        if (rc == NGX_AGAIN) {
            write_dbg(DBG_LEVEL_WARNING, "Downstream busy during resume for session %d", ctx->session_id);
            ngx_add_timer(&ctx->resume_event, 50);
            return;
        } else {
            queue_free(r, ctx);
            ctx->queue_head = ctx->queue_tail = NULL;
        }
    }

    if (ctx->released && ctx->waiting) {
        write_dbg(DBG_LEVEL_DEBUG, "Posted resume: resuming session %d complete", ctx->session_id);
        ctx->waiting = 0;
        SAFE_DESTROY_CTX(ctx);
        ngx_http_core_run_phases(r);
        return;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Posted resume: posting read event for session %d, read event %d", ctx->session_id, r->connection->read->active);
    ngx_post_event(r->connection->read, &ngx_posted_events);
}

static void
cp_async_post_request(ngx_http_cp_async_ctx_t *ctx) 
{
    write_dbg(DBG_LEVEL_DEBUG, "Posting event for session %d", ctx->session_id);
    ngx_post_event(&ctx->resume_event, &ngx_posted_events);    
}

///
/// @brief Checks if the given verdict is a final verdict (accept/drop/custom_response)
/// @param[in] verdict The verdict to check
/// @return 1 if verdict is final, 0 otherwise
///
static ngx_int_t
is_verdict_final(ServiceVerdict verdict)
{
    return (verdict == TRAFFIC_VERDICT_ACCEPT || 
            verdict == TRAFFIC_VERDICT_DROP || 
            verdict == TRAFFIC_VERDICT_CUSTOM_RESPONSE);
}

///
/// @brief Free modification list
/// @param[in] ctx Async context
///
static void
ngx_cp_async_free_modification_list(ngx_http_cp_async_ctx_t *ctx)
{
    ngx_http_request_t *request;
    ngx_http_cp_modification_list *current_modification;
    
    if (ctx == NULL || ctx->modifications == NULL) {
        return;
    }
    
    request = ngx_cp_async_ctx_get_request_safe(ctx);
    if (request == NULL) {
        return;
    }
    
    while (ctx->modifications) {
        current_modification = ctx->modifications;
        ctx->modifications = ctx->modifications->next;
        ngx_pfree(request->pool, current_modification->modification.data);
        ngx_pfree(request->pool, current_modification);
    }
}

///
/// @brief Check if verdict should be treated as drop (includes custom response)
/// @param[in] verdict The verdict to check
/// @return 1 if verdict should be treated as drop, 0 otherwise
///
static ngx_int_t
is_verdict_drop_or_custom(ServiceVerdict verdict)
{
    return (verdict == TRAFFIC_VERDICT_DROP || verdict == TRAFFIC_VERDICT_CUSTOM_RESPONSE);
}

static ngx_int_t
ngx_cp_async_apply_verdict_for_stage(ngx_http_cp_async_ctx_t *ctx)
{
    uint32_t session_id;
    ngx_http_cp_session_data *session_data;
    ngx_cp_async_stage_t stage;
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    stage = ngx_cp_async_ctx_get_stage_safe(ctx);
    
    if (session_id == 0 || session_data == NULL || stage == NGX_CP_ASYNC_STAGE_ERROR) {
        write_dbg(DBG_LEVEL_WARNING, "Apply verdict for stage: invalid context data");
        return NGX_ERROR;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Applying verdict %d for stage %d, session %d", 
        session_data->verdict,
        stage,
        session_id
    );
    
    switch (stage) {
        case NGX_CP_ASYNC_STAGE_META_DATA:
            write_dbg(DBG_LEVEL_DEBUG, "Applying verdict for meta-data stage, session %d", session_id);
            
            if (is_verdict_drop_or_custom(session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "Meta-data verdict is drop/custom-response - proceeding directly to completion for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                return NGX_OK;
            } else if (session_data->verdict == TRAFFIC_VERDICT_DELAYED) {
                write_dbg(DBG_LEVEL_DEBUG, "Meta-data verdict is wait - transitioning to wait meta verdict stage for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_WAIT_META_VERDICT);
                return NGX_OK;
            } else {
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "Meta-data verdict %d - transitioning to headers for session %d", 
                    session_data->verdict,
                    session_id
                );
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_HEADERS);
                return NGX_OK;
            }
            break;
            
        case NGX_CP_ASYNC_STAGE_HEADERS:
            write_dbg(DBG_LEVEL_DEBUG, "Applying verdict for headers stage, session %d", session_id);
            
            if (is_verdict_drop_or_custom(ctx->session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "Header verdict is drop/custom-response - proceeding directly to completion for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                return NGX_OK;
            } else if (ctx->session_data->verdict == TRAFFIC_VERDICT_DELAYED) {
                write_dbg(DBG_LEVEL_DEBUG, "Header verdict is wait - transitioning to wait header verdict stage for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT);
                return NGX_OK;
            } else {
                write_dbg(DBG_LEVEL_DEBUG, "Header verdict is inspect - checking for body for session %d", session_id);
                if (does_contain_body(&(ctx->request->headers_in))) {
                    write_dbg(DBG_LEVEL_DEBUG, "Request has body - transitioning to body stage for session %d", session_id);
                    ctx->header_declined = 1;
                    ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_BODY);
                    ngx_cp_async_cancel_deadline_timer(ctx);
                    if (ctx->waiting) {
                        ctx->waiting = 0;
                        ngx_http_core_run_phases(ctx->request);
                    }
                    return NGX_DECLINED;
                } else {
                    write_dbg(DBG_LEVEL_DEBUG, "No body in request - transitioning to end transaction for session %d", session_id);
                    ctx->session_data->async_processing_needed = 0;
                    ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_END_TRANSACTION);
                    return NGX_OK;
                }
            }
            break;
            
        case NGX_CP_ASYNC_STAGE_END_TRANSACTION:
            write_dbg(DBG_LEVEL_DEBUG, "End transaction verdict processing for session %d", session_id);
            
            if (is_verdict_drop_or_custom(ctx->session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "End transaction verdict is drop/custom-response - proceeding directly to completion for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                return NGX_OK;
            } else if (ctx->session_data->verdict == TRAFFIC_VERDICT_DELAYED) {
                write_dbg(DBG_LEVEL_DEBUG, "End transaction verdict is wait - transitioning to wait end verdict stage for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT);
                ngx_add_timer(&ctx->agent_event, async_wait_verdict_timeout_ms);
                return NGX_AGAIN;
            } else {
                write_dbg(
                    DBG_LEVEL_DEBUG, 
                    "End transaction verdict received (%d) - proceeding to completion for session %d", 
                    ctx->session_data->verdict,
                    session_id
                );
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                ctx->header_declined = 1;
                ctx->session_data->async_processing_needed = 0;
                return NGX_OK;
            }
            break;
            
        case NGX_CP_ASYNC_STAGE_BODY:
            write_dbg(DBG_LEVEL_DEBUG, "Body verdict processing for session %d", session_id);
            
            if (is_verdict_drop_or_custom(ctx->session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "Body verdict is drop/custom-response - proceeding to completion for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                return NGX_OK;
            } else if (ctx->session_data->verdict == TRAFFIC_VERDICT_DELAYED) {
                write_dbg(DBG_LEVEL_DEBUG, "Body verdict is wait - transitioning to wait body verdict stage for session %d", session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT);
                ngx_add_timer(&ctx->agent_event, async_wait_verdict_timeout_ms);
                return NGX_AGAIN;
            } else if (ctx->session_data->was_request_fully_inspected) {
                write_dbg(DBG_LEVEL_DEBUG, "Body verdict is accept (final) - proceeding directly to completion for session %d", session_id);
                ctx->req_seq = 0;
                return NGX_OK;
            } else {
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "Body verdict received (%d) - continuing body processing for session %d", 
                    ctx->session_data->verdict
                    ,ctx->session_id
                );
                return NGX_OK;
            }
            break;

        case NGX_CP_ASYNC_STAGE_WAIT_META_VERDICT:
        case NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT:
        case NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT:
        case NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT:
            write_dbg(DBG_LEVEL_DEBUG, "Still waiting for verdict in stage %d for session %d", ctx->stage, ctx->session_id);
            ngx_add_timer(&ctx->agent_event, async_wait_verdict_timeout_ms);
            return NGX_AGAIN;
            
        default:
            write_dbg(
                DBG_LEVEL_ERROR,
                "No stage-specific verdict processing for stage %d, session %d", 
                ctx->stage,
                ctx->session_id
            );
            return NGX_OK;
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_cp_async_apply_verdict(ngx_http_cp_async_ctx_t *ctx, HttpReplyFromService *reply_p)
{
    ngx_int_t rc = NGX_OK;
    uint32_t session_id;
    ngx_http_cp_session_data *session_data;

    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        write_dbg(DBG_LEVEL_WARNING, "Apply verdict called with invalid/destroyed context for session %d - ignoring", reply_p->session_id);
        return NGX_ERROR;
    }
    
    session_id = ngx_cp_async_ctx_get_session_id_safe(ctx);
    session_data = ngx_cp_async_ctx_get_session_data_safe(ctx);
    
    if (session_data == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Apply verdict: invalid session data for session %d", session_id);
        return NGX_ERROR;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Applying verdict %d for session %d", reply_p->verdict, session_id);
    
    session_data->verdict = (ServiceVerdict)reply_p->verdict;

    if (is_verdict_final((ServiceVerdict)reply_p->verdict)) {
        session_data->was_request_fully_inspected = 1;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Final verdict %d received for session %d - marking request as fully inspected", 
            reply_p->verdict,
            session_id
        );
    }

    if (reply_p->verdict == TRAFFIC_VERDICT_DELAYED && !ctx->first_wait_verdict_encountered) {
        ctx->first_wait_verdict_encountered = 1;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "First wait verdict encountered for session %d - cancelling current deadline timer and starting new one with %dms timeout", 
            session_id,
            req_max_proccessing_ms_time
        );
        ngx_cp_async_cancel_deadline_timer(ctx);
        ngx_cp_async_start_deadline_timer(ctx, ngx_max(req_max_proccessing_ms_time, async_body_stage_timeout));
    }
    
    if (reply_p->verdict == LIMIT_RESPONSE_HEADERS) {
        write_dbg(DBG_LEVEL_DEBUG, "Received limit response headers verdict for session %d", session_id);
        return NGX_OK;
    }
    
    if (is_verdict_drop_or_custom(reply_p->verdict) && reply_p->modification_count > 0) {        
        if (reply_p->verdict == TRAFFIC_VERDICT_DROP) {
            write_dbg(DBG_LEVEL_DEBUG, "Applying custom web response for session %d", session_id);
            handle_custom_web_response(reply_p->modify_data->web_response_data);
        } else if (reply_p->verdict == TRAFFIC_VERDICT_CUSTOM_RESPONSE) {
            write_dbg(DBG_LEVEL_DEBUG, "Applying custom response for session %d", session_id);
            handle_custom_response(reply_p->modify_data->custom_response_data);
        }
        
        ngx_cp_async_free_modification_list(ctx);
        session_data->remaining_messages_to_reply = 0;
    }
    
    if (reply_p->verdict == TRAFFIC_VERDICT_INJECT && reply_p->modification_count > 0) {
        write_dbg(
            DBG_LEVEL_DEBUG, "Processing %d modifications for session %d",
            reply_p->modification_count,
            session_id
        );

        HttpInjectData *current_inject_data = reply_p->modify_data->inject_data;
        uint8_t modification_count = reply_p->modification_count;
        ngx_http_cp_modification_list *new_modification = NULL;
        ngx_http_cp_modification_list *current_modification = NULL;
        unsigned int modification_index;
        
        ngx_http_request_t *request = ngx_cp_async_ctx_get_request_safe(ctx);
        if (request == NULL) {
            write_dbg(DBG_LEVEL_WARNING, "Apply verdict: invalid request for session %d - cannot process modifications", session_id);
            return NGX_ERROR;
        }
        
        for (modification_index = 0; modification_index < modification_count; modification_index++) {
            new_modification = create_modification_node(current_inject_data, request);
            if (new_modification == NULL) {
                write_dbg(DBG_LEVEL_WARNING, "Failed to create modification node for session %d", session_id);
                while (ctx->modifications) {
                    current_modification = ctx->modifications;
                    ctx->modifications = ctx->modifications->next;
                    ngx_pfree(request->pool, current_modification->modification_buffer);
                    ngx_pfree(request->pool, current_modification);
                }
                rc = NGX_ERROR;
                break;
            }
            
            if (ctx->modifications == NULL) {
                ctx->modifications = new_modification;
                current_modification = ctx->modifications;
            } else {
                current_modification->next = new_modification;
                current_modification = current_modification->next;
            }
            
            current_inject_data = (HttpInjectData *)(
                (char *)current_inject_data +
                sizeof(HttpInjectData) +
                current_inject_data->injection_size
            );
        }
        
        if (rc != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to parse modifications for session %d", session_id);
        } else {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Successfully parsed %d modifications for session %d", 
                modification_count,
                session_id
            );
        }
    }

    if (session_data->remaining_messages_to_reply > 0) {
        session_data->remaining_messages_to_reply--;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Verdict received - remaining messages for session %d: %d", 
            session_id,
            session_data->remaining_messages_to_reply
        );
    }

    if (ctx->req_seq > 0) {
        ctx->req_seq--;
    }

    if (
        session_data->remaining_messages_to_reply == 0
        || (session_data->was_request_fully_inspected && ngx_cp_async_ctx_get_stage_safe(ctx) == NGX_CP_ASYNC_STAGE_BODY)
    ) {
        ngx_int_t apply_verdict_rc = ngx_cp_async_apply_verdict_for_stage(ctx);
        if (apply_verdict_rc == NGX_OK) {
            ngx_cp_async_event_handler(&ctx->agent_event);
        }
    }
    
    return rc;
}

ngx_int_t
ngx_cp_async_continue_processing(ngx_http_cp_async_ctx_t *ctx)
{
    ngx_int_t rc = NGX_OK;
    ngx_uint_t num_messages_sent = 0;
    
    if (ctx->flow_error) {
        write_dbg(DBG_LEVEL_WARNING, "Flow error flag set, skipping processing");
        ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        return fail_mode_verdict == NGX_OK ? NGX_DECLINED : fail_mode_verdict;
    }
    
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Processing stage %d - remaining_messages_to_reply=%d", 
        ctx->stage,
        ctx->session_data->remaining_messages_to_reply
    );

    set_current_session_id(ctx->session_id);
    
    switch (ctx->stage) {
        case NGX_CP_ASYNC_STAGE_META_DATA:
            write_dbg(DBG_LEVEL_DEBUG, "Entered meta-data stage for session %d", ctx->session_id);
            
            if (!ctx->meta_data_sent) {
                write_dbg(DBG_LEVEL_DEBUG, "Calling async meta data sender for session %d", ctx->session_id);
                rc = ngx_cp_async_send_meta_data_nonblocking(ctx, &num_messages_sent);
                write_dbg(
                    DBG_LEVEL_DEBUG, "Async meta-data sender returned: %d, messages sent: %d for session %d",
                    rc,
                    num_messages_sent,
                    ctx->session_id
                );

                if (rc == INSPECTION_IRRELEVANT) {
                    write_dbg(DBG_LEVEL_DEBUG, "Request irrelevant for session %d - returning irrelevant verdict", ctx->session_id);
                    ctx->session_data->verdict = TRAFFIC_VERDICT_IRRELEVANT;
                    return NGX_DECLINED;
                }
                
                if (rc != NGX_OK) {
                    write_dbg(DBG_LEVEL_DEBUG, "Failed to send meta-data for session %d - rc: %d", ctx->session_id, rc);
                    ctx->flow_error = 1;
                    ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                    goto process_complete_stage;
                }
                
                write_dbg(DBG_LEVEL_DEBUG, "Meta-data sent - awaiting verdict for session %d", ctx->session_id);
                ctx->session_data->remaining_messages_to_reply += num_messages_sent;
                ctx->meta_data_sent = 1;
                return NGX_AGAIN;
            }
            break;

        case NGX_CP_ASYNC_STAGE_HEADERS:
            write_dbg(DBG_LEVEL_DEBUG, "Entered headers stage for session %d", ctx->session_id);
            
            if (!ctx->headers_sent) {
                num_messages_sent = 0;
                write_dbg(DBG_LEVEL_DEBUG, "Calling async headers sender for session %d", ctx->session_id);
                rc = ngx_cp_async_send_headers_nonblocking(ctx, &num_messages_sent);
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "Async headers sender returned: %d, messages sent: %d for session %d", 
                    rc,
                    num_messages_sent,
                    ctx->session_id
                );
                
                if (rc != NGX_OK) {
                    write_dbg(DBG_LEVEL_WARNING, "Failed to send headers for session %d - rc: %d", ctx->session_id, rc);
                    ctx->flow_error = 1;
                    ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                    goto process_complete_stage;
                }
                
                write_dbg(DBG_LEVEL_DEBUG, "Headers sent - awaiting verdict for session %d", ctx->session_id);
                ctx->session_data->remaining_messages_to_reply += num_messages_sent;
                ctx->headers_sent = 1;
                
                return NGX_AGAIN;
            }
            break;

        case NGX_CP_ASYNC_STAGE_END_TRANSACTION:
            write_dbg(DBG_LEVEL_DEBUG, "Entered end transaction stage for session %d", ctx->session_id);
            if (!ctx->end_transaction_sent) {
                write_dbg(DBG_LEVEL_DEBUG, "Calling async end transaction sender for session %d", ctx->session_id);
                rc = ngx_cp_async_send_end_transaction_nonblocking(ctx, &num_messages_sent);

                write_dbg(
                    DBG_LEVEL_DEBUG, "Async end transaction sender returned: %d, messages sent: %d for session %d",
                    rc,
                    num_messages_sent,
                    ctx->session_id
                );

                if (rc != NGX_OK) {
                    write_dbg(DBG_LEVEL_WARNING, "End transaction sender failed for session %d", ctx->session_id);
                    ctx->flow_error = 1;
                    ctx->session_data->verdict = fail_mode_verdict == NGX_OK ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
                    goto process_complete_stage;
                }
                
                write_dbg(DBG_LEVEL_DEBUG, "End transaction sent - awaiting verdict for session %d", ctx->session_id);
                ctx->session_data->remaining_messages_to_reply += num_messages_sent;
                ctx->end_transaction_sent = 1;
                return NGX_AGAIN;
            }
            break;

        case NGX_CP_ASYNC_STAGE_BODY:
            write_dbg(DBG_LEVEL_DEBUG, "Entered body stage for session %d", ctx->session_id);
            if (is_verdict_drop_or_custom(ctx->session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "Final verdict is drop - proceeding to complete stage for session %d", ctx->session_id);
                ASYNC_STAGE_TRANSITION(ctx, NGX_CP_ASYNC_STAGE_COMPLETE);
                goto process_complete_stage;
            }

            if (ctx->req_seq > 0) {
                write_dbg(DBG_LEVEL_DEBUG, "Body chunks sent - awaiting verdicts for session %d", ctx->session_id);
                return NGX_AGAIN;
            }

            if (ctx->req_seq == 0 && ctx->end_transaction_sent == 1 && ctx->req_seen_last == 1) {
                write_dbg(DBG_LEVEL_DEBUG, "All body chunks processed - finalizing request for session %d", ctx->session_id);
                ctx->released = 1;
            }

            cp_async_post_request(ctx);
            return NGX_AGAIN;
            break;

        case NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT:
            write_dbg(DBG_LEVEL_DEBUG, "Entered wait header verdict stage for session %d", ctx->session_id);
            return ngx_cp_async_handle_wait_verdict(ctx, "header");
            
        case NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT:
            write_dbg(DBG_LEVEL_DEBUG, "Entered wait end verdict stage for session %d", ctx->session_id);
            return ngx_cp_async_handle_wait_verdict(ctx, "end");
            
        case NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT:
            write_dbg(DBG_LEVEL_DEBUG, "Entered wait body verdict stage for session %d", ctx->session_id);
            return ngx_cp_async_handle_wait_verdict(ctx, "body");
            
process_complete_stage:
        case NGX_CP_ASYNC_STAGE_COMPLETE:
            write_dbg(DBG_LEVEL_DEBUG, "Entered complete stage for session %d", ctx->session_id);
            ngx_cp_async_cancel_deadline_timer(ctx);

            write_dbg(DBG_LEVEL_DEBUG, "Calculating processing time for session %d", ctx->session_id);
            calcProcessingTime(ctx->session_data, &ctx->start_time, 1);
            
            write_dbg(DBG_LEVEL_DEBUG, "Finalizing request headers hook for session %d", ctx->session_id);
            rc = ngx_http_cp_finalize_request_headers_hook(
                ctx->request,
                ctx->session_data,
                ctx->modifications,
                NGX_OK
            );
            write_dbg(DBG_LEVEL_DEBUG, "Finalize headers hook returned: %d for session %d", rc, ctx->session_id);
            
            if (ctx->agent_event.timer_set) {
                write_dbg(DBG_LEVEL_DEBUG, "Canceling pending timer for session %d", ctx->session_id);
                ngx_del_timer(&ctx->agent_event);
            }

            if (
                ctx->session_data->verdict == TRAFFIC_VERDICT_ACCEPT
                || ctx->session_data->verdict == TRAFFIC_VERDICT_INSPECT
                || ctx->session_data->verdict == TRAFFIC_VERDICT_IRRELEVANT
            ) {
                write_dbg(
                    DBG_LEVEL_DEBUG,
                    "Request allowed (verdict: %d) - continuing to proxy pass for session %d",
                    ctx->session_data->verdict,
                    ctx->session_id
                );
                return NGX_DECLINED;
            }
        
            write_dbg(DBG_LEVEL_DEBUG, "Final verdict for session %d: %d", ctx->session_id, ctx->session_data->verdict);
            if (is_verdict_drop_or_custom(ctx->session_data->verdict)) {
                write_dbg(DBG_LEVEL_DEBUG, "Request blocked - rejecting request for session %d", ctx->session_id);
                return NGX_HTTP_FORBIDDEN;
            } else {
                write_dbg(
                    DBG_LEVEL_WARNING,
                    "Unknown verdict %d - using fail-safe mode for session %d", 
                    ctx->session_data->verdict,
                    ctx->session_id
                );
                ngx_int_t fail_safe_rc = fail_mode_verdict == NGX_OK ? NGX_DECLINED : NGX_HTTP_FORBIDDEN;
                return fail_safe_rc;
            }

            write_dbg(DBG_LEVEL_DEBUG, "Async processing complete for session %d", ctx->session_id);
            break;
            
        case NGX_CP_ASYNC_STAGE_ERROR:
        default:
            write_dbg(DBG_LEVEL_WARNING, "Entered error/unknown stage (%d) for session %d", ctx->stage, ctx->session_id);
            return NGX_ERROR;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Stage processing finished - expecting further events");
    return NGX_AGAIN;
}
