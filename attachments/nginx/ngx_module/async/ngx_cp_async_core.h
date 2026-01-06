#ifndef __NGX_CP_ASYNC_CORE_H__
#define __NGX_CP_ASYNC_CORE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

#include "../ngx_cp_hook_threads.h"
#include "nano_attachment_common.h"

extern ngx_module_t ngx_http_cp_attachment_module; ///< CP Attachment module
extern ngx_http_request_body_filter_pt ngx_http_next_request_body_filter; ///< NGINX request body filter.
extern ngx_uint_t async_backpressure_threshold;
extern ngx_msec_t async_header_timeout_ms; // Default 3s for headers/meta_data/end_transaction
extern ngx_msec_t async_body_stage_timeout; // Default 5s for body stage
extern ngx_msec_t async_wait_verdict_timeout_ms; // Default 50ms for wait verdict polling
extern ngx_msec_t async_first_wait_verdict_timeout_ms; // Default 10s for first wait verdict deadline timer
extern ngx_msec_t async_signal_timeout_ms; // Default 10ms for service signal timeout
extern ngx_msec_t async_context_cleanup_timeout_ms; // Default 5 minutes for context cleanup

/// @struct ngx_http_cp_async_ctx
/// @brief Simplified async context for handling non-blocking agent communication
typedef struct ngx_http_cp_async_ctx {
    ngx_http_request_t                *request;          ///< Original request
    ngx_http_cp_session_data          *session_data;     ///< Session data
    uint32_t                           session_id;       ///< Session ID for this context
    ngx_int_t                          stage;            ///< Current processing stage
    ngx_event_t                        agent_event;      ///< Event for agent communication
    ngx_event_t                        deadline_event;   ///< Deadline timeout event for current stage
    ngx_event_t                        cleanup_event;    ///< Context cleanup timeout event
    ngx_event_t                        resume_event;     ///< Event to resume request processing
    struct timespec                    start_time;       ///< Processing start time
    ngx_str_t                          waf_tag;          ///< WAF tag for this request
    ngx_http_cp_modification_list     *modifications;   ///< Modifications data
    unsigned                           waiting:1;            ///< Flag to indicate waiting for verdict
    unsigned                           body_phase_started:1; ///< Flag to indicate if body phase started
    unsigned                           released:1;           ///< Flag to indicate if request is released
    unsigned                           req_seen_last:1;      ///< Flag to indicate if last chunk seen
    ngx_uint_t                         req_seq;              ///< Request body chunk sequence number
    ngx_chain_t                       *queue_head;           ///< Saved chains to forward later
    ngx_chain_t                       *queue_tail;           ///< Tail of saved chains
    ngx_uint_t                         meta_data_sent;   ///< Flag to track if meta data was sent
    ngx_uint_t                         headers_sent;     ///< Flag to track if headers were sent
    ngx_uint_t                         end_transaction_sent; ///< Flag to track if end transaction was sent
    ngx_uint_t                         header_declined;  ///< Flag to track if headers were declined
    unsigned                           first_wait_verdict_encountered:1; ///< Flag to track if first wait verdict was encountered
    struct ngx_http_cp_async_ctx      *map_next;         ///< Next context in hash bucket chain
    unsigned                           flow_error:1;             ///< Flag to indicate flow error/failure/abort occurred
    unsigned                           request_ref_incremented:1; ///< Flag to track if request reference count was incremented
    struct timespec                    request_start_time;  ///< Current stage start time
} ngx_http_cp_async_ctx_t;


///
/// @brief Initialize the async connection management system
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t ngx_cp_async_init();

///
/// @brief Cleanup the async connection management system
///
void ngx_cp_async_cleanup();

///
/// @brief Create and initialize async context
/// @param[in] request NGINX request
/// @param[in] session_data Session data
/// @return Async context pointer or NULL on failure
///
ngx_http_cp_async_ctx_t *ngx_cp_async_create_ctx(ngx_http_request_t *request, ngx_http_cp_session_data *session_data);

///
/// @brief Destroy async context
/// @param[in] ctx Async context to destroy
///
void ngx_cp_async_destroy_ctx(ngx_http_cp_async_ctx_t *ctx);

///
/// @brief Find async context by session ID
/// @param[in] session_id Session ID to find
/// @return Async context pointer or NULL if not found
///
ngx_http_cp_async_ctx_t *ngx_cp_async_find_ctx(uint32_t session_id);

///
/// @brief Add async context to connection map
/// @param[in] ctx Async context to add
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t ngx_cp_async_add_ctx(ngx_http_cp_async_ctx_t *ctx);

///
/// @brief Remove async context from connection map
/// @param[in] ctx Async context to remove
///
void ngx_cp_async_remove_ctx(ngx_http_cp_async_ctx_t *ctx);

///
/// @brief Main async event handler
/// @param[in] ev Event that triggered the handler
///
void ngx_cp_async_event_handler(ngx_event_t *ev);

///
/// @brief Start async agent communication
/// @param[in] ctx Async context
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t ngx_cp_async_start_agent_communication(ngx_http_cp_async_ctx_t *ctx);

///
/// @brief Continue processing to next stage
/// @param[in] ctx Async context
/// @return NGX_OK, NGX_AGAIN, NGX_HTTP_FORBIDDEN, or NGX_ERROR
///
ngx_int_t ngx_cp_async_continue_processing(ngx_http_cp_async_ctx_t *ctx);

///
/// @brief Start deadline timer for current stage
/// @param[in] ctx Async context
/// @param[in] timeout_ms Timeout in milliseconds  
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t ngx_cp_async_start_deadline_timer(ngx_http_cp_async_ctx_t *ctx, ngx_msec_t timeout_ms);

///
/// @brief Disable IPC verdict event handler and free connection
///
void disable_ipc_verdict_event_handler(void);

///
/// @brief Enable IPC verdict event handler and setup connection
///
void enable_ipc_verdict_event_handler(void);

///
/// @brief Setup IPC verdict event handler
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t ngx_cp_async_setup_verdict_event_handler(void);

///
/// @brief Add chain of buffers to async context queue
/// @param[in] request NGINX request
/// @param[in] ctx Async context
/// @param[in] in Chain of buffers to add
/// @return NGX_OK on success, NGX_ERROR on failure
///
ngx_int_t chain_add_copy(ngx_http_request_t *request, ngx_http_cp_async_ctx_t *ctx, ngx_chain_t *in);

///
/// @brief Free queued chains in async context
/// @param[in] r NGINX request
/// @param[in] ctx Async context
///
void queue_free(ngx_http_request_t *r, ngx_http_cp_async_ctx_t *ctx);

void ngx_cp_async_increment_pending_chunks(uint32_t session_id, const char *chunk_type);

void ngx_cp_async_decrement_pending_chunks(uint32_t session_id, const char *verdict_type);

///
/// @brief Post backpressure drain event if conditions are met
///
void ngx_cp_async_post_backpressure_drain_event(void);

#endif // __NGX_CP_ASYNC_CORE_H__
