#include "ngx_cp_async_ctx_validation.h"

#include "ngx_cp_async_core.h"
#include "../ngx_cp_utils.h"

///
/// @brief Check if a context pointer is valid and not destroyed
/// @param[in] ctx Context to validate
/// @return 1 if valid, 0 if invalid/destroyed
///
ngx_int_t 
ngx_cp_async_ctx_is_valid(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    
    if (!ctx->session_id) {
        write_dbg(DBG_LEVEL_WARNING, "Context validation failed: invalid session_id 0");
        return 0;
    }

    if (!ctx->request) {
        write_dbg(DBG_LEVEL_WARNING, "Context validation failed: NULL request for session %d", ctx->session_id);
        return 0;
    }
    
    if (!ctx->session_data) {
        write_dbg(DBG_LEVEL_WARNING, "Context validation failed: NULL session_data for session %d", ctx->session_id);
        return 0;
    }
    
    return 1;
}

///
/// @brief Safely get session ID from context
/// @param[in] ctx Context to get session ID from
/// @return Session ID or 0 if invalid
///
uint32_t 
ngx_cp_async_ctx_get_session_id_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 0;
    }
    return ctx->session_id;
}

///
/// @brief Safely get request from context
/// @param[in] ctx Context to get request from
/// @return Request pointer or NULL if invalid
///
ngx_http_request_t *
ngx_cp_async_ctx_get_request_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return NULL;
    }
    return ctx->request;
}

///
/// @brief Safely get session data from context
/// @param[in] ctx Context to get session data from
/// @return Session data pointer or NULL if invalid
///
ngx_http_cp_session_data *
ngx_cp_async_ctx_get_session_data_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return NULL;
    }
    return ctx->session_data;
}

///
/// @brief Safely get stage from context
/// @param[in] ctx Context to get stage from
/// @return Stage or NGX_CP_ASYNC_STAGE_ERROR if invalid
///
ngx_cp_async_stage_t 
ngx_cp_async_ctx_get_stage_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return NGX_CP_ASYNC_STAGE_ERROR;
    }
    return ctx->stage;
}

///
/// @brief Safely get flow error flag from context
/// @param[in] ctx Context to get flow error from
/// @return Flow error flag or 1 (error) if invalid
///
ngx_int_t 
ngx_cp_async_ctx_get_flow_error_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 1; // Assume error if context is invalid
    }
    return ctx->flow_error;
}

///
/// @brief Safely get header declined flag from context
/// @param[in] ctx Context to get header declined from
/// @return Header declined flag or 0 if invalid
///
ngx_int_t 
ngx_cp_async_ctx_get_header_declined_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 0;
    }
    return ctx->header_declined;
}

///
/// @brief Safely get request sequence from context
/// @param[in] ctx Context to get req_seq from
/// @return Request sequence or 0 if invalid
///
ngx_uint_t 
ngx_cp_async_ctx_get_req_seq_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 0;
    }
    return ctx->req_seq;
}

///
/// @brief Safely get waiting flag from context
/// @param[in] ctx Context to get waiting from
/// @return Waiting flag or 0 if invalid
///
ngx_int_t 
ngx_cp_async_ctx_get_waiting_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 0;
    }
    return ctx->waiting;
}

///
/// @brief Safely get released flag from context
/// @param[in] ctx Context to get released from
/// @return Released flag or 0 if invalid
///
ngx_int_t 
ngx_cp_async_ctx_get_released_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return 0;
    }
    return ctx->released;
}

///
/// @brief Safely get queue head from context
/// @param[in] ctx Context to get queue_head from
/// @return Queue head or NULL if invalid
///
ngx_chain_t *
ngx_cp_async_ctx_get_queue_head_safe(ngx_http_cp_async_ctx_t *ctx)
{
    if (!ngx_cp_async_ctx_is_valid(ctx)) {
        return NULL;
    }
    return ctx->queue_head;
}

///
/// @brief Nullify all references to a context in event handlers
/// @param[in] ctx Context being destroyed
///
void 
ngx_cp_async_nullify_ctx_refs(ngx_http_cp_async_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    // Clear event data pointers to prevent dangling references
    if (ctx->agent_event.data == ctx) {
        ctx->agent_event.data = NULL;
    }
    if (ctx->cleanup_event.data == ctx) {
        ctx->cleanup_event.data = NULL;
    }
    if (ctx->resume_event.data == ctx) {
        ctx->resume_event.data = NULL;
    }
    if (ctx->deadline_event.data == ctx) {
        ctx->deadline_event.data = NULL;
    }
    
    write_dbg(DBG_LEVEL_DEBUG, "Nullified context references for session %d", ctx->session_id);
}
