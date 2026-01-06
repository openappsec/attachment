#ifndef __NGX_CP_ASYNC_CTX_VALIDATION_H__
#define __NGX_CP_ASYNC_CTX_VALIDATION_H__

#include "ngx_cp_async_types.h"

// Context validation functions
ngx_int_t ngx_cp_async_ctx_is_valid(ngx_http_cp_async_ctx_t *ctx);
uint32_t ngx_cp_async_ctx_get_session_id_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_http_request_t *ngx_cp_async_ctx_get_request_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_http_cp_session_data *ngx_cp_async_ctx_get_session_data_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_cp_async_stage_t ngx_cp_async_ctx_get_stage_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_int_t ngx_cp_async_ctx_get_flow_error_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_int_t ngx_cp_async_ctx_get_header_declined_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_uint_t ngx_cp_async_ctx_get_req_seq_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_int_t ngx_cp_async_ctx_get_waiting_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_int_t ngx_cp_async_ctx_get_released_safe(ngx_http_cp_async_ctx_t *ctx);
ngx_chain_t *ngx_cp_async_ctx_get_queue_head_safe(ngx_http_cp_async_ctx_t *ctx);

// Context nullification function
void ngx_cp_async_nullify_ctx_refs(ngx_http_cp_async_ctx_t *ctx);

// Forward declaration for find function
ngx_http_cp_async_ctx_t *ngx_cp_async_find_ctx(uint32_t session_id);

// Macro for safe context destruction with null assignment
#define SAFE_DESTROY_CTX(ctx_ptr) do { \
    if (ctx_ptr) { \
        ngx_cp_async_destroy_ctx(ctx_ptr); \
        ctx_ptr = NULL; \
    } \
} while(0)

#endif // __NGX_CP_ASYNC_CTX_VALIDATION_H__
