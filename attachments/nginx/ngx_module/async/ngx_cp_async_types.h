#ifndef __NGX_CP_ASYNC_TYPES_H__
#define __NGX_CP_ASYNC_TYPES_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// Forward declarations
typedef struct ngx_http_cp_async_ctx ngx_http_cp_async_ctx_t;
typedef struct ngx_http_cp_session_data ngx_http_cp_session_data;

/// @enum ngx_cp_async_stage_t
/// @brief Processing stages for async operations
typedef enum {
    NGX_CP_ASYNC_STAGE_INIT = 0,
    NGX_CP_ASYNC_STAGE_META_DATA,
    NGX_CP_ASYNC_STAGE_WAIT_META_VERDICT,
    NGX_CP_ASYNC_STAGE_HEADERS,
    NGX_CP_ASYNC_STAGE_WAIT_HEADER_VERDICT,
    NGX_CP_ASYNC_STAGE_END_TRANSACTION,
    NGX_CP_ASYNC_STAGE_WAIT_END_VERDICT,
    NGX_CP_ASYNC_STAGE_BODY,
    NGX_CP_ASYNC_STAGE_WAIT_BODY_VERDICT,
    NGX_CP_ASYNC_STAGE_VERDICT,
    NGX_CP_ASYNC_STAGE_COMPLETE,
    NGX_CP_ASYNC_STAGE_ERROR = -1
} ngx_cp_async_stage_t;

#endif // __NGX_CP_ASYNC_TYPES_H__
