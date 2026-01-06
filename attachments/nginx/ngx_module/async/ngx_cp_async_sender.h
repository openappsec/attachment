#ifndef __NGX_CP_ASYNC_SENDER_H__
#define __NGX_CP_ASYNC_SENDER_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

#include "ngx_cp_async_core.h"
#include "nano_attachment_common.h"

ngx_int_t ngx_cp_async_wait_signal_sender(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent);

ngx_int_t ngx_cp_async_send_meta_data_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent);

ngx_int_t ngx_cp_async_wait_signal_sender(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent);

ngx_int_t ngx_cp_async_send_headers_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent);

ngx_int_t ngx_cp_async_send_end_transaction_nonblocking(ngx_http_cp_async_ctx_t *ctx, ngx_uint_t *num_messages_sent);

ngx_int_t
ngx_cp_async_send_single_body_chunk_nonblocking(
    ngx_http_cp_async_ctx_t *ctx,
    ngx_chain_t *chunk,
    ngx_uint_t *num_messages_sent
);

ngx_int_t
ngx_cp_async_send_to_agent_nonblocking(
    ngx_http_cp_async_ctx_t *ctx, 
    AttachmentDataType chunk_type,
    const void *data, 
    uint16_t data_size
);

#endif // __NGX_CP_ASYNC_SENDER_H__
