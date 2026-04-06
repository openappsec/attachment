#ifndef __NGX_CP_ASYNC_HEADERS_H__
#define __NGX_CP_ASYNC_HEADERS_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

ngx_int_t ngx_http_cp_res_header_filter_async(ngx_http_request_t *request);
ngx_int_t ngx_http_cp_req_header_handler_async(ngx_http_request_t *request);

#endif // __NGX_CP_ASYNC_HEADERS_H__
