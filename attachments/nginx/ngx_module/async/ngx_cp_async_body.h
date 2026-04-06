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

/// @file ngx_cp_async_body.h
/// 
/// Body async filter processing for Check Point Nano Agent NGINX module.
/// 

#ifndef __NGX_CP_ASYNC_BODY_H__
#define __NGX_CP_ASYNC_BODY_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

ngx_int_t ngx_http_cp_res_body_filter_async(ngx_http_request_t *request, ngx_chain_t *body_chain);
ngx_int_t ngx_http_cp_req_body_filter_async(ngx_http_request_t *r, ngx_chain_t *in);

#endif // __NGX_CP_ASYNC_BODY_H__
