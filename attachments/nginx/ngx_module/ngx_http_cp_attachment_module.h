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

/// @file ngx_http_cp_attachment_module.h
#ifndef __NGX_HTTP_CP_ATTACHMENT_MODULE_H__
#define __NGX_HTTP_CP_ATTACHMENT_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_http_output_header_filter_pt ngx_http_next_response_header_filter; ///< NGINX response header filter.

extern ngx_http_request_body_filter_pt ngx_http_next_request_body_filter; ///< NGINX request body filter.
extern ngx_http_output_body_filter_pt ngx_http_next_response_body_filter; ///< NGINX output body filter.

extern ngx_module_t ngx_http_cp_attachment_module; ///< NGINX Module.

///
/// @brief Returns if NGINX CP attachment is disabled.
/// @param[in] request NGINX request.
/// @returns ngx_int_t
///         - #0 attachment is enabled.
///         - #1 attachment is disabled.
///
ngx_int_t is_ngx_cp_attachment_disabled(ngx_http_request_t *request);

///
/// @brief Get the number of workers.
/// @param[in] request NGINX request.
/// @returns ngx_uint_t returns number of workers.
///
ngx_uint_t get_num_of_workers(ngx_http_request_t *request);

///
/// @brief Set module config.
/// @param[in] request NGINX request.
/// @param[in] new_state NGINX flag to set.
///
void ngx_cp_set_module_loc_conf(ngx_http_request_t *request, ngx_flag_t new_state);

#endif // __NGX_HTTP_CP_ATTACHMENT_MODULE_H__
