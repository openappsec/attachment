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

/// @file ngx_cp_custom_response.h
#ifndef __NGX_CP_CUSTOM_RESPONSE_H__
#define __NGX_CP_CUSTOM_RESPONSE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "nginx_attachment_common.h"

/// @struct ngx_http_cp_modification_list
/// @brief A node that holds all the information regarding modifications.
typedef struct ngx_http_cp_modification_list {
    struct ngx_http_cp_modification_list *next; ///< Next node.
    ngx_http_cp_inject_data_t modification; ///< Modification data.
    char *modification_buffer; ///< Modification buffer used to store extra needed data.
} ngx_http_cp_modification_list;

///
/// @brief Generates and sends a response headers.
/// @param[in, out] request NGINX request.
/// @param[in] response_code Response code.
/// @param[in] content_length Content length.
/// @param[in] last_modified_time Last modification time.
/// @param[in] allow_ranges Allowed ranges.
/// @param[in] keepalive Keep alive metadata.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_response_headers_sender(
    ngx_http_request_t *request,
    const ngx_uint_t response_code,
    const off_t content_length,
    const time_t last_modified_time,
    const unsigned int allow_ranges,
    const unsigned int keepalive
);

///
/// @brief Generates and sends a response file.
/// @param[in, out] request NGINX request.
/// @param[in, out] file_path NGINX string.
/// @param[in, out] open_file_info NGINX file info - file information.
/// @param[in] is_main_request Flags if the file is the main request.
/// @param[in] log NGINX log.
/// @param[in] memory_pool NGINX pool.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_file_response_sender(
    ngx_http_request_t *request,
    ngx_str_t *file_path,
    ngx_open_file_info_t *open_file_info,
    ngx_int_t is_main_request,
    ngx_log_t *log,
    ngx_pool_t *memory_pool
);

///
/// @brief Finalizing a rejected request.
/// @param[in, out] request NGINX request.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t ngx_http_cp_finalize_rejected_request(ngx_http_request_t *request);

///
/// @brief Modifies headers with the provided modifiers.
/// @param[in, out] headers NGINX headers list.
/// @param[in] modifications CP modification list.
/// @param[in, out] request NGINX request.
/// @param[in] is_content_length Flag that signals if the header is of content length.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_header_modifier(
    ngx_list_t *headers,
    ngx_http_cp_modification_list *modifications,
    ngx_http_request_t *request,
    ngx_flag_t is_content_length
);

///
/// @brief Modifies body chain with the provided modifiers.
/// @param[in, out] body_chain NGINX body chain.
/// @param[in] modifications CP modification list.
/// @param[in, out] modification_pool NGINX pool for modifications.
/// @return ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
ngx_http_cp_body_modifier(
    ngx_chain_t *body_chain,
    ngx_http_cp_modification_list *modifications,
    ngx_pool_t *modification_pool
);

#endif // __NGX_CP_CUSTOM_RESPONSE_H__
