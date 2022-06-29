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

/// @file ngx_cp_http_parser.h
#ifndef __NGX_CP_HTTP_PARSER_H__
#define __NGX_CP_HTTP_PARSER_H__

#include <ngx_core.h>

#include "compression_utils.h"

/// @struct ngx_http_response_data
/// Holds all the data for NGINX CP http response data.
typedef struct {
    uint32_t          num_body_chunk; ///< Number of body chunks.

    /// NGINX Response data status
    ///     - #NGX_OK
    ///     - #NGX_ERROR
    ngx_int_t         response_data_status;

    /// Original compression type, can hold the following values:
    /// - #GZIP
    /// - #ZLIB
    CompressionType   original_compression_type;

    /// A new compression type, can hold the following values:
    /// - #GZIP
    /// - #ZLIB
    CompressionType   new_compression_type;

    /// Compression stream
    CompressionStream *compression_stream;

    /// Decompression stream
    CompressionStream *decompression_stream;
} ngx_http_response_data;

///
/// @brief Parses content encoding and returns it in response_encoding.
/// @param[in, out] response_encoding Returns value of one of the supported encoding:
///     - #GZIP
///     - #ZLIB
///     - #NO_COMPRESSION
/// @param[in, out] content_encoding_header_value Encoded value.
/// @return ngx_int_t
///     - #NGX_OK
///     - #NGX_ERROR - Unsupported encoding.
///
ngx_int_t
parse_content_encoding(
    CompressionType *response_encoding,
    const ngx_str_t *content_encoding_header_value
);

///
/// @brief Sets the content encoding type of the provided encoding header.
/// @param[in, out] content_encoding Returns variable of one of the supported encoding:
///     - #GZIP
///     - #ZLIB
///     - #NO_COMPRESSION
/// @param[in, out] content_encoding_header NGINX table Encoding header.
/// @return ngx_int_t
///     - #NGX_OK
///     - #NGX_ERROR - Unsupported encoding.
///
ngx_int_t
set_response_content_encoding(
    CompressionType *content_encoding,
    const ngx_table_elt_t *content_encoding_header
);

#endif // __NGX_CP_HTTP_PARSER_H__
