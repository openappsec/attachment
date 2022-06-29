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

/// @file ngx_cp_compression.h
#ifndef __NGX_CP_COMPRESSION_H__
#define __NGX_CP_COMPRESSION_H__

#include <ngx_core.h>

#include "nginx_attachment_common.h"
#include "compression_utils.h"

/// @struct ngx_cp_http_compression_params
/// @brief Holds all the information regarding NGINX compression.
typedef struct {
    ngx_int_t       is_last_part;
    CompressionType compression_type;
} ngx_cp_http_compression_params;

///
/// @brief Returns compression debug printing initialization status.
/// @returns ngx_int_t;
///         - #0 Debug printing is not initialized.
///         - #1 Debug printing is initialized.
///
ngx_int_t is_compression_debug_printing_initialized();

///
/// @brief Initialize compression debug printing.
///
void initialize_compression_debug_printing();

///
/// @brief Decompress the provided body stream.
/// @param[in, out] decompression_stream CompressionStream to decompress.
/// @param[in] chunk_type Body chunk type:
///      - #REQUEST_BODY
///      - #RESPONSE_BODY
/// @param[in, out] is_last_decompressed_part Flags if the buffer's last part was decompressed.
/// @param[in] body NGINX chain, serves as an output.
/// @param[in] original_body_contents NGINX chain, serves as an input to be decompressed.
/// @param[in, out] pool NGINX pool.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
decompress_body(
    CompressionStream *decompression_stream,
    const ngx_http_chunk_type_e chunk_type,
    int *is_last_decompressed_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool
);

///
/// @brief Compresses the provided body stream.
/// @details Provided by the body, body type (Response/Request) and stream. 
/// Compresses the provided body by using the provided compression stream.
/// @param[in, out] decompression_stream CompressionStream to compress.
/// @param[in] compression_type Compression type.
///      - #GZIP
///      - #ZLIB
///      - #NO_COMPRESSION - Serves as a sanity check in case this function is called
///         on a compression type of data that isn't defined and will return NGX_ERROR. 
/// @param[in] chunk_type Body chunk type:
///      - #REQUEST_BODY
///      - #RESPONSE_BODY
/// @param[in, out] is_last_part Saves the value if last part was compressed.
/// @param[in] body NGINX chain.
/// @param[in] original_body_contents NGINX chain, serves as an input to be compressed.
/// @param[in, out] pool NGINX pool.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
ngx_int_t
compress_body(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const ngx_http_chunk_type_e chunk_type,
    const int is_last_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool
);

#endif // __NGX_CP_COMPRESSION_H__
