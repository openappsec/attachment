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

/// @file ngx_cp_compression.c
#include "ngx_cp_compression.h"

#include "ngx_cp_utils.h"
#include "ngx_cp_metric.h"

static ngx_int_t is_debug_printing_initialized = 0;

ngx_int_t
is_compression_debug_printing_initialized()
{
    return is_debug_printing_initialized;
}

///
/// @brief Writes a debug message at a debug level of Trace.
/// @param[in] debug_message message to be written.
///
static void
compression_trace_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_TRACE, debug_message);
}

///
/// @brief Writes a debug message at a debug level of Debug.
/// @param[in] debug_message message to be written.
///
static void
compression_debug_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_DEBUG, debug_message);
}

///
/// @brief Writes a debug message at a debug level of Info.
/// @param[in] debug_message message to be written.
///
static void
compression_info_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_INFO, debug_message);
}

///
/// @brief Writes a debug message at a debug level of Warning.
/// @param[in] debug_message message to be written.
///
static void
compression_warning_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_WARNING, debug_message);
}

///
/// @brief Writes a debug message at a debug level of Error.
/// @param[in] debug_message message to be written.
///
static void
compression_error_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_ERROR, debug_message);
}

///
/// @brief Writes a debug message at a debug level of Assert.
/// @param[in] debug_message message to be written.
///
static void
compression_assert_level_debug_printer(const char *debug_message)
{
    write_dbg(DBG_LEVEL_ASSERT, debug_message);
}

void
initialize_compression_debug_printing()
{
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_TRACE, compression_trace_level_debug_printer);
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_DEBUG, compression_debug_level_debug_printer);
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_INFO, compression_info_level_debug_printer);
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_WARNING, compression_warning_level_debug_printer);
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_ERROR, compression_error_level_debug_printer);
    setCompressionDebugFunction(COMPRESSION_DBG_LEVEL_ASSERTION, compression_assert_level_debug_printer);

    is_debug_printing_initialized = 1;
}

///
/// @brief Checks if the compression buffer is valid.
/// @param[in] should_compress Checks if buffer can be used for compression.
///      - #0 - Buffer is used for decompression.
///      - #1 - Buffer is used for compression.
/// @param[in] buffer message to be written.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
is_valid_compression_buffer(const ngx_int_t should_compress, const ngx_buf_t *buffer)
{
    uint64_t buffer_size = buffer->last - buffer->pos;

    if (buffer_size == 0 && !should_compress) {
        write_dbg(DBG_LEVEL_WARNING, "Invalid decompression buffer: has size 0");
        return NGX_ERROR;
    }

    return NGX_OK;
}

///
/// @brief Gets the NGINX string data from NGINX buffer.
/// @param[in, out] buffer_data NGINX string, used as a destination.
/// @param[in] buffer NGINX buffer.
///
static void
get_buffer_data(ngx_str_t *buffer_data, const ngx_buf_t *buffer)
{
    if (buffer_data == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Passed a null pointer as destination buffer");
        return;
    }

    buffer_data->len = buffer->last - buffer->pos;
    buffer_data->data = buffer->pos;
}

///
/// @brief Sets the buffer from NGINX string to NGINX buffer.
/// @param[in, out] buffer NGINX buffer, used as a destination.
/// @param[in] buffer_data NGINX string.
///
static void
set_buffer_data(ngx_buf_t *buffer, const ngx_str_t *data)
{
    buffer->start = data->data;
    buffer->pos = buffer->start;
    buffer->last = buffer->start + data->len;
    buffer->end = buffer->last;
}

///
/// @brief Decompresses or compresses the provided data.
/// @param[in] should_compress Checks if buffer is used for compression or decompression.
///      - #0 - Function will decompression.
///      - #1 - Function will compress.
/// @param[in, out] compression_stream CompressionStream to compress.
/// @param[in] is_last_decompressed_part Flags if the buffer's last part was decompressed.
/// @param[in, out] output NGINX string to be used as output.
/// @param[in] input  NGINX string input to be used as input.
/// @param[in] pool NGINX pool.
/// @param[in, out] params Holds NGINX compression parameters.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
compression_data_filter(
    const ngx_int_t should_compress,
    CompressionStream *compression_stream,
    int *is_last_decompressed_part,
    ngx_str_t *output,
    ngx_str_t *input,
    ngx_pool_t *pool,
    ngx_cp_http_compression_params *params
)
{
    CompressionResult compression_result;

    write_dbg(DBG_LEVEL_TRACE, "Performing %s on buffer data", should_compress ? "compression" : "decompression");

    if (should_compress && params == NULL) {
        write_dbg(DBG_LEVEL_ASSERT, "Passed a pointer to null as compression parameters");
        return NGX_ERROR;
    }

    if (should_compress) {
        // Compressing data.
        compression_result = compressData(
            compression_stream,
            params->compression_type,
            input->len,
            input->data,
            params->is_last_part
        );
    } else {
        // Decompressing data.
        DecompressionResult decompression_result = decompressData(compression_stream, input->len, input->data);
        compression_result.ok = decompression_result.ok;
        compression_result.num_output_bytes = decompression_result.num_output_bytes;
        compression_result.output = decompression_result.output;
        *is_last_decompressed_part = decompression_result.is_last_chunk;
    }
    if (!compression_result.ok) return NGX_ERROR;

    if (compression_result.output == NULL) {
        output->len = 0;
        output->data = (u_char *)"";
    } else {
        output->len = compression_result.num_output_bytes;
        output->data = ngx_palloc(pool, output->len);
        if (output->data == NULL) {
            // Failed to allocate a new buffer.
            write_dbg(DBG_LEVEL_WARNING, "Failed to allocate a new buffer");

            return NGX_ERROR;
        }

        ngx_memcpy(output->data, compression_result.output, output->len);
        free(compression_result.output);
    }

    write_dbg(DBG_LEVEL_TRACE, "Successfully %s buffer data", should_compress ? "compressed" : "decompressed");

    return NGX_OK;
}

///
/// @brief Decompresses or compresses the provided buffer.
/// @param[in] should_compress Checks if buffer is used for compression or decompression.
///      - #0 - Function will decompression.
///      - #1 - Function will compress.
/// @param[in, out] compression_stream CompressionStream to compress.
/// @param[in] is_last_decompressed_part Flags if the buffer's last part was decompressed.
/// @param[in, out] dest NGINX buffer used as destination.
/// @param[in] src  NGINX buffer used as source.
/// @param[in] pool NGINX pool.
/// @param[in] params Holds NGINX compression parameters.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
compression_buffer_filter(
    const ngx_int_t should_compress,
    CompressionStream *compression_stream,
    int *is_last_decompressed_part,
    ngx_buf_t *dest,
    ngx_buf_t *src,
    ngx_pool_t *pool,
    ngx_cp_http_compression_params *params
)
{
    ngx_str_t src_data;
    ngx_str_t dest_data;
    ngx_int_t compression_result;

    write_dbg(DBG_LEVEL_TRACE, "Performing %s on buffer", should_compress ? "compression" : "decompression");

    if (is_valid_compression_buffer(should_compress, src) != NGX_OK) {
        // Invalid buffer provided.
        write_dbg(DBG_LEVEL_WARNING, "Failed to %s: invalid buffer", should_compress ? "compress" : "decompress");

        return NGX_ERROR;
    }

    if (should_compress) {
        // Preparing data for compression.
        params->is_last_part = src->last_buf;

        if (params->is_last_part && src->pos == NULL) {
            src->start = (u_char *)"";
            src->pos = src->start;
            src->last = src->start;
            src->end = src->start;
        }
    }

    get_buffer_data(&src_data, src);
    // Compresses the data
    compression_result = compression_data_filter(
        should_compress,
        compression_stream,
        is_last_decompressed_part,
        &dest_data,
        &src_data,
        pool,
        params
    );
    if (compression_result != NGX_OK) {
        // Failed to compress or decompress.
        write_dbg(DBG_LEVEL_WARNING, "Failed to %s data", should_compress ? "compress" : "decompress");

        return NGX_ERROR;
    }

    ngx_memcpy(dest, src, sizeof(ngx_buf_t));
    set_buffer_data(dest, &dest_data);

    write_dbg(DBG_LEVEL_TRACE, "Successfully %s buffer", should_compress ? "compressed" : "decompressed");

    return NGX_OK;
}

///
/// @brief Compresses the provided chain.
/// @param[in] should_compress Checks if buffer is used for compression or decompression.
///      - #0 - Function will decompression.
///      - #1 - Function will compress.
/// @param[in, out] compression_stream CompressionStream to compress.
/// @param[in] is_last_decompressed_part Flags if the buffer's last part was decompressed.
/// @param[in, out] body NGINX chain used as destination.
/// @param[in] original_body_contents  NGINX chain used as source.
/// @param[in] pool NGINX pool.
/// @param[in] params Holds NGINX cp compression parameters.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
compression_chain_filter(
    const ngx_int_t should_compress,
    CompressionStream *compression_stream,
    int *is_last_decompressed_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool,
    ngx_cp_http_compression_params *params
)
{
    ngx_int_t compression_result;
    ngx_buf_t *output_buffer = ngx_calloc_buf(pool);
    ngx_chain_t *curr_input_link = NULL;
    ngx_chain_t *curr_original_contents_link = original_body_contents == NULL ? NULL : *original_body_contents;

    if (body == NULL) {
        // Null body parameter has been passed.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to %s chain: passed null pointer as output chain",
            should_compress ? "compress" : "decompress"
        );
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_TRACE, "Performing %s on chain", should_compress ? "compression" : "decompression");

    for (curr_input_link = *body; curr_input_link != NULL; curr_input_link = curr_input_link->next) {
        // Decompress or compresses buffer
        compression_result = compression_buffer_filter(
            should_compress,
            compression_stream,
            is_last_decompressed_part,
            output_buffer,
            curr_input_link->buf,
            pool,
            params
        );
        if (compression_result != NGX_OK) {
            // Failed to decompress or compress.
            free_chain(pool, *body);

            return NGX_ERROR;
        }

        if (curr_original_contents_link != NULL) {
            curr_original_contents_link->buf = ngx_calloc_buf(pool);
            ngx_memcpy(curr_original_contents_link->buf, curr_input_link->buf, sizeof(ngx_buf_t));

            if (curr_input_link->next != NULL) {
                // Allocates next chain.
                curr_original_contents_link->next = ngx_alloc_chain_link(pool);
                ngx_memset(curr_original_contents_link->next, 0, sizeof(ngx_chain_t));
                curr_original_contents_link = curr_original_contents_link->next;
            }
        }

        ngx_memcpy(curr_input_link->buf, output_buffer, sizeof(ngx_buf_t));

        // Empty buffer should not be marked as "in-memory"
        if (curr_input_link->buf->last - curr_input_link->buf->pos != 0) {
            curr_input_link->buf->memory = 1;
        }
    }

    write_dbg(DBG_LEVEL_TRACE, "Successfully %s chain", should_compress ? "compressed" : "decompressed");

    return NGX_OK;
}

///
/// @brief Sets the ngx_cp_http_compression_params and calls compression_chain_filter with compression flag.
/// @param[in, out] compression_stream CompressionStream to compress.
/// @param[in] compression_type Compression type to be used by compressions.
/// @param[in] is_last_part Flags if the buffer's last part was compressed.
/// @param[in, out] body NGINX chain used as destination.
/// @param[in] original_body_contents  NGINX chain used as source.
/// @param[in] pool NGINX pool.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
compress_chain(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const int is_last_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool
)
{
    ngx_cp_http_compression_params params;
    params.compression_type = compression_type;
    params.is_last_part = is_last_part;

    return compression_chain_filter(1, compression_stream, NULL, body, original_body_contents, pool, &params);
}

///
/// @brief Sets the ngx_cp_http_compression_params and calls compression_chain_filter with decompression flag.
/// @param[in, out] compression_stream CompressionStream to compress.
/// @param[in] compression_type Compression type to be used by compressions.
/// @param[in] is_last_decompressed_part Flags if the buffer's last part was decompressed.
/// @param[in, out] body NGINX chain used as destination.
/// @param[in] original_body_contents  NGINX chain used as source.
/// @param[in] pool NGINX pool.
/// @returns ngx_int_t
///      - #NGX_OK
///      - #NGX_ERROR
///
static ngx_int_t
decompress_chain(
    CompressionStream *decompress_stream,
    int *is_last_decompressed_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body,
    ngx_pool_t *pool
)
{
    return
        compression_chain_filter(
            0,
            decompress_stream,
            is_last_decompressed_part,
            body,
            original_body,
            pool,
            NULL
        );
}

ngx_int_t
decompress_body(
    CompressionStream *decompression_stream,
    const ngx_http_chunk_type_e chunk_type,
    int *is_last_decompressed_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool
)
{
    char *body_type = chunk_type == REQUEST_BODY ? "request" : "response";

    write_dbg(DBG_LEVEL_TRACE, "Decompressing %s body", body_type);

    ngx_int_t decompress_data_res = decompress_chain(
        decompression_stream,
        is_last_decompressed_part,
        body,
        original_body_contents,
        pool
    );
    if (decompress_data_res != NGX_OK) {
        // Failed to decompress the provided data.
        write_dbg(DBG_LEVEL_WARNING, "Failed to decompress %s body", body_type);
        updateMetricField(
            chunk_type == REQUEST_BODY ? REQ_FAILED_DECOMPRESSION_COUNT : RES_FAILED_DECOMPRESSION_COUNT,
            1
        );
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_TRACE, "Successfully decompressed %s body", body_type);
    updateMetricField(
        chunk_type == REQUEST_BODY ? REQ_SUCCESSFUL_DECOMPRESSION_COUNT : RES_SUCCESSFUL_DECOMPRESSION_COUNT,
        1
    );

    return NGX_OK;
}

ngx_int_t
compress_body(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const ngx_http_chunk_type_e chunk_type,
    const int is_last_part,
    ngx_chain_t **body,
    ngx_chain_t **original_body_contents,
    ngx_pool_t *pool
)
{
    ngx_int_t compress_res;
    char *body_type;

    if (compression_type == NO_COMPRESSION) {
        // This function should not be called with a NO_COMPRESSION type.
        // This if statement serves a case that somewhere throughout the code the data
        // is set to be compressed but the compression type is wrongly set. 
        write_dbg(DBG_LEVEL_WARNING, "Invalid compression type: NO_COMPRESSION");
        return NGX_ERROR;
    }

    body_type = chunk_type == REQUEST_BODY ? "request" : "response";
    write_dbg(
        DBG_LEVEL_TRACE,
        "Compressing plain-text %s body in the format \"%s\"",
        body_type,
        compression_type == GZIP ? "gzip" : "zlib"
    );
    // Checks if the compression was successful.
    compress_res = compress_chain(
        compression_stream,
        compression_type,
        is_last_part,
        body,
        original_body_contents,
        pool
    );
    if (compress_res != NGX_OK) {
        // Failed to compress the body.
        write_dbg(DBG_LEVEL_WARNING, "Failed to compress %s body", body_type);
        updateMetricField(
            chunk_type == REQUEST_BODY ? REQ_FAILED_COMPRESSION_COUNT : RES_FAILED_COMPRESSION_COUNT,
            1
        );
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_TRACE, "Successfully compressed %s body", body_type);
    updateMetricField(
        chunk_type == REQUEST_BODY ? REQ_SUCCESSFUL_COMPRESSION_COUNT : RES_SUCCESSFUL_COMPRESSION_COUNT,
        1
    );

    return NGX_OK;
}
