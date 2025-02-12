#include "nano_compression.h"

#include <stdlib.h>

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "compression_utils.h"
#include "nano_utils.h"

HttpBody *
nano_compress_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
)
{
    CompressionResult compression_result;
    HttpBody *compressed_body;
    size_t i;

    if (session_data_p->response_data.compression_type == NO_COMPRESSION) {
        return NULL;
    }
    write_dbg(
        attachment,
        session_data_p->session_id,
        DBG_LEVEL_TRACE,
        "Compressing body"
    );

    if (session_data_p->response_data.compression_stream == NULL) {
        session_data_p->response_data.compression_stream = initCompressionStream();
    }

    compressed_body = malloc(sizeof(HttpBody));
    if (compressed_body == NULL) {
        return NULL;
    }

    compressed_body->bodies_count = bodies->bodies_count;
    compressed_body->data = malloc(bodies->bodies_count * sizeof(nano_str_t));
    if (compressed_body->data == NULL) {
        free(compressed_body);
        return NULL;
    }

    for (i = 0; i < bodies->bodies_count; ++i) {
        compression_result = compressData(
            session_data_p->response_data.compression_stream,
            session_data_p->response_data.compression_type,
            bodies->data[i].len,
            bodies->data[i].data,
            i == bodies->bodies_count - 1
        );
        compressed_body->data[i].len = compression_result.num_output_bytes;
        compressed_body->data[i].data = compression_result.output;
    }

    return compressed_body;
}

HttpBody *
nano_decompress_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
)
{
    DecompressionResult decompression_result;
    HttpBody *decompressed_body;
    size_t i;

    if (session_data_p->response_data.compression_type == NO_COMPRESSION) {
        return NULL;
    }
    write_dbg(
        attachment,
        session_data_p->session_id,
        DBG_LEVEL_TRACE,
        "Decompressing body"
    );

    if (session_data_p->response_data.decompression_stream == NULL) {
        session_data_p->response_data.decompression_stream = initCompressionStream();
    }

    decompressed_body = malloc(sizeof(HttpBody));
    if (decompressed_body == NULL) {
        return NULL;
    }

    decompressed_body->bodies_count = bodies->bodies_count;
    decompressed_body->data = malloc(bodies->bodies_count * sizeof(nano_str_t));
    if (decompressed_body->data == NULL) {
        free(decompressed_body);
        return NULL;
    }

    for (i = 0; i < bodies->bodies_count; ++i) {
        decompression_result = decompressData(
            session_data_p->response_data.decompression_stream,
            bodies->data[i].len,
            bodies->data[i].data
        );
        decompressed_body->data[i].len = decompression_result.num_output_bytes;
        decompressed_body->data[i].data = decompression_result.output;
    }

    return decompressed_body;
}

void
nano_free_compressed_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
)
{
    if (bodies == NULL) {
        return;
    }
    write_dbg(
        attachment,
        session_data_p->session_id,
        DBG_LEVEL_TRACE,
        "Freeing compressed body"
    );
    free(bodies->data);
    free(bodies);
}
