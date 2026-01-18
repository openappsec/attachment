#include "nano_attachment_sender_async.h"

#include <string.h>

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "nano_attachment_io.h"
#include "nano_attachment_sender_thread.h"

static HttpHeaderData *
get_http_header(HttpHeaders *http_headers, const char *header_name) {
    size_t i;
    for (i = 0; i < http_headers->headers_count; ++i) {
        if (strcasecmp((char*)http_headers->data[i].key.data, header_name) == 0) {
            return &http_headers->data[i];
        }
    }
    return NULL;
}

static void
set_response_content_encoding(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpHeaders *http_headers
)
{
    write_dbg(
        attachment,
        session_data_p->session_id,
        DBG_LEVEL_TRACE,
        "Determining response body's content encoding"
    );

    const HttpHeaderData *content_encoding = get_http_header(http_headers, "content-encoding");

    if (content_encoding == NULL) {
        session_data_p->response_data.compression_type = NO_COMPRESSION;
        return;
    }

    if (strcasecmp((char*)content_encoding->value.data, "gzip") == 0) {
        session_data_p->response_data.compression_type = GZIP;
    } else if (strcasecmp((char*)content_encoding->value.data, "deflate") == 0) {
        session_data_p->response_data.compression_type = ZLIB;
    } else if (strcasecmp((char*)content_encoding->value.data, "identity") == 0) {
        session_data_p->response_data.compression_type = NO_COMPRESSION;
    } else {
        write_dbg(
            attachment,
            session_data_p->session_id,
            DBG_LEVEL_WARNING,
            "Unsupported response content encoding: %.*s",
            content_encoding->value.data
        );
        session_data_p->response_data.compression_type = NO_COMPRESSION;
    }
}

NanoCommunicationResult
SendRequestFilterAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpRequestFilterData *start_data
)
{
    NanoCommunicationResult res;

    if (start_data == NULL) {
        return NANO_ERROR;
    }

    if (start_data->meta_data != NULL) {
        res = SendMetadataAsyncImpl(attachment, session_data_p, start_data->meta_data);
        if (res != NANO_OK) {
            return res;
        }
    }

    if (start_data->req_headers != NULL) {
        res = SendRequestHeadersAsyncImpl(attachment, session_data_p, start_data->req_headers);
        if (res != NANO_OK) {
            return res;
        }
    }

    if (!start_data->contains_body) {
        res = SendRequestEndAsyncImpl(attachment, session_data_p);
        if (res != NANO_OK) {
            return res;
        }
    }

    return NANO_OK;
}

NanoCommunicationResult
SendMetadataAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpMetaData *metadata
)
{
    HttpEventThreadCtx ctx;
    bool is_verdict_requested = false;

    if (attachment == NULL || session_data_p == NULL || metadata == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_metadata_sender(
        attachment,
        metadata,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_METADATA);

    return ctx.res;
}

NanoCommunicationResult
SendRequestHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpHeaders *headers
)
{
    HttpEventThreadCtx ctx;
    bool is_verdict_requested = false;

    if (attachment == NULL || session_data_p == NULL || headers == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_header_sender(
        attachment,
        headers,
        &ctx,
        REQUEST_HEADER,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_HEADER);

    return ctx.res;
}

NanoCommunicationResult
SendResponseHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    ResHttpHeaders *headers
)
{
    HttpEventThreadCtx ctx;
    HttpHeaders *http_headers;

    if (attachment == NULL || session_data_p == NULL || headers == NULL) {
        return NANO_ERROR;
    }

    http_headers = headers->headers;

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_send_response_code(
        attachment,
        headers->response_code,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    nano_send_response_content_length(
        attachment,
        headers->content_length,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    if (http_headers != NULL) {
        set_response_content_encoding(
            attachment,
            session_data_p,
            http_headers
        );

        nano_header_sender(
            attachment,
            http_headers,
            &ctx,
            RESPONSE_HEADER,
            session_data_p->session_id,
            &session_data_p->remaining_messages_to_reply,
            false
        );
    }

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_RESPONSE_HEADER);

    return ctx.res;
}

NanoCommunicationResult
SendRequestBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
)
{
    HttpEventThreadCtx ctx;

    if (attachment == NULL || session_data_p == NULL || bodies == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_body_sender(
        attachment,
        bodies,
        &ctx,
        REQUEST_BODY,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        false
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_BODY);

    return ctx.res;
}

NanoCommunicationResult
SendResponseBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
)
{
    HttpEventThreadCtx ctx;

    if (attachment == NULL || session_data_p == NULL || bodies == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_body_sender(
        attachment,
        bodies,
        &ctx,
        RESPONSE_BODY,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        false
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_RESPONSE_BODY);

    return ctx.res;
}

NanoCommunicationResult
SendRequestEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    HttpEventThreadCtx ctx;

    if (attachment == NULL || session_data_p == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_end_transaction_sender(
        attachment,
        REQUEST_END,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        false
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_END);

    return ctx.res;
}

NanoCommunicationResult
SendResponseEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    HttpEventThreadCtx ctx;

    if (attachment == NULL || session_data_p == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_end_transaction_sender(
        attachment,
        RESPONSE_END,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        false
    );

    signal_for_session_data(attachment, session_data_p->session_id, HTTP_RESPONSE_END);

    return ctx.res;
}

NanoCommunicationResult
SendDelayedVerdictRequestAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    HttpEventThreadCtx ctx;

    if (attachment == NULL || session_data_p == NULL) {
        return NANO_ERROR;
    }

    ctx.attachment = attachment;
    ctx.data = NULL;
    ctx.session_data_p = session_data_p;
    ctx.res = NANO_OK;
    ctx.web_response_data = NULL;
    ctx.modifications = NULL;

    nano_request_delayed_verdict(
        attachment,
        &ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        false
    );

    signal_for_session_data(attachment, session_data_p->session_id, HOLD_DATA);

    return ctx.res;
}
