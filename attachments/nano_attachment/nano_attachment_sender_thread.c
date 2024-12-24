#include "nano_attachment_sender_thread.h"

#include "nano_initializer.h"
#include "nano_attachment_sender.h"
#include "nano_attachment_common.h"
#include "nano_attachment_io.h"

void
init_thread_ctx(HttpEventThreadCtx *ctx, NanoAttachment *attachment, AttachmentData *data)
{
    ctx->attachment = attachment;
    ctx->data = data;
    ctx->session_data_p = (data == NULL) ? NULL : data->session_data;
    ctx->res = NANO_OK;
    ctx->web_response_data = NULL;
    ctx->modifications = NULL;
}

void *
RegistrationCommSocketThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    NanoAttachment *attachment = ctx->attachment;

    ctx->res = connect_to_comm_socket(attachment);

    return NULL;
}

void *
RegistrationSocketThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    NanoAttachment *attachment = ctx->attachment;

    ctx->res = connect_to_registration_socket(attachment);
    return 0;
}

void *
SendRequestFilterThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;

    HttpRequestFilterData *start_data = (HttpRequestFilterData*)ctx->data->data;
    HttpMetaData *metadata = start_data->meta_data;
    HttpHeaders *headers = start_data->req_headers;
    bool contains_body = start_data->contains_body;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;
    bool is_verdict_requested = false;

    nano_metadata_sender(
        attachment,
        metadata,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    nano_header_sender(
        attachment,
        headers,
        ctx,
        REQUEST_HEADER,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    if (!contains_body) {
        nano_end_transaction_sender(
            attachment,
            REQUEST_END,
            ctx,
            session_data_p->session_id,
            &session_data_p->remaining_messages_to_reply
        );
    }

    return NULL;
}

void *
SendMetadataThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    HttpMetaData *metadata = (HttpMetaData*)ctx->data->data;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;
    bool is_verdict_requested = false;

    nano_metadata_sender(
        attachment,
        metadata,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    return NULL;
}

void *
SendRequestHeadersThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    HttpHeaders *headers = (HttpHeaders*)ctx->data->data;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;
    bool is_verdict_requested = false;

    nano_header_sender(
        attachment,
        headers,
        ctx,
        REQUEST_HEADER,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    return NULL;
}

void *
SendResponseHeadersThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    ResHttpHeaders *headers = (ResHttpHeaders*)ctx->data->data;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;
    HttpHeaders *http_headers = headers->headers;
    bool is_verdict_requested = false;

    nano_send_response_code(
        attachment,
        headers->response_code,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    nano_send_response_content_length(
        attachment,
        headers->content_length,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    nano_header_sender(
        attachment,
        http_headers,
        ctx,
        RESPONSE_HEADER,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply,
        is_verdict_requested
    );

    return NULL;
}

void *
SendRequestBodyThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    HttpBody *bodies = (HttpBody*)ctx->data->data;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;

    nano_body_sender(
        attachment,
        bodies,
        ctx,
        REQUEST_BODY,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    return NULL;
}

void *
SendResponseBodyThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    HttpBody *bodies = (HttpBody*)ctx->data->data;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;

    nano_body_sender(
        attachment,
        bodies,
        ctx,
        RESPONSE_BODY,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    return NULL;
}

void *
SendRequestEndThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;

    nano_end_transaction_sender(
        attachment,
        REQUEST_END,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    return NULL;
}

void *
SendResponseEndThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;

    nano_end_transaction_sender(
        attachment,
        RESPONSE_END,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    return NULL;
}

void *
SendDelayedVerdictRequestThread(void *_ctx)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_ctx;
    NanoAttachment *attachment = ctx->attachment;
    HttpSessionData *session_data_p = ctx->session_data_p;

    nano_request_delayed_verdict(
        attachment,
        ctx,
        session_data_p->session_id,
        &session_data_p->remaining_messages_to_reply
    );

    return NULL;
}

void *
SendMetricToServiceThread(void *_data)
{
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)_data;
    NanoAttachment *attachment = ctx->attachment;

    nano_send_metric_data_sender(attachment);

    return NULL;
}
