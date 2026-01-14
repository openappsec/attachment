#include "nano_attachment_sender_async.h"

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "nano_attachment_io.h"
#include "nano_attachment_sender_thread.h"

NanoCommunicationResult
RegistrationCommSocketAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
RegistrationSocketAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
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

    return ctx.res;
}

NanoCommunicationResult
SendResponseHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    ResHttpHeaders *headers
)
{
    (void)attachment;
    (void)session_data_p;
    (void)headers;
    return NANO_OK;
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

    return ctx.res;
}

NanoCommunicationResult
SendResponseBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
)
{
    (void)attachment;
    (void)session_data_p;
    (void)bodies;
    return NANO_OK;
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

    return ctx.res;
}

NanoCommunicationResult
SendResponseEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendDelayedVerdictRequestAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendMetricToServiceAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}
