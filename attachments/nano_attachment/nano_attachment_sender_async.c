#include "nano_attachment_sender_async.h"

#include <string.h>

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "nano_attachment_io.h"
#include "nano_attachment_sender_thread.h"
#include "nano_utils.h"
#include "nano_attachment_bucket.h"

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
        is_verdict_requested,
        SIGNAL_USAGE_ASYNC
    );

    if (ctx.res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return ctx.res;
    }

    NanoCommunicationResult signal_res = signal_for_session_data(attachment, session_data_p->session_id, REQUEST_START, SIGNAL_USAGE_ASYNC);
    if (signal_res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return signal_res;
    }

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
        is_verdict_requested,
        SIGNAL_USAGE_ASYNC
    );

    if (ctx.res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return ctx.res;
    }

    NanoCommunicationResult signal_res = signal_for_session_data(attachment, session_data_p->session_id, REQUEST_HEADER, SIGNAL_USAGE_ASYNC);
    if (signal_res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return signal_res;
    }

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
        false,
        SIGNAL_USAGE_ASYNC
    );

    if (ctx.res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return ctx.res;
    }

    NanoCommunicationResult signal_res = signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_BODY, SIGNAL_USAGE_ASYNC);
    if (signal_res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return signal_res;
    }

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
        false,
        SIGNAL_USAGE_ASYNC
    );

    if (ctx.res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return ctx.res;
    }

    NanoCommunicationResult signal_res = signal_for_session_data(attachment, session_data_p->session_id, HTTP_REQUEST_END, SIGNAL_USAGE_ASYNC);
    if (signal_res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return signal_res;
    }

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
        false,
        SIGNAL_USAGE_ASYNC
    );

    if (ctx.res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return ctx.res;
    }

    NanoCommunicationResult signal_res = signal_for_session_data(attachment, session_data_p->session_id, HOLD_DATA, SIGNAL_USAGE_ASYNC);
    if (signal_res != NANO_OK) {
        NanoAsyncFailedSessionIDQueueAdd(attachment, session_data_p->session_id);
        return signal_res;
    }

    return ctx.res;
}
