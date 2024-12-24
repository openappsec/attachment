#include "nano_attachment_sender.h"

#include <time.h>
#include <stdlib.h>

#include "nano_attachment_sender_thread.h"
#include "nano_attachment_thread.h"
#include "nano_utils.h"
#include "nano_attachment_metric.h"

static unsigned char default_uuid[] = "20118dba-81f7-4999-8e94-003cf242f5dd\0";
static const size_t default_uuid_size = 37;

static unsigned char default_title[] = "Default Title\0";
static const size_t default_title_size = 14;

static unsigned char default_body[] = "Default Body\0";
static const size_t default_body_size = 13;

static uint16_t default_response_code = 403;

///
/// @brief Creates a default block page.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @return A pointer to a WebResponseData struct containing the default block page data.
///
static WebResponseData*
CreateDefaultBlockPage(NanoAttachment *attachment, SessionID session_id)
{
    WebResponseData *web_response_data = NULL;
    CustomResponseData *custom_response_data = NULL;

    web_response_data = (WebResponseData *)malloc(sizeof(WebResponseData));
    if (web_response_data == NULL) {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_WARNING,
            "Failed to allocate memory for WebResponseData"
        );
        return NULL;
    }

    custom_response_data = (CustomResponseData *)malloc(sizeof(CustomResponseData));
    if (custom_response_data == NULL) {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_WARNING,
            "Failed to allocate memory for CustomResponseData"
        );
        free(web_response_data);
        return NULL;
    }

    web_response_data->web_response_type = CUSTOM_WEB_RESPONSE;
    memcpy(web_response_data->uuid, default_uuid, default_uuid_size);
    custom_response_data->response_code = default_response_code;
    memcpy(custom_response_data->title, default_title, default_title_size);
    memcpy(custom_response_data->body, default_body, default_body_size);
    web_response_data->data = (DataBuffer*)custom_response_data;

    return web_response_data;
}

///
/// @brief Get a string representation of the AttachmentVerdict enum.
///
/// @param verdict The AttachmentVerdict enum value.
/// @return A string representation of the enum value.
///
static const char*
AttachmentVerdictToString(AttachmentVerdict verdict)
{
    switch (verdict) {
        case ATTACHMENT_VERDICT_INSPECT:
            return "inspect";
        case ATTACHMENT_VERDICT_ACCEPT:
            return "accept";
        case ATTACHMENT_VERDICT_DROP:
            return "drop";
        case ATTACHMENT_VERDICT_INJECT:
            return "inject";
        default:
            return "unknown";
    }
}

///
/// @brief Sends a verdict response for a corrupt memory condition.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_data_p Pointer to the HttpSessionData struct containing the session data.
/// @return An AttachmentVerdictResponse struct containing the session ID and verdict.
///
static AttachmentVerdictResponse
SendCorruptMemoryVerdict(NanoAttachment *attachment, HttpSessionData *session_data_p)
{
    AttachmentVerdictResponse response = {
        .session_id = session_data_p->session_id,
        .web_response_data = NULL,
        .modifications = NULL
    };

    if (attachment->fail_mode_verdict == NANO_OK) {
        updateMetricField(attachment, INSPECTION_OPEN_FAILURES_COUNT, 1);
        response.verdict = ATTACHMENT_VERDICT_ACCEPT;
        session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
    } else {
        updateMetricField(attachment, INSPECTION_CLOSE_FAILURES_COUNT, 1);
        response.verdict = ATTACHMENT_VERDICT_DROP;
        session_data_p->verdict = TRAFFIC_VERDICT_DROP;
        response.web_response_data = CreateDefaultBlockPage(attachment, session_data_p->session_id);
    }

    write_dbg(
        attachment,
        response.session_id,
        DBG_LEVEL_DEBUG,
        "Shared memory is corrupted, returning default fail mode verdict. Session id: %d, verdict: %s",
        response.session_id,
        response.verdict == ATTACHMENT_VERDICT_ACCEPT ? "accept" : "drop"
    );
    return response;
}

///
/// @brief Sends a verdict response for a thread timeout condition.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the HTTP event context.
/// @return An AttachmentVerdictResponse struct containing the session ID and verdict.
///
static AttachmentVerdictResponse
SendThreadTimeoutVerdict(NanoAttachment *attachment, SessionID session_id, HttpEventThreadCtx *ctx)
{
    AttachmentVerdictResponse response = {
        .session_id = session_id,
        .web_response_data = NULL,
        .modifications = NULL
    };

    if (attachment->fail_mode_verdict == NANO_OK) {
        response.verdict = ATTACHMENT_VERDICT_ACCEPT;
        ctx->session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
    } else {
        response.verdict = ATTACHMENT_VERDICT_DROP;
        ctx->session_data_p->verdict = TRAFFIC_VERDICT_DROP;
        response.web_response_data = CreateDefaultBlockPage(attachment, session_id);
    }

    write_dbg(
        attachment,
        response.session_id,
        DBG_LEVEL_DEBUG,
        "Thread failed, returning fail mode verdict. Session id: %d, verdict: %s",
        response.session_id,
        response.verdict == ATTACHMENT_VERDICT_ACCEPT ? "accept" : "drop"
    );
    return response;
}

///
/// @brief Finalizes a successful response by determining the verdict based on the HTTP response code.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the HTTP event context.
/// @return An AttachmentVerdictResponse struct containing the session ID and verdict.
///
static AttachmentVerdictResponse
FinalizeSuccessfulResponse(
    NanoAttachment *attachment,
    SessionID session_id,
    HttpEventThreadCtx *ctx
)
{
    AttachmentVerdictResponse response = {
        .session_id = session_id,
        .web_response_data = ctx->web_response_data,
        .modifications = ctx->modifications
    };

    switch (ctx->session_data_p->verdict) {
        case TRAFFIC_VERDICT_INSPECT:
            response.verdict = ATTACHMENT_VERDICT_INSPECT;
        break;
        case TRAFFIC_VERDICT_ACCEPT:
            response.verdict = ATTACHMENT_VERDICT_ACCEPT;
            break;
        case TRAFFIC_VERDICT_DROP:
            response.verdict = ATTACHMENT_VERDICT_DROP;
            break;
        case TRAFFIC_VERDICT_INJECT:
            // Not yet supported
            response.verdict = ATTACHMENT_VERDICT_INSPECT;
            break;
        default:
            write_dbg(
                attachment,
                session_id,
                DBG_LEVEL_WARNING,
                "Unknown verdict %d",
                ctx->session_data_p->verdict
            );
            response.verdict = ATTACHMENT_VERDICT_INSPECT;
            break;
    }

    updateMetricField(attachment, INSPECTION_SUCCESSES_COUNT, 1);

    write_dbg(
        attachment,
        response.session_id,
        DBG_LEVEL_DEBUG,
        "Finalizing successful response to Session id: %d, verdict: %s",
        response.session_id,
        AttachmentVerdictToString(response.verdict)
    );
    return response;
}

///
/// @brief Finalizes an irrelevant response by setting the verdict to accept.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @return An AttachmentVerdictResponse struct containing the session ID and verdict.
///
static AttachmentVerdictResponse
FinalizeIrrelevantResponse(NanoAttachment *attachment, SessionID session_id)
{
    AttachmentVerdictResponse response = {
        .verdict = ATTACHMENT_VERDICT_ACCEPT,
        .session_id = session_id,
        .web_response_data = NULL,
        .modifications = NULL
    };

    updateMetricField(attachment, IRRELEVANT_VERDICTS_COUNT, 1);

    write_dbg(
        attachment,
        response.session_id,
        DBG_LEVEL_TRACE,
        "Finalizing irrelevant response to Session id: %d",
        response.session_id
    );
    return response;
}

///
/// @brief Finalizes a failed response by determining the verdict
/// based on the fail mode verdict associated with the attachment.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the HTTP event context.
/// @return An AttachmentVerdictResponse struct containing the session ID and verdict.
///
static AttachmentVerdictResponse
FinalizeFailedResponse(NanoAttachment *attachment, SessionID session_id, HttpEventThreadCtx *ctx)
{
    AttachmentVerdictResponse response = {
        .session_id = session_id,
        .web_response_data = NULL,
        .modifications = NULL
    };

    if (attachment->fail_mode_verdict == NANO_OK) {
        updateMetricField(attachment, INSPECTION_OPEN_FAILURES_COUNT, 1);
        response.verdict = ATTACHMENT_VERDICT_ACCEPT;
        ctx->session_data_p->verdict = TRAFFIC_VERDICT_ACCEPT;
    } else {
        updateMetricField(attachment, INSPECTION_CLOSE_FAILURES_COUNT, 1);
        response.verdict = ATTACHMENT_VERDICT_DROP;
        ctx->session_data_p->verdict = TRAFFIC_VERDICT_DROP;
        response.web_response_data = CreateDefaultBlockPage(attachment, session_id);
    }

    write_dbg(
        attachment,
        response.session_id,
        DBG_LEVEL_TRACE,
        "Handling Failure with fail %s mode",
        response.verdict == ATTACHMENT_VERDICT_ACCEPT ? "open" : "close"
    );
    return response;
}

AttachmentVerdictResponse
SendRequestFilter(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Request filter handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendRequestFilterThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendRequestFilterThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        "SendRequestFilterThread",
        REQUEST
    );

    if (!res) {
        updateMetricField(attachment, REQ_METADATA_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendMetadataThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res == NANO_DECLINED) {
        return FinalizeIrrelevantResponse(attachment, session_id);
    }

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendMetadata(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Request start handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendMetadataThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendMetadataThread,
        (void *)&ctx,
        attachment->req_start_thread_timeout_msec,
        "SendMetadataThread",
        REQUEST
    );

    if (!res) {
        updateMetricField(attachment, REQ_METADATA_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendMetadataThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res == NANO_DECLINED) {
        return FinalizeIrrelevantResponse(attachment, session_id);
    }

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendRequestHeaders(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Request header handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendRequestHeadersThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendRequestHeadersThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        "SendRequestHeadersThread",
        REQUEST
    );

    if (!res) {
        updateMetricField(attachment, REQ_HEADER_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendRequestHeadersThread successfully. res=%d",
        ctx.res
    );

    if (session_data_p->verdict == TRAFFIC_VERDICT_DELAYED) {
        write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendDelayedVerdictRequestThread");
        res = NanoRunInThreadTimeout(
            attachment,
            data,
            SendDelayedVerdictRequestThread,
            (void *)&ctx,
            attachment->waiting_for_verdict_thread_timeout_msec,
            "SendDelayedVerdictRequestThread",
            REQUEST
        );
        if (!res) {
            updateMetricField(attachment, HOLD_THREAD_TIMEOUT, 1);
            return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
        }

        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_DEBUG,
            "finished SendDelayedVerdictRequestThread successfully. res=%d",
            ctx.res
        );
    }

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendResponseHeaders(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Response header handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendResponseHeadersThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendResponseHeadersThread,
        (void *)&ctx,
        attachment->res_header_thread_timeout_msec,
        "SendResponseHeadersThread",
        RESPONSE
    );

    if (!res) {
        updateMetricField(attachment, RES_HEADER_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendResponseHeadersThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendRequestBody(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "Request body handling session ID: %d", session_id);

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendRequestBodyThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendRequestBodyThread,
        (void *)&ctx,
        attachment->req_body_thread_timeout_msec,
        "SendRequestBodyThread",
        REQUEST
    );

    if (!res) {
        updateMetricField(attachment, REQ_BODY_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendRequestBodyThread successfully. res=%d",
        ctx.res
    );

    if (session_data_p->verdict == TRAFFIC_VERDICT_DELAYED) {
        write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendDelayedVerdictRequestThread");
        res = NanoRunInThreadTimeout(
            attachment,
            data,
            SendDelayedVerdictRequestThread,
            (void *)&ctx,
            attachment->waiting_for_verdict_thread_timeout_msec,
            "SendDelayedVerdictRequestThread",
            REQUEST
        );
        if (!res) {
            updateMetricField(attachment, HOLD_THREAD_TIMEOUT, 1);
            return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
        }

        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_DEBUG,
            "finished SendDelayedVerdictRequestThread successfully. res=%d",
            ctx.res
        );
    }

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendResponseBody(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "Response body handling session ID: %d", session_id);

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendResponseBodyThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendResponseBodyThread,
        (void *)&ctx,
        attachment->res_body_thread_timeout_msec,
        "SendResponseBodyThread",
        RESPONSE
    );

    if (!res) {
        updateMetricField(attachment, RES_BODY_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendResponseBodyThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendRequestEnd(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Request end handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendRequestEndThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendRequestEndThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        "SendRequestEndThread",
        REQUEST
    );

    if (!res) {
        updateMetricField(attachment, REQ_END_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendRequestEndThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

AttachmentVerdictResponse
SendResponseEnd(NanoAttachment *attachment, AttachmentData *data)
{
    HttpEventThreadCtx ctx;
    HttpSessionData *session_data_p = data->session_data;
    SessionID session_id = session_data_p->session_id;
    int res;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Response end handling session ID: %d",
        session_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        return SendCorruptMemoryVerdict(attachment, session_data_p);
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "spawn SendResponseEndThread");
    res = NanoRunInThreadTimeout(
        attachment,
        data,
        SendResponseEndThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        "SendResponseEndThread",
        RESPONSE
    );

    if (!res) {
        updateMetricField(attachment, RES_END_THREAD_TIMEOUT, 1);
        return SendThreadTimeoutVerdict(attachment, session_id, &ctx);
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "finished SendResponseEndThread successfully. res=%d",
        ctx.res
    );

    if (ctx.res != NANO_HTTP_FORBIDDEN && ctx.res != NANO_OK) {
        return FinalizeFailedResponse(attachment, session_id, &ctx);
    }

    return FinalizeSuccessfulResponse(attachment, session_id, &ctx);
}

NanoCommunicationResult
SendMetricData(NanoAttachment *attachment)
{
    HttpEventThreadCtx ctx;
    int res;

    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Sending metric data saved in worker ID: %d",
        attachment->worker_id
    );

    if (handle_shmem_corruption(attachment) == NANO_ERROR) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_DEBUG,
            "Failed to send metric data, shmem corruption Worker ID: %d",
            attachment->worker_id
        );
        return NANO_ERROR;
    }

    res = NanoRunInThreadTimeout(
        attachment,
        NULL,
        SendMetricToServiceThread,
        (void *)&ctx,
        attachment->metric_timeout_timeout,
        "SendMetricToServiceThread",
        METRICS
    );

    if (!res) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_DEBUG,
            "Thread timeout while sending metric data from worker ID: %d",
            attachment->worker_id
        );
        return NANO_ERROR;
    }

    return NANO_OK;
}
