#include "nano_attachment_bucket.h"

#include <string.h>

#include "nano_utils.h"

#define CP_ASYNC_CTX_BUCKETS 2048 ///< Hash table buckets for better distribution

///
/// @brief Hash function for session IDs using Knuth's multiplicative method
/// @param[in] session_id Session ID to hash
/// @return Hash bucket index
///
static uint
nano_attachment_async_ctx_hash(SessionID session_id)
{
    // Knuth's multiplicative hash with golden ratio constant
    static const uint32_t KNUTH_CONSTANT = 2654435761U; // (sqrt(5) - 1) / 2 * 2^32
    return (session_id * KNUTH_CONSTANT) % CP_ASYNC_CTX_BUCKETS;
}

AttachmentVerdictResponse
NanoAsyncFindResponse(NanoAttachment *attachment, SessionID session_id)
{
    AttachmentVerdictResponse response;
    uint bucket = nano_attachment_async_ctx_hash(session_id);

    response.verdict = attachment->async_buckets[bucket].verdict;
    response.session_id = attachment->async_buckets[bucket].session_id;
    response.modifications = attachment->async_buckets[bucket].modifications;
    response.web_response_data = attachment->async_buckets[bucket].web_response_data;

    return response;
}

AttachmentVerdictResponse
GenerateFailedVerdict(NanoAttachment *attachment, SessionID session_id)
{
    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_WARNING,
        "No verdict response found for session ID: %d, generating failed verdict",
        session_id
    );

    AttachmentVerdictResponse failed_response;

    failed_response.session_id = session_id;
    if (attachment->fail_mode_verdict == NANO_OK) {
        failed_response.verdict = ATTACHMENT_VERDICT_ACCEPT;
    } else {
        failed_response.verdict = ATTACHMENT_VERDICT_DROP;
    }
    failed_response.web_response_data = NULL;
    failed_response.modifications = NULL;

    return failed_response;
}

NanoCommunicationResult
NanoAsyncAddResponse(NanoAttachment *attachment, SessionID session_id, AttachmentVerdictResponse *response)
{
    uint bucket;

    if (response == NULL) {
        return NANO_ERROR;
    }

    bucket = nano_attachment_async_ctx_hash(session_id);
    attachment->async_buckets[bucket].session_id = response->session_id;
    attachment->async_buckets[bucket].verdict = response->verdict;
    attachment->async_buckets[bucket].modifications = response->modifications;
    attachment->async_buckets[bucket].web_response_data = response->web_response_data;
    return NANO_OK;
}

void
NanoAsyncRemoveResponse(NanoAttachment *attachment, SessionID session_id)
{
    uint bucket = nano_attachment_async_ctx_hash(session_id);
    memset(&attachment->async_buckets[bucket], 0, sizeof(AttachmentVerdictResponse));
    attachment->async_buckets[bucket].verdict = ATTACHMENT_VERDICT_INSPECT;
}

bool
NanoAsyncFailedSessionIDQueueIsEmpty(NanoAttachment *attachment)
{
    if (attachment == NULL) {
        return 1;
    }

    return attachment->async_failed_bucket.count == 0;
}

NanoCommunicationResult
NanoAsyncFailedSessionIDQueueAdd(NanoAttachment *attachment, SessionID session_id)
{
    if (attachment == NULL) {
        return NANO_ERROR;
    }

    SessionIDQueue *queue = &attachment->async_failed_bucket;

    if (queue->count >= SESSION_ID_QUEUE_SIZE) {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_TRACE,
            "Session ID queue is full, cannot add session ID: %u",
            session_id
        );
        return NANO_ERROR;
    }

    queue->queue[queue->tail] = session_id;
    queue->tail = (queue->tail + 1) % SESSION_ID_QUEUE_SIZE;
    queue->count++;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Added session ID to queue: %u (count: %u)",
        session_id,
        queue->count
    );

    return NANO_OK;
}

SessionID
NanoAsyncFailedSessionIDQueuePop(NanoAttachment *attachment)
{
    if (attachment == NULL) {
        return 0;
    }

    SessionIDQueue *queue = &attachment->async_failed_bucket;

    if (queue->count == 0) {
        return 0;
    }

    SessionID session_id = queue->queue[queue->head];
    queue->head = (queue->head + 1) % SESSION_ID_QUEUE_SIZE;
    queue->count--;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Popped session ID from queue: %u (count: %u)",
        session_id,
        queue->count
    );

    return session_id;
}
