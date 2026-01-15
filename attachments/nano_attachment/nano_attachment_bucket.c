#include "nano_attachment_bucket.h"

#include <string.h>

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

    response.verdict = attachment->async_buckets[bucket]->verdict;
    response.session_id = attachment->async_buckets[bucket]->session_id;
    response.modifications = attachment->async_buckets[bucket]->modifications;
    response.web_response_data = attachment->async_buckets[bucket]->web_response_data;
    
    return response;
}

NanoCommunicationResult
NanoAsyncAddResponse(NanoAttachment *attachment, SessionID session_id, AttachmentVerdictResponse *response)
{
    uint bucket;
    
    if (response == NULL) {
        return NANO_ERROR;
    }

    bucket = nano_attachment_async_ctx_hash(session_id);
    attachment->async_buckets[bucket]->session_id = response->session_id;
    attachment->async_buckets[bucket]->verdict = response->verdict;
    attachment->async_buckets[bucket]->modifications = response->modifications;
    attachment->async_buckets[bucket]->web_response_data = response->web_response_data;
    return NANO_OK;
}

void
NanoAsyncRemoveResponse(NanoAttachment *attachment, SessionID session_id)
{
    uint bucket = nano_attachment_async_ctx_hash(session_id);
    memset(&attachment->async_buckets[bucket], 0, sizeof(AttachmentVerdictResponse));
    attachment->async_buckets[bucket].verdict = ATTACHMENT_VERDICT_INSPECT;
}
