/// @file nano_attachment_bucket.h
#ifndef __NANO_ATTACHMENT_BUCKET_H__
#define __NANO_ATTACHMENT_BUCKET_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

#define CP_ASYNC_CTX_BUCKETS 2048 ///< Hash table buckets for better distribution

typedef struct NanoAttachment NanoAttachment;

AttachmentVerdictResponse NanoAsyncFindResponse(NanoAttachment *attachment, SessionID session_id);

NanoCommunicationResult NanoAsyncAddResponse(NanoAttachment *attachment, SessionID session_id, AttachmentVerdictResponse *response);

AttachmentVerdictResponse GenerateFailedVerdict(NanoAttachment *attachment, SessionID session_id);

void NanoAsyncRemoveResponse(NanoAttachment *attachment, SessionID session_id);

bool NanoAsyncFailedSessionIDQueueIsEmpty(NanoAttachment *attachment);

NanoCommunicationResult NanoAsyncFailedSessionIDQueueAdd(NanoAttachment *attachment, SessionID session_id);

SessionID NanoAsyncFailedSessionIDQueuePop(NanoAttachment *attachment);

#endif // __NANO_ATTACHMENT_BUCKET_H__
