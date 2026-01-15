/// @file nano_attachment_bucket.h
#ifndef __NANO_ATTACHMENT_BUCKET_H__
#define __NANO_ATTACHMENT_BUCKET_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

#define CP_ASYNC_CTX_BUCKETS 2048 ///< Hash table buckets for better distribution

AttachmentVerdictResponse NanoAsyncFindResponse(NanoAttachment *attachment, SessionID session_id);

NanoCommunicationResult NanoAsyncAddResponse(NanoAttachment *attachment, SessionID session_id, AttachmentVerdictResponse *response);

void NanoAsyncRemoveResponse(NanoAttachment *attachment, SessionID session_id);
#endif // __NANO_ATTACHMENT_BUCKET_H__
