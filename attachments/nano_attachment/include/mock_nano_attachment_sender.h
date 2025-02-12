#ifndef __MOCK_NANO_ATTACHMENT_SENDER_H__
#define __MOCK_NANO_ATTACHMENT_SENDER_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_attachment_sender.h"
}

class NanoAttachmentSenderMocker : public CMockMocker<NanoAttachmentSenderMocker>
{
public:
    MOCK_METHOD2(SendMetadata, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendRequestHeaders, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendResponseHeaders, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendRequestBody, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendResponseBody, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendRequestEnd, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD2(SendResponseEnd, AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data));
    MOCK_METHOD1(SendMetricData, NanoCommunicationResult(NanoAttachment *attachment));
};

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendMetadata,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendRequestHeaders,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendResponseHeaders,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendRequestBody,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendResponseBody,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendRequestEnd,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION2(
    NanoAttachmentSenderMocker,
    SendResponseEnd,
    AttachmentVerdictResponse(NanoAttachment *attachment, AttachmentData *data)
);

CMOCK_MOCK_FUNCTION1(
    NanoAttachmentSenderMocker,
    SendMetricData,
    NanoCommunicationResult(NanoAttachment *attachment)
);

#endif // __MOCK_NANO_ATTACHMENT_SENDER_H__
