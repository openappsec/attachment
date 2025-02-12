#ifndef __MOCK_NANO_INITIALIZER_IO_H__
#define __MOCK_NANO_INITIALIZER_IO_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_attachment_io.h"
}

class NanoAttachmentIoMocker : public CMockMocker<NanoAttachmentIoMocker>
{
public:
    MOCK_METHOD1(
        connect_to_comm_socket,
        NanoCommunicationResult(NanoAttachment *attachment)
    );

    MOCK_METHOD1(
        connect_to_registration_socket,
        NanoCommunicationResult(NanoAttachment *attachment)
    );

    MOCK_METHOD6(
        nano_metadata_sender,
        void(
            NanoAttachment *attachment,
            HttpMetaData *metadata,
            HttpEventThreadCtx *ctx,
            uint32_t cur_request_id,
            unsigned int *num_of_messages_sent,
            bool is_verdict_requested
        )
    );

    MOCK_METHOD7(
        nano_header_sender,
        void(
            NanoAttachment *attachment,
            HttpHeaders *headers,
            HttpEventThreadCtx *ctx,
            AttachmentDataType header_type,
            uint32_t cur_request_id,
            unsigned int *num_messages_sent,
            bool is_verdict_requested
        )
    );

    MOCK_METHOD5(
        nano_send_response_code,
        void(
            NanoAttachment *attachment,
            uint16_t response_code,
            HttpEventThreadCtx *ctx,
            uint32_t cur_request_id,
            unsigned int *num_messages_sent
        )
    );

    MOCK_METHOD5(
        nano_send_response_content_length,
        void(
            NanoAttachment *attachment,
            uint64_t content_length,
            HttpEventThreadCtx *ctx,
            uint32_t cur_request_id,
            unsigned int *num_messages_sent
        )
    );

    MOCK_METHOD6(
        nano_body_sender,
        void(
            NanoAttachment *attachment,
            HttpBody *bodies,
            HttpEventThreadCtx *ctx,
            AttachmentDataType body_type,
            uint32_t cur_request_id,
            unsigned int *num_messages_sent
        )
    );

    MOCK_METHOD5(
        nano_end_transaction_sender,
        void(
            NanoAttachment *attachment,
            AttachmentDataType end_transaction_type,
            HttpEventThreadCtx *ctx,
            SessionID cur_request_id,
            unsigned int *num_messages_sent
        )
    );

    MOCK_METHOD4(
        nano_request_delayed_verdict,
        void(
            NanoAttachment *attachment,
            HttpEventThreadCtx *ctx,
            SessionID cur_request_id,
            unsigned int *num_messages_sent
        )
    );

    MOCK_METHOD1(nano_send_metric_data_sender, void(NanoAttachment *Attachment));
};

CMOCK_MOCK_FUNCTION1(
    NanoAttachmentIoMocker,
    connect_to_comm_socket,
    NanoCommunicationResult(NanoAttachment *attachment)
);

CMOCK_MOCK_FUNCTION1(
    NanoAttachmentIoMocker,
    connect_to_registration_socket,
    NanoCommunicationResult(NanoAttachment *attachment)
);

CMOCK_MOCK_FUNCTION6(
    NanoAttachmentIoMocker,
    nano_metadata_sender,
    void(
        NanoAttachment *attachment,
        HttpMetaData *metadata,
        HttpEventThreadCtx *ctx,
        uint32_t cur_request_id,
        unsigned int *num_of_messages_sent,
        bool is_verdict_requested
    )
);

CMOCK_MOCK_FUNCTION7(
    NanoAttachmentIoMocker,
    nano_header_sender,
    void(
        NanoAttachment *attachment,
        HttpHeaders *headers,
        HttpEventThreadCtx *ctx,
        AttachmentDataType header_type,
        uint32_t cur_request_id,
        unsigned int *num_messages_sent,
        bool is_verdict_requested
    )
);

CMOCK_MOCK_FUNCTION5(
    NanoAttachmentIoMocker,
    nano_send_response_code,
    void(
        NanoAttachment *attachment,
        uint16_t response_code,
        HttpEventThreadCtx *ctx,
        uint32_t cur_request_id,
        unsigned int *num_messages_sent
    )
);

CMOCK_MOCK_FUNCTION5(
    NanoAttachmentIoMocker,
    nano_send_response_content_length,
    void(
        NanoAttachment *attachment,
        uint64_t content_length,
        HttpEventThreadCtx *ctx,
        uint32_t cur_request_id,
        unsigned int *num_messages_sent
    )
);


CMOCK_MOCK_FUNCTION6(
    NanoAttachmentIoMocker,
    nano_body_sender,
    void(
        NanoAttachment *attachment,
        HttpBody *bodies,
        HttpEventThreadCtx *ctx,
        AttachmentDataType body_type,
        uint32_t cur_request_id,
        unsigned int *num_messages_sent
    )
);

CMOCK_MOCK_FUNCTION5(
    NanoAttachmentIoMocker,
    nano_end_transaction_sender,
    void(
        NanoAttachment *attachment,
        AttachmentDataType end_transaction_type,
        HttpEventThreadCtx *ctx,
        SessionID cur_request_id,
        unsigned int *num_messages_sent
    )
);

CMOCK_MOCK_FUNCTION4(
    NanoAttachmentIoMocker,
    nano_request_delayed_verdict,
    void(
        NanoAttachment *attachment,
        HttpEventThreadCtx *ctx,
        SessionID cur_request_id,
        unsigned int *num_messages_sent
    )
);

CMOCK_MOCK_FUNCTION1(
    NanoAttachmentIoMocker,
    nano_send_metric_data_sender,
    void(NanoAttachment *Attachment)
);

#endif // __MOCK_NANO_INITIALIZER_IO_H__
