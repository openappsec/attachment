#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_initializer.h"
#include "mock_nano_attachment_io.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_attachment_sender_thread.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentSenderThreadTest : public Test
{
public:
    void
    SetUp() override
    {
        EXPECT_CALL(
            initializer_mocker,
            nano_attachment_init_process(_)
        ).WillOnce(
            Return(NanoCommunicationResult::NANO_OK)
        );
        setenv("CLOUDGUARD_UID", "Testing", 1);
        attachment = InitNanoAttachment(
            static_cast<uint8_t>(AttachmentType::NGINX_ATT_ID),
            2,
            4,
            STDOUT_FILENO
        );
        EXPECT_NE(attachment, nullptr);
        attachment->dbg_level = nano_http_cp_debug_level::DBG_LEVEL_TRACE;

        session_data = InitSessionData(attachment, 1);
        EXPECT_NE(session_data, nullptr);
        start_data.session_data = session_data;
        req_header_data.session_data = session_data;
        res_header_data.session_data = session_data;
        req_body_data.session_data = session_data;
        res_body_data.session_data = session_data;
        req_end_data.session_data = session_data;
        res_end_data.session_data = session_data;
        delayed_verdict_data.session_data = session_data;
        req_filter_data.session_data = session_data;
    }

    void
    TearDown() override
    {
        FiniSessionData(attachment, session_data);
        FiniNanoAttachment(attachment);
    }

    nano_str_t
    create_nano_str(const char *str)
    {
        nano_str_t nano_str;
        nano_str.data = reinterpret_cast<unsigned char *>(const_cast<char *>(str));
        nano_str.len = strlen(str);
        return nano_str;
    }

    HttpMetaData http_meta_data = {
        create_nano_str("HTTP/1.1"),
        create_nano_str("GET"),
        create_nano_str("www.nanoattachmentut.com"),
        create_nano_str("192.168.1.100"),
        80,
        create_nano_str("/dogs.html"),
        create_nano_str("192.168.1.101"),
        253,
        create_nano_str("nanoattachmentut.com"),
        create_nano_str("/dogs.html")
    };

    HttpHeaderData http_headers[3] = {
        {
            create_nano_str("Host"),
            create_nano_str("www.nanoattachmentut.com")
        },
        {
            create_nano_str("User-Agent"),
            create_nano_str("Mozilla/5.0")
        },
        {
            create_nano_str("Accept"),
            create_nano_str("text/html")
        }
    };

    HttpHeaders http_headers_data = {
        http_headers,
        3
    };

    HttpRequestFilterData request_filter_data = {
        &http_meta_data,
        &http_headers_data,
        false
    };

    ResHttpHeaders res_http_headers_data = {
        &http_headers_data,
        static_cast<uint16_t>(522),
        static_cast<uint64_t>(300)
    };

    nano_str_t body[3] = {
        create_nano_str("Hello"),
        create_nano_str("World"),
        create_nano_str("!")
    };

    HttpBody http_body_data = {
        body,
        3
    };

    AttachmentData start_data = {
        1,
        HttpChunkType::HTTP_REQUEST_METADATA,
        session_data,
        (DataBuffer)&http_meta_data
    };

    AttachmentData req_header_data = {
        1,
        HttpChunkType::HTTP_REQUEST_HEADER,
        session_data,
        (DataBuffer)&http_headers_data
    };

    AttachmentData req_filter_data = {
        1,
        HttpChunkType::HTTP_REQUEST_FILTER,
        session_data,
        (DataBuffer)&request_filter_data
    };

    AttachmentData res_header_data = {
        1,
        HttpChunkType::HTTP_RESPONSE_HEADER,
        session_data,
        (DataBuffer)&res_http_headers_data
    };

    AttachmentData req_body_data = {
        1,
        HttpChunkType::HTTP_REQUEST_BODY,
        session_data,
        (DataBuffer)&http_body_data
    };

    AttachmentData res_body_data = {
        1,
        HttpChunkType::HTTP_RESPONSE_BODY,
        session_data,
        (DataBuffer)&http_body_data
    };

    AttachmentData req_end_data = {
        1,
        HttpChunkType::HTTP_REQUEST_END,
        session_data,
        NULL
    };

    AttachmentData res_end_data = {
        1,
        HttpChunkType::HTTP_RESPONSE_END,
        session_data,
        NULL
    };

    AttachmentData delayed_verdict_data = {
        1,
        HttpChunkType::HOLD_DATA,
        session_data,
        NULL
    };

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    StrictMock<NanoInitializerMocker> initializer_mocker;
    StrictMock<NanoAttachmentIoMocker> io_mocker;
};

TEST_F(NanoAttachmentSenderThreadTest, InitThreadCtx)
{
    HttpEventThreadCtx ctx;
    init_thread_ctx(&ctx, attachment, &req_body_data);
    EXPECT_EQ(ctx.attachment, attachment);
    EXPECT_EQ(ctx.data, &req_body_data);
    EXPECT_EQ(ctx.session_data_p, session_data);
    EXPECT_EQ(ctx.res, NanoCommunicationResult::NANO_OK);
    EXPECT_EQ(ctx.web_response_data, nullptr);
    EXPECT_EQ(ctx.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderThreadTest, RegistrationCommSocketThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        connect_to_comm_socket(attachment)
    );

    init_thread_ctx(&ctx, attachment, nullptr);
    RegistrationCommSocketThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, RegistrationSocketThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        connect_to_registration_socket(attachment)
    );

    init_thread_ctx(&ctx, attachment, nullptr);
    RegistrationSocketThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendMetadataThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_metadata_sender(
            attachment,
            (HttpMetaData *)start_data.data,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply,
            false
        )
    );

    init_thread_ctx(&ctx, attachment, &start_data);
    SendMetadataThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendRequestFilterThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_metadata_sender(
            attachment,
            (HttpMetaData *)start_data.data,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply,
            false
        )
    );

    EXPECT_CALL(
        io_mocker,
        nano_header_sender(
            attachment,
            (HttpHeaders *)req_header_data.data,
            &ctx,
            AttachmentDataType::REQUEST_HEADER,
            session_data->session_id,
            &session_data->remaining_messages_to_reply,
            false
        )
    );

    EXPECT_CALL(
        io_mocker,
        nano_end_transaction_sender(
            attachment,
            AttachmentDataType::REQUEST_END,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &req_filter_data);
    SendRequestFilterThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendRequestHeadersThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_header_sender(
            attachment,
            (HttpHeaders *)req_header_data.data,
            &ctx,
            AttachmentDataType::REQUEST_HEADER,
            session_data->session_id,
            &session_data->remaining_messages_to_reply,
            false
        )
    );

    init_thread_ctx(&ctx, attachment, &req_header_data);
    SendRequestHeadersThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendResponseHeadersThread)
{
    HttpEventThreadCtx ctx;
    ResHttpHeaders *res_headers = (ResHttpHeaders *)res_header_data.data;

    EXPECT_CALL(
        io_mocker,
        nano_send_response_code(
            attachment,
            static_cast<uint16_t>(522),
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    EXPECT_CALL(
        io_mocker,
        nano_send_response_content_length(
            attachment,
            static_cast<uint64_t>(300),
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    EXPECT_CALL(
        io_mocker,
        nano_header_sender(
            attachment,
            (HttpHeaders *)res_headers->headers,
            &ctx,
            AttachmentDataType::RESPONSE_HEADER,
            session_data->session_id,
            &session_data->remaining_messages_to_reply,
            false
        )
    );

    init_thread_ctx(&ctx, attachment, &res_header_data);
    SendResponseHeadersThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendRequestBodyThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_body_sender(
            attachment,
            (HttpBody *)req_body_data.data,
            &ctx,
            AttachmentDataType::REQUEST_BODY,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &req_body_data);
    SendRequestBodyThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendResponseBodyThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_body_sender(
            attachment,
            (HttpBody *)res_body_data.data,
            &ctx,
            AttachmentDataType::RESPONSE_BODY,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &res_body_data);
    SendResponseBodyThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendRequestEndThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_end_transaction_sender(
            attachment,
            AttachmentDataType::REQUEST_END,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &req_end_data);
    SendRequestEndThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendResponseEndThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_end_transaction_sender(
            attachment,
            AttachmentDataType::RESPONSE_END,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &res_end_data);
    SendResponseEndThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendDelayedVerdictRequestThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_request_delayed_verdict(
            attachment,
            &ctx,
            session_data->session_id,
            &session_data->remaining_messages_to_reply
        )
    );

    init_thread_ctx(&ctx, attachment, &delayed_verdict_data);
    SendDelayedVerdictRequestThread(&ctx);
}

TEST_F(NanoAttachmentSenderThreadTest, SendMetricToServiceThread)
{
    HttpEventThreadCtx ctx;

    EXPECT_CALL(
        io_mocker,
        nano_send_metric_data_sender(attachment)
    );

    init_thread_ctx(&ctx, attachment, &delayed_verdict_data);
    SendMetricToServiceThread(&ctx);
}
