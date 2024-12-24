#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_initializer.h"
#include "mock_nano_attachment_thread.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_attachment_sender.h"
#include "nano_attachment_sender_thread.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentSenderTest : public Test
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
        attachment->dbg_level = nano_http_cp_debug_level_e::DBG_LEVEL_TRACE;

        session_data = InitSessionData(attachment, 1);
        EXPECT_NE(session_data, nullptr);
        start_data.session_data = session_data;
        req_header_data.session_data = session_data;
        res_header_data.session_data = session_data;
        req_body_data.session_data = session_data;
        res_body_data.session_data = session_data;
        req_end_data.session_data = session_data;
        res_end_data.session_data = session_data;
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

    void
    NanoRunInThreadTimeoutInvoker(
        AttachmentData *data,
        void *arg,
        NanoCommunicationResult com_res,
        ServiceVerdict verdict
    )
    {

        HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)arg;
        init_thread_ctx(ctx, attachment, data);

        ctx->session_data_p = data->session_data;
        ctx->res = com_res;
        ctx->session_data_p->verdict = verdict;
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

    AttachmentData req_filter_data = {
        1,
        HttpChunkType::HTTP_REQUEST_FILTER,
        session_data,
        (DataBuffer)&request_filter_data
    };

    AttachmentData req_header_data = {
        1,
        HttpChunkType::HTTP_REQUEST_HEADER,
        session_data,
        (DataBuffer)&http_headers_data
    };

    AttachmentData res_header_data = {
        1,
        HttpChunkType::HTTP_RESPONSE_HEADER,
        session_data,
        (DataBuffer)&http_headers_data
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

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    StrictMock<NanoInitializerMocker> initializer_mocker;
    StrictMock<NanoAttachmentThreadMocker> thread_mocker;
};

TEST_F(NanoAttachmentSenderTest, SendRequestCorruptMemory)
{
    AttachmentVerdictResponse response;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_ERROR)
    );

    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestFailOpenDrop)
{
    AttachmentVerdictResponse response;
    CustomResponseData *custom_response_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_ERROR)
    );

    attachment->fail_mode_verdict = static_cast<int>(NanoCommunicationResult::NANO_HTTP_FORBIDDEN);
    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_DROP);
    EXPECT_NE(response.web_response_data, nullptr);
    EXPECT_EQ(response.web_response_data->web_response_type, NanoWebResponseType::CUSTOM_WEB_RESPONSE);
    EXPECT_STREQ(
        reinterpret_cast<const char *>(
            response.web_response_data->uuid
        ),
        "20118dba-81f7-4999-8e94-003cf242f5dd"
    );
    EXPECT_NE(response.web_response_data->data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);

    custom_response_data = (CustomResponseData *)response.web_response_data->data;
    EXPECT_EQ(custom_response_data->response_code, 403);
    EXPECT_STREQ(reinterpret_cast<const char *>(custom_response_data->title), "Default Title");
    EXPECT_STREQ(reinterpret_cast<const char *>(custom_response_data->body), "Default Body");
}

TEST_F(NanoAttachmentSenderTest, SendRequestTimeout)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &start_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_TIMEOUT,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(0))
    );

    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestIrrelevant)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &start_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_DECLINED,
                    ServiceVerdict::TRAFFIC_VERDICT_ACCEPT
                );
            }
        ),
        Return(1))
    );

    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestFailed)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &start_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_ERROR,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestFilter)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &req_filter_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendRequestFilter(attachment, &req_filter_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendMetadata)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &start_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendMetadata(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestHeaders)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &req_header_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendRequestHeaders(attachment, &req_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendResponseHeaders)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &res_header_data,
            _,
            _,
            _,
            _,
            TransactionType::RESPONSE
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendResponseHeaders(attachment, &res_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestBody)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &req_body_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendRequestBody(attachment, &req_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendResponseBody)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &res_body_data,
            _,
            _,
            _,
            _,
            TransactionType::RESPONSE
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_INSPECT
                );
            }
        ),
        Return(1))
    );

    response = SendResponseBody(attachment, &res_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendRequestEnd)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &req_end_data,
            _,
            _,
            _,
            _,
            TransactionType::REQUEST
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_ACCEPT
                );
            }
        ),
        Return(1))
    );

    response = SendRequestEnd(attachment, &req_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendResponseEnd)
{
    AttachmentVerdictResponse response;
    void *_ctx;
    AttachmentData *_attachment_data;

    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            &res_end_data,
            _,
            _,
            _,
            _,
            TransactionType::RESPONSE
        )
    ).WillOnce(DoAll(SaveArg<1>(&_attachment_data), SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    _attachment_data,
                    _ctx,
                    NanoCommunicationResult::NANO_OK,
                    ServiceVerdict::TRAFFIC_VERDICT_ACCEPT
                );
            }
        ),
        Return(1))
    );

    response = SendResponseEnd(attachment, &res_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(response.web_response_data, nullptr);
    EXPECT_EQ(response.modifications, nullptr);
}

TEST_F(NanoAttachmentSenderTest, SendMetricData)
{
    EXPECT_CALL(
        initializer_mocker,
        handle_shmem_corruption(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
    );

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            attachment,
            _,
            _,
            _,
            _,
            _,
            TransactionType::METRICS
        )
    ).WillOnce(Return(1));

    SendMetricData(attachment);
}
