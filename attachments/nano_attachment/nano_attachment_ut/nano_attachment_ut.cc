#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_socket.h"
#include "mock_nano_initializer.h"
#include "mock_nano_attachment_sender.h"
#include "mock_nano_configuration.h"

extern "C" {
#include "nano_attachment.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentTest : public Test
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

        session_data = InitSessionData(attachment, 1);
        EXPECT_NE(session_data, nullptr);
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

    WebResponseData *
    create_custom_drop_response_data()
    {
        WebResponseData *web_response_data = (WebResponseData *)malloc(sizeof(WebResponseData));
        web_response_data->web_response_type = NanoWebResponseType::CUSTOM_WEB_RESPONSE;
        memcpy(web_response_data->uuid, "TestThisIsUuidTest\0", 20);

        CustomResponseData *custom_response_data = (CustomResponseData *)malloc(sizeof(CustomResponseData));
        custom_response_data->response_code = 502;
        memcpy(custom_response_data->title, "Woof Woof\0", 10);
        memcpy(custom_response_data->body, "This is Ruby's barking\0", 24);

        web_response_data->data = custom_response_data;

        return web_response_data;
    }

    WebResponseData *
    create_redirect_response_data()
    {
        WebResponseData *web_response_data = (WebResponseData *)malloc(sizeof(WebResponseData));
        web_response_data->web_response_type = NanoWebResponseType::REDIRECT_WEB_RESPONSE;
        memcpy(web_response_data->uuid, "TestThisIsUuidTest\0", 20);

        RedirectData *redirect_response_data = (RedirectData *)malloc(sizeof(CustomResponseData));
        memcpy(redirect_response_data->redirect_location, "Woowwwiee.com\0", 15);

        web_response_data->data = redirect_response_data;

        return web_response_data;
    }

    NanoHttpModificationList *
    create_modifications_data()
    {
        NanoHttpModificationList *modification_node =
            (NanoHttpModificationList *)malloc(sizeof(NanoHttpModificationList));

        modification_node->next = NULL;
        modification_node->modification.mod_type = HttpModificationType::APPEND;
        modification_node->modification_buffer = NULL;

        return modification_node;
    }

    AttachmentVerdictResponse inspect_response = {
        AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT,
        1,
        NULL,
        NULL
    };

    AttachmentVerdictResponse accept_response = {
        AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT,
        1,
        NULL,
        NULL
    };

    AttachmentVerdictResponse custom_drop_response = {
        AttachmentVerdict::ATTACHMENT_VERDICT_DROP,
        1,
        NULL,
        NULL
    };

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

    AttachmentData req_body_data = {
        1,
        HttpChunkType::HTTP_REQUEST_BODY,
        session_data,
        (DataBuffer)&http_body_data
    };

    AttachmentData req_end_data = {
        1,
        HttpChunkType::HTTP_REQUEST_END,
        session_data,
        NULL
    };

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    StrictMock<NanoAttachmentSenderMocker> sender_mocker;
    StrictMock<NanoInitializerMocker> initializer_mocker;
    StrictMock<NanoSocketMocker> socket_mocker;
    StrictMock<NanoConfigurationMocker> configuration_mocker;
};

TEST_F(NanoAttachmentTest, InitNanoAttachment)
{
    EXPECT_EQ(strcmp(attachment->shared_verdict_signal_path, ""), 0);

    EXPECT_EQ(attachment->worker_id, 2);
    EXPECT_EQ(attachment->num_of_workers, 4);
    EXPECT_EQ(attachment->nano_user_id, getuid());
    EXPECT_EQ(attachment->nano_group_id, getgid());
    EXPECT_EQ(attachment->registration_socket, -1);
    EXPECT_EQ(attachment->attachment_type, static_cast<uint8_t>(AttachmentType::NGINX_ATT_ID));
    EXPECT_EQ(attachment->comm_socket, -1);
    EXPECT_EQ(attachment->logging_fd, STDOUT_FILENO);

    EXPECT_EQ(attachment->is_configuration_updated, NanoCommunicationResult::NANO_ERROR);
    EXPECT_EQ(attachment->current_config_version, 0u);
    EXPECT_EQ(attachment->dbg_level, nano_http_cp_debug_level::DBG_LEVEL_INFO);
    EXPECT_EQ(attachment->num_of_connection_attempts, 0);
    EXPECT_EQ(attachment->fail_open_timeout, 50u);
    EXPECT_EQ(attachment->fail_open_delayed_timeout, 150u);
    EXPECT_EQ(attachment->sessions_per_minute_limit_verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(attachment->max_sessions_per_minute, 0u);
    EXPECT_EQ(attachment->req_max_proccessing_ms_time, 3000u);
    EXPECT_EQ(attachment->res_max_proccessing_ms_time, 3000u);
    EXPECT_EQ(attachment->registration_thread_timeout_msec, 100u);
    EXPECT_EQ(attachment->req_start_thread_timeout_msec, 100u);
    EXPECT_EQ(attachment->req_header_thread_timeout_msec, 100u);
    EXPECT_EQ(attachment->req_body_thread_timeout_msec, 150u);
    EXPECT_EQ(attachment->res_header_thread_timeout_msec, 100u);
    EXPECT_EQ(attachment->res_body_thread_timeout_msec, 150u);
    EXPECT_EQ(attachment->waiting_for_verdict_thread_timeout_msec, 150u);
    EXPECT_EQ(attachment->inspection_mode, NanoHttpInspectionMode::NON_BLOCKING_THREAD);
    EXPECT_EQ(attachment->num_of_nano_ipc_elements, 200u);
    EXPECT_EQ(attachment->keep_alive_interval_msec, DEFAULT_KEEP_ALIVE_INTERVAL_MSEC);

    EXPECT_CALL(
        configuration_mocker,
        reset_attachment_config(_)
    ).WillOnce(
        Return(NanoCommunicationResult::NANO_OK)
    );

    RestartAttachmentConfiguration(attachment);
}

TEST_F(NanoAttachmentTest, InitSessionData)
{
    EXPECT_NE(session_data, nullptr);
    EXPECT_EQ(session_data->was_request_fully_inspected, 0);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_INSPECT);
    EXPECT_EQ(session_data->session_id, 1u);
    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->req_proccesing_time, 0u);
    EXPECT_EQ(session_data->res_proccesing_time, 0u);
    EXPECT_EQ(session_data->processed_req_body_size, 0u);
    EXPECT_EQ(session_data->processed_res_body_size, 0u);
    EXPECT_EQ(IsSessionFinalized(attachment, session_data), 0);
}

TEST_F(NanoAttachmentTest, AcceptFlow)
{
    EXPECT_CALL(sender_mocker, SendMetadata(attachment, &start_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestHeaders(attachment, &req_header_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestBody(attachment, &req_body_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestEnd(attachment, &req_end_data)).WillOnce(Return(accept_response));

    AttachmentVerdictResponse response = SendDataNanoAttachment(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);
}

TEST_F(NanoAttachmentTest, DropFlow)
{
    AttachmentVerdictResponse response;
    BlockPageData block_page_data;
    custom_drop_response.web_response_data = create_custom_drop_response_data();

    EXPECT_CALL(sender_mocker, SendMetadata(attachment, &start_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestHeaders(attachment, &req_header_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestBody(attachment, &req_body_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestEnd(attachment, &req_end_data)).WillOnce(Return(custom_drop_response));

    response = SendDataNanoAttachment(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_DROP);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::CUSTOM_WEB_RESPONSE);

    block_page_data = GetBlockPage(attachment, session_data, &response);
    EXPECT_EQ(block_page_data.response_code, 502);
    EXPECT_EQ(strcmp((char *)block_page_data.uuid.data, "TestThisIsUuidTest"), 0);
    EXPECT_EQ(strcmp((char *)block_page_data.title.data, "Woof Woof"), 0);
    EXPECT_EQ(strcmp((char *)block_page_data.body.data, "This is Ruby's barking"), 0);

    FreeAttachmentResponseContent(attachment, session_data, &response);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
}

TEST_F(NanoAttachmentTest, RedirectFlow)
{
    AttachmentVerdictResponse response;
    RedirectPageData redirect_page_data;
    custom_drop_response.web_response_data = create_redirect_response_data();

    EXPECT_CALL(sender_mocker, SendMetadata(attachment, &start_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestHeaders(attachment, &req_header_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestBody(attachment, &req_body_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestEnd(attachment, &req_end_data)).WillOnce(Return(custom_drop_response));

    response = SendDataNanoAttachment(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_DROP);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::REDIRECT_WEB_RESPONSE);

    redirect_page_data = GetRedirectPage(attachment, session_data, &response);
    EXPECT_EQ(strcmp((char *)redirect_page_data.redirect_location.data, "Woowwwiee.com"), 0);

    FreeAttachmentResponseContent(attachment, session_data, &response);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
}

TEST_F(NanoAttachmentTest, ModificationsFlow)
{
    AttachmentVerdictResponse response;
    NanoResponseModifications response_modifications;
    accept_response.modifications = create_modifications_data();

    EXPECT_CALL(sender_mocker, SendMetadata(attachment, &start_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestHeaders(attachment, &req_header_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestBody(attachment, &req_body_data)).WillOnce(Return(inspect_response));
    EXPECT_CALL(sender_mocker, SendRequestEnd(attachment, &req_end_data)).WillOnce(Return(accept_response));

    response = SendDataNanoAttachment(attachment, &start_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_header_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_body_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_INSPECT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    FreeAttachmentResponseContent(attachment, session_data, &response);

    response = SendDataNanoAttachment(attachment, &req_end_data);
    EXPECT_EQ(response.session_id, 1u);
    EXPECT_EQ(response.verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    EXPECT_EQ(IsResponseWithModification(attachment, session_data, &response), 1);
    response_modifications = GetResponseModifications(attachment, session_data, &response);
    EXPECT_NE(response_modifications.modifications, nullptr);
    EXPECT_EQ(response_modifications.modifications->next, nullptr);
    EXPECT_EQ(response_modifications.modifications->modification.mod_type, HttpModificationType::APPEND);

    FreeAttachmentResponseContent(attachment, session_data, &response);
    EXPECT_EQ(GetWebResponseType(attachment, session_data, &response), NanoWebResponseType::NO_WEB_RESPONSE);
    EXPECT_EQ(IsResponseWithModification(attachment, session_data, &response), 0);
}

TEST_F(NanoAttachmentTest, SendAlive)
{
    EXPECT_CALL(socket_mocker, socket(AF_UNIX, SOCK_STREAM, 0)).WillOnce(Return(34));
    EXPECT_CALL(socket_mocker, connect(34, _, _)).WillOnce(Return(0));
    EXPECT_CALL(initializer_mocker, write_to_service(attachment, _, _, _, _))
        .WillRepeatedly(Return(NanoCommunicationResult::NANO_OK));
    EXPECT_CALL(socket_mocker, close(34));
    SendKeepAlive(attachment);
}

TEST_F(NanoAttachmentTest, SendAliveFail)
{
    EXPECT_CALL(socket_mocker, socket(AF_UNIX, SOCK_STREAM, 0)).WillOnce(Return(34));
    EXPECT_CALL(socket_mocker, connect(34, _, _)).WillOnce(Return(-1));
    EXPECT_CALL(socket_mocker, close(34));
    SendKeepAlive(attachment);
}

TEST_F(NanoAttachmentTest, TestMetricUpdate)
{
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::INJECT_VERDICTS_COUNT)], 0u);
    UpdateMetric(attachment, AttachmentMetricType::INJECT_VERDICTS_COUNT, 100);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::INJECT_VERDICTS_COUNT)], 100u);
}

TEST_F(NanoAttachmentTest, SendAccumulatedMetricData)
{
    EXPECT_CALL(sender_mocker, SendMetricData(attachment)).WillOnce(Return(NanoCommunicationResult::NANO_OK));
    SendAccumulatedMetricData(attachment);
}
