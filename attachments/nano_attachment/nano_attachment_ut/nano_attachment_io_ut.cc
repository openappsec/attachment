#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_initializer.h"
#include "mock_shmem_ipc.h"
#include "mock_nano_socket.h"
#include "mock_nano_poll.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_attachment_io.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentIoTest : public Test
{
public:
    void
    SetUp() override
    {
        EXPECT_CALL(
            initializer_mocker,
            nano_attachment_init_process(_)).WillOnce(Return(NanoCommunicationResult::NANO_OK)
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

        session_data = InitSessionData(attachment, 501);
        EXPECT_NE(session_data, nullptr);

        ctx_data.session_data = session_data;
        init_thread_ctx(&ctx, attachment, &ctx_data);

        reply_from_service_mock = (HttpReplyFromService *)malloc(
            sizeof(HttpReplyFromService) +
            sizeof(HttpModifyData) +
            sizeof(HttpInjectData) +
            sizeof(HttpWebResponseData)
        );
        reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_INSPECT);
        reply_from_service_mock->session_id = session_data->session_id;
        reply_from_service_mock->modification_count = 0;

        modify_data_mock = reinterpret_cast<HttpModifyData *>(reply_from_service_mock->modify_data);
        inject_data = reinterpret_cast<HttpInjectData *>(
            reply_from_service_mock->modify_data + sizeof(HttpModifyData)
        );
        web_response_data = reinterpret_cast<HttpWebResponseData *>(
            reply_from_service_mock->modify_data + sizeof(HttpModifyData)
        );
    }

    void
    TearDown() override
    {
        free(reply_from_service_mock);
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

    AttachmentData ctx_data = {
        1,
        HttpChunkType::HTTP_REQUEST_METADATA,
        session_data,
        nullptr
    };

    HttpReplyFromService *reply_from_service_mock;
    HttpModifyData *modify_data_mock;
    HttpInjectData *inject_data;
    HttpWebResponseData *web_response_data;
    uint32_t reply_session_id = -1;
    void *reply_session_id_void = &reply_session_id;
    const char **replay_data_mock;

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    HttpEventThreadCtx ctx;

    StrictMock<NanoInitializerMocker> initializer_mocker;
    StrictMock<NanoShmemIPCMocker> mock_shmem_ipc;
    StrictMock<NanoSocketMocker> mock_nano_socket;
    StrictMock<NanoPollMocker> mock_nano_poll;
};

TEST_F(NanoAttachmentIoTest, ConnectToCommSocket)
{
    NanoCommunicationResult res;

    EXPECT_CALL(
        mock_nano_socket,
        socket(AF_UNIX, SOCK_STREAM, 0)
    ).WillOnce(Return(53));

    EXPECT_CALL(
        mock_nano_socket,
        connect(53, _, _)
    ).WillOnce(Return(0));

    res = connect_to_comm_socket(attachment);

    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);
    EXPECT_EQ(attachment->comm_socket, 53);
}

TEST_F(NanoAttachmentIoTest, ConnectToRegistrationSocket)
{
    NanoCommunicationResult res;

    EXPECT_CALL(
        mock_nano_socket,
        socket(AF_UNIX, SOCK_STREAM, 0)
    ).WillOnce(Return(39));

    EXPECT_CALL(
        mock_nano_socket,
        connect(39, _, _)
    ).WillOnce(Return(0));

    res = connect_to_registration_socket(attachment);

    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);
    EXPECT_EQ(attachment->registration_socket, 39);
}

TEST_F(NanoAttachmentIoTest, NanoMetadataSender)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    nano_metadata_sender(
        attachment,
        &http_meta_data,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply,
        true
    );
}

TEST_F(NanoAttachmentIoTest, NanoMetadataSenderFailOnce)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    nano_metadata_sender(
        attachment,
        &http_meta_data,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply,
        false
    );
}

TEST_F(NanoAttachmentIoTest, NanoHeadersSender)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = (const char *)reply_from_service_mock;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_header_sender(
        attachment,
        &http_headers_data,
        &ctx,
        AttachmentDataType::REQUEST_HEADER,
        session_data->session_id,
        &session_data->remaining_messages_to_reply,
        true
    );
}

TEST_F(NanoAttachmentIoTest, NanoBodySender)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).Times(3)
    .WillOnce(Return(0))
    .WillOnce(Return(0))
    .WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillRepeatedly(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillRepeatedly(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        close(_)
    ).WillRepeatedly(Return(0));

    EXPECT_CALL(
        mock_nano_socket,
        connect(_, _, _)
    ).WillRepeatedly(Return(0));

    EXPECT_CALL(
        mock_nano_socket,
        socket(_, _, _)
    ).WillRepeatedly(Return(0));

    EXPECT_CALL(
        initializer_mocker,
        write_to_service(attachment, _, _, _, _)
    ).WillRepeatedly(Return(NanoCommunicationResult::NANO_OK));

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillRepeatedly(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = (const char *)reply_from_service_mock;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillRepeatedly(Return(1));

    nano_body_sender(
        attachment,
        &http_body_data,
        &ctx,
        AttachmentDataType::REQUEST_BODY,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );
}

TEST_F(NanoAttachmentIoTest, NanoSendResponseContentLength)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    nano_send_response_content_length(
        attachment,
        332,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 1u);
}

TEST_F(NanoAttachmentIoTest, NanoSendResponseCode)
{
    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    nano_send_response_code(
        attachment,
        443,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 1u);
}

TEST_F(NanoAttachmentIoTest, NanoEndTransactionSender)
{
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_end_transaction_sender(
        attachment,
        AttachmentDataType::REQUEST_END,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);
}

TEST_F(NanoAttachmentIoTest, NanoDelayedTransactionSender)
{
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_request_delayed_verdict(
        attachment,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);
}

TEST_F(NanoAttachmentIoTest, NanoDropResponseBadResponse)
{
    web_response_data->web_response_type = static_cast<uint16_t>(NanoWebResponseType::NO_WEB_RESPONSE);
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_DROP);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_end_transaction_sender(
        attachment,
        AttachmentDataType::REQUEST_END,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_DROP);
}

TEST_F(NanoAttachmentIoTest, NanoDropCustomResponse)
{
    web_response_data->web_response_type = static_cast<uint16_t>(NanoWebResponseType::CUSTOM_WEB_RESPONSE);
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_DROP);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_end_transaction_sender(
        attachment,
        AttachmentDataType::REQUEST_END,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_DROP);
}

TEST_F(NanoAttachmentIoTest, NanoDropRedirectResponse)
{
    web_response_data->web_response_type = static_cast<uint16_t>(NanoWebResponseType::REDIRECT_WEB_RESPONSE);
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_DROP);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_end_transaction_sender(
        attachment,
        AttachmentDataType::REQUEST_END,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_DROP);
}

TEST_F(NanoAttachmentIoTest, NanoInjectResponse)
{
    reply_from_service_mock->modification_count = 1;
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_INJECT);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        mock_nano_poll,
        poll(_, _, _)
    ).Times(2)
    .WillOnce(Return(1))
    .WillOnce(Return(2));

    EXPECT_CALL(
        mock_nano_socket,
        write(_, _, _)
    ).WillOnce(Return(sizeof(SessionID)));

    EXPECT_CALL(
        mock_nano_socket,
        read(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<1>(&reply_session_id_void),
            InvokeWithoutArgs(
                [&] () {
                    *reinterpret_cast<uint32_t *>(reply_session_id_void) = 501;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        isDataAvailable(_)
    ).WillOnce(Return(1));

    EXPECT_CALL(
        mock_shmem_ipc,
        receiveData(_, _, _)
    ).WillOnce(
        DoAll(
            SaveArg<2>(&replay_data_mock),
            InvokeWithoutArgs(
                [&] () {
                    *replay_data_mock = reinterpret_cast<const char *>(reply_from_service_mock);
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        mock_shmem_ipc,
        popData(_)
    ).WillOnce(Return(1));

    nano_end_transaction_sender(
        attachment,
        AttachmentDataType::REQUEST_END,
        &ctx,
        session_data->session_id,
        &session_data->remaining_messages_to_reply
    );

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
    EXPECT_EQ(session_data->verdict, ServiceVerdict::TRAFFIC_VERDICT_INSPECT);
}

TEST_F(NanoAttachmentIoTest, NanoSendMetricData)
{
    reply_from_service_mock->verdict = static_cast<uint16_t>(ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);

    EXPECT_CALL(
        mock_shmem_ipc,
        sendChunkedData(_, _, _, _)
    ).WillOnce(Return(0));

    nano_send_metric_data_sender(attachment);

    EXPECT_EQ(session_data->remaining_messages_to_reply, 0u);
}
