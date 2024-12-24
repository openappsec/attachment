#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_socket.h"
#include "mock_nano_initializer.h"
#include "mock_nano_sender_thread.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_attachment_thread.h"
#include "nano_attachment_sender_thread.h"
}

using namespace std;
using namespace testing;

class NanoThreadTest : public Test
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

        ctx_data.session_data = session_data;
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

    AttachmentVerdictResponse accept_response = {
        AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT,
        1,
        NULL,
        NULL
    };

    AttachmentData ctx_data = {
        1,
        HttpChunkType::HTTP_REQUEST_END,
        session_data,
        NULL
    };

    HttpEventThreadCtx ctx;

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    StrictMock<NanoSenderThreadMocker> sender_thread_mocker;
    StrictMock<NanoInitializerMocker> initializer_mocker;
    StrictMock<NanoSocketMocker> socket_mocker;
};

TEST_F(NanoThreadTest, NanoRunInThreadTimeout)
{
    int res;
    char func_name[] = "SendRequestEndThread";
    EXPECT_CALL(
        sender_thread_mocker,
        SendRequestEndThread(&ctx)
    ).WillOnce(Return(nullptr));

    res = NanoRunInThreadTimeout(
        attachment,
        &ctx_data,
        SendRequestEndThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        func_name,
        REQUEST
    );

    EXPECT_EQ(res, 1);
}

TEST_F(NanoThreadTest, NanoRunInThreadTimeoutNonThread)
{
    int res;
    char func_name[] = "SendRequestEndThread";
    attachment->inspection_mode = NanoHttpInspectionMode::NO_THREAD;

    EXPECT_CALL(
        sender_thread_mocker,
        SendRequestEndThread(&ctx)
    ).WillOnce(Return(nullptr));

    res = NanoRunInThreadTimeout(
        attachment,
        &ctx_data,
        SendRequestEndThread,
        (void *)&ctx,
        attachment->req_header_thread_timeout_msec,
        func_name,
        REQUEST
    );
    
    EXPECT_EQ(res, 1);
}
