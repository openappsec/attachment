#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"
#include <poll.h>

#include <stdlib.h>

#include "mock_nano_socket.h"
#include "mock_shmem_ipc.h"
#include "mock_nano_access.h"
#include "mock_nano_poll.h"
#include "mock_nano_configuration.h"
#include "mock_nano_stat.h"
#include "mock_nano_attachment_thread.h"

extern "C" {
#include "nano_initializer.h"
#include "nano_attachment_sender_thread.h"
}

using namespace std;
using namespace testing;

class NanoInitializerTest : public Test
{
public:
    void
    SetUp() override
    {
        ipc_holder = make_unique<int>();
        mock_ipc = reinterpret_cast<SharedMemoryIPC *>(ipc_holder.get());

        set_logging_fd(&attachment, STDOUT_FILENO);
        attachment.dbg_level = nano_http_cp_debug_level_e::DBG_LEVEL_TRACE;
    }

    void
    NanoRunInThreadTimeoutInvoker(
        AttachmentData *data,
        void *arg,
        int comm_socket,
        NanoCommunicationResult com_res
    )
    {

        HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)arg;
        init_thread_ctx(ctx, &attachment, data);
        attachment.comm_socket = comm_socket;
        attachment.registration_socket = comm_socket;
        ctx->res = com_res;
    }

    unique_ptr<int> ipc_holder;
    NanoAttachment attachment;
    SharedMemoryIPC *mock_ipc;
    void *_ctx;

    StrictMock<NanoSocketMocker> socket_mocker;
    StrictMock<NanoShmemIPCMocker> ipc_mocker;
    StrictMock<NanoAccessMocker> access_mocker;
    StrictMock<NanoPollMocker> poll_mocker;
    StrictMock<NanoConfigurationMocker> config_mocker;
    StrictMock<NanoStatMocker> stat_mocker;
    StrictMock<NanoAttachmentThreadMocker> thread_mocker;
};

TEST_F(NanoInitializerTest, InitNanoAttachmentProcess)
{
    NanoCommunicationResult res;

    struct pollfd mock_s_poll;
    struct pollfd *mock_s_poll_ptr = &mock_s_poll;

    attachment.registration_state = nano_attachment_registration_state::REGISTERED;
    attachment.comm_socket = -1;
    attachment.nano_service_ipc = nullptr;

    EXPECT_CALL(
        poll_mocker,
        poll(_, _, _)
    ).WillRepeatedly(
        DoAll(
            SaveArg<0>(&mock_s_poll_ptr),
            InvokeWithoutArgs(
                [&] () {
                    mock_s_poll_ptr->revents = POLLIN;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        socket_mocker,
        write(_, _, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        socket_mocker,
        read(
            _,
            _,
            _
        )
    ).Times(1)
    .WillOnce(Return(sizeof(uint8_t)));

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            &attachment,
            _,
            _,
            _,
            _,
            _,
            TransactionType::REGISTRATION
        )
    ).WillOnce(DoAll(SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    nullptr,
                    _ctx,
                    32,
                    NanoCommunicationResult::NANO_OK
                );
            }
        ),
        Return(1))
    );

    EXPECT_CALL(
        config_mocker,
        init_attachment_config(
            &attachment,
            _
        )
    ).Times(2)
    .WillOnce(Return(NanoCommunicationResult::NANO_ERROR))
    .WillOnce(Return(NanoCommunicationResult::NANO_OK));

    EXPECT_CALL(
        access_mocker,
        access(
            _,
            _
        )
    ).WillOnce(Return(0));

    EXPECT_CALL(
        ipc_mocker,
        initIpc(
            _,
            _,
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(mock_ipc));

    res = nano_attachment_init_process(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);
}

TEST_F(NanoInitializerTest, RegisterToAttachment)
{
    NanoCommunicationResult res;
    struct pollfd mock_s_poll;
    struct pollfd *mock_s_poll_ptr = &mock_s_poll;

    attachment.comm_socket = 53;
    attachment.registration_socket = 34;
    attachment.nano_service_ipc = mock_ipc;

    EXPECT_CALL(
        socket_mocker,
        close(34)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        socket_mocker,
        close(88)
    ).WillOnce(Return(0));

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            &attachment,
            _,
            _,
            _,
            _,
            _,
            TransactionType::REGISTRATION
        )
    ).WillOnce(DoAll(SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    nullptr,
                    _ctx,
                    88,
                    NanoCommunicationResult::NANO_OK
                );
            }
        ),
        Return(1))
    );

    EXPECT_CALL(
        socket_mocker,
        write(_, _, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        poll_mocker,
        poll(_, _, _)
    ).WillRepeatedly(
        DoAll(
            SaveArg<0>(&mock_s_poll_ptr),
            InvokeWithoutArgs(
                [&] () {
                    mock_s_poll_ptr->revents = POLLIN;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        socket_mocker,
        read(
            _,
            _,
            _
        )
    ).Times(1)
    .WillOnce(Return(sizeof(uint8_t)));

    res = register_to_attachments_manager(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);
}

TEST_F(NanoInitializerTest, DisconnectCommunication)
{
    int res;
    attachment.comm_socket = 53;
    attachment.nano_service_ipc = mock_ipc;

    EXPECT_CALL(
        socket_mocker,
        close(53)
    ).WillOnce(Return(-1));

    EXPECT_CALL(
        ipc_mocker,
        destroyIpc(mock_ipc, 0)
    ).WillOnce(Return());

    EXPECT_CALL(
        ipc_mocker,
        isCorruptedShmem(mock_ipc, 0)
    ).WillOnce(Return(0));

    handle_shmem_corruption(&attachment);

    disconnect_communication(&attachment);

    EXPECT_EQ(attachment.comm_socket, -1);
    EXPECT_EQ(attachment.nano_service_ipc, nullptr);

    res = isIpcReady(&attachment);
    EXPECT_EQ(res, 0);
}

TEST_F(NanoInitializerTest, RestartCommunication)
{
    NanoCommunicationResult res;
    struct pollfd mock_s_poll;
    struct pollfd *mock_s_poll_ptr = &mock_s_poll;

    attachment.comm_socket = 53;
    attachment.registration_socket = 34;
    attachment.nano_service_ipc = mock_ipc;

    EXPECT_CALL(
        ipc_mocker,
        destroyIpc(mock_ipc, 0)
    ).WillOnce(Return());

    EXPECT_CALL(
        poll_mocker,
        poll(_, _, _)
    ).WillRepeatedly(
        DoAll(
            SaveArg<0>(&mock_s_poll_ptr),
            InvokeWithoutArgs(
                [&] () {
                    mock_s_poll_ptr->revents = POLLIN;
                }
            ),
            Return(1)
        )
    );

    EXPECT_CALL(
        socket_mocker,
        write(_, _, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        socket_mocker,
        read(
            _,
            _,
            _
        )
    ).Times(1)
    .WillOnce(Return(sizeof(uint8_t)));

    EXPECT_CALL(
        ipc_mocker,
        initIpc(
            _,
            _,
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(mock_ipc));

    EXPECT_CALL(
        thread_mocker,
        NanoRunInThreadTimeout(
            &attachment,
            _,
            _,
            _,
            _,
            _,
            TransactionType::REGISTRATION
        )
    ).WillOnce(DoAll(SaveArg<3>(&_ctx),
        InvokeWithoutArgs(
            [&] () {
                NanoRunInThreadTimeoutInvoker(
                    nullptr,
                    _ctx,
                    53,
                    NanoCommunicationResult::NANO_OK
                );
            }
        ),
        Return(1))
    );

    res = restart_communication(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);
}

TEST_F(NanoInitializerTest, SetLoggingFailure)
{
    NanoCommunicationResult res;
    EXPECT_CALL(stat_mocker, mkdir(_, _)).WillOnce(Return(-1));
    
    res = set_logging_fd(&attachment, 0);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_ERROR);
}
