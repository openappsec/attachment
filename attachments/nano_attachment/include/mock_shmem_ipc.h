#ifndef __MOCK_SHMEM_IPC__
#define __MOCK_SHMEM_IPC__

#include "cmock.h"
#include "cptest.h"

extern "C" {
#include "shmem_ipc_2.h"
}

class NanoShmemIPCMocker : public CMockMocker<NanoShmemIPCMocker>
{
public:
    MOCK_METHOD7(
        initIpc,
        SharedMemoryIPC *(
            const char queue_name[32],
            uint32_t user_id,
            uint32_t group_id,
            int is_owner,
            uint16_t num_of_queue_elem,
            const LoggingData *logging_data,
            void (*debug_func)(
                const LoggingData *loggin_data,
                uint32_t worker_id,
                int is_error,
                const char *func,
                const char *file,
                int line_num,
                const char *fmt,
                ...
            )
        )
    );
    MOCK_METHOD2(destroyIpc, void(SharedMemoryIPC *ipc, int is_owner));
    MOCK_METHOD2(resetIpc, void(SharedMemoryIPC *ipc, uint16_t num_of_data_segments));
    MOCK_METHOD3(
        sendData,
        int(SharedMemoryIPC *ipc, const uint16_t data_to_send_size, const char *data_to_send)
    );
    MOCK_METHOD4(
        sendChunkedData,
        int(
            SharedMemoryIPC *ipc,
            const uint16_t *data_to_send_sizes,
            const char **data_elem_to_send,
            const uint8_t num_of_data_elem
        )
    );
    MOCK_METHOD3(
        receiveData,
        int(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data)
    );
    MOCK_METHOD1(popData, int(SharedMemoryIPC *ipc));
    MOCK_METHOD1(isDataAvailable, int(SharedMemoryIPC *ipc));
    MOCK_METHOD2(isCorruptedShmem, int(SharedMemoryIPC *ipc, int));
};

CMOCK_MOCK_FUNCTION7(
    NanoShmemIPCMocker,
    initIpc,
    SharedMemoryIPC *(
        const char queue_name[32],
        uint32_t user_id,
        uint32_t group_id,
        int is_owner,
        uint16_t num_of_queue_elem,
        const LoggingData *logging_data,
        void (*debug_func)(
            const LoggingData *loggin_data,
            uint32_t worker_id,
            int is_error,
            const char *func,
            const char *file,
            int line_num,
            const char *fmt,
            ...
        )
    )
);
CMOCK_MOCK_FUNCTION2(NanoShmemIPCMocker, destroyIpc, void(SharedMemoryIPC *ipc, int is_owner));
CMOCK_MOCK_FUNCTION3(
    NanoShmemIPCMocker,
    sendData,
    int(SharedMemoryIPC *ipc, const uint16_t data_to_send_size, const char *data_to_send)
)
CMOCK_MOCK_FUNCTION4(
    NanoShmemIPCMocker,
    sendChunkedData,
    int(
        SharedMemoryIPC *ipc,
        const uint16_t *data_to_send_sizes,
        const char **data_elem_to_send,
        const uint8_t num_of_data_elem
    )
);
CMOCK_MOCK_FUNCTION3(
    NanoShmemIPCMocker,
    receiveData,
    int(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data)
);
CMOCK_MOCK_FUNCTION1(NanoShmemIPCMocker, popData, int(SharedMemoryIPC *ipc));
CMOCK_MOCK_FUNCTION1(NanoShmemIPCMocker, isDataAvailable, int(SharedMemoryIPC *ipc));
CMOCK_MOCK_FUNCTION2(NanoShmemIPCMocker, resetIpc, void(SharedMemoryIPC *ipc, uint16_t num_of_data_segments));
CMOCK_MOCK_FUNCTION2(NanoShmemIPCMocker, isCorruptedShmem, int(SharedMemoryIPC *ipc, int));

#endif // __MOCK_SHMEM_IPC__
