#ifndef __MOCK_NANO_INITIALIZER_H__
#define __MOCK_NANO_INITIALIZER_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_initializer.h"
}

class NanoInitializerMocker : public CMockMocker<NanoInitializerMocker>
{
public:
    MOCK_METHOD1(nano_attachment_init_process, NanoCommunicationResult(NanoAttachment *attachment));
    MOCK_METHOD5(
        write_to_service,
        NanoCommunicationResult(
            NanoAttachment *attachment,
            int *socket,
            void *data,
            uint32_t size,
            struct timeval *absolute_end_time
        )
    );
    MOCK_METHOD1(handle_shmem_corruption, NanoCommunicationResult(NanoAttachment *attachment));
};

CMOCK_MOCK_FUNCTION1(
    NanoInitializerMocker,
    nano_attachment_init_process,
    NanoCommunicationResult(NanoAttachment *attachment)
);

CMOCK_MOCK_FUNCTION5(
    NanoInitializerMocker,
    write_to_service,
    NanoCommunicationResult(
        NanoAttachment *attachment,
        int *socket,
        void *data,
        uint32_t size,
        struct timeval *absolute_end_time
    )
);

CMOCK_MOCK_FUNCTION1(
    NanoInitializerMocker,
    handle_shmem_corruption,
    NanoCommunicationResult(NanoAttachment *attachment)
);

#endif // __MOCK_NANO_INITIALIZER_H__
