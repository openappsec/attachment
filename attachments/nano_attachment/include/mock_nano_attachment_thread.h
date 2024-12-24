#ifndef __MOCK_NANO_ATTACHMENT_THREAD_H__
#define __MOCK_NANO_ATTACHMENT_THREAD_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_attachment_thread.h"
}

class NanoAttachmentThreadMocker : public CMockMocker<NanoAttachmentThreadMocker>
{
public:
    MOCK_METHOD7(
        NanoRunInThreadTimeout,
        int(
            NanoAttachment *attachment,
            AttachmentData *data,
            CpThreadRoutine thread_func,
            void *arg,
            int timeout_msecs,
            char *func_name,
            TransactionType transaction_type
        )
    );
};

CMOCK_MOCK_FUNCTION7(
    NanoAttachmentThreadMocker,
    NanoRunInThreadTimeout,
    int(
        NanoAttachment *attachment,
        AttachmentData *data,
        CpThreadRoutine thread_func,
        void *arg,
        int timeout_msecs,
        char *func_name,
        TransactionType transaction_type
    )
);

#endif // __MOCK_NANO_ATTACHMENT_THREAD_H__
