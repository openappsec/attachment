#ifndef __MOCK_NANO_ATTACHMENT_SENDER_THREAD_H__
#define __MOCK_NANO_ATTACHMENT_SENDER_THREAD_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_attachment_sender_thread.h"
}

class NanoSenderThreadMocker : public CMockMocker<NanoSenderThreadMocker>
{
public:
    MOCK_METHOD1(SendRequestEndThread, void *(void *_ctx));
};

CMOCK_MOCK_FUNCTION1(
    NanoSenderThreadMocker,
    SendRequestEndThread,
    void *(void *_ctx)
);

#endif // __MOCK_NANO_ATTACHMENT_SENDER_THREAD_H__
