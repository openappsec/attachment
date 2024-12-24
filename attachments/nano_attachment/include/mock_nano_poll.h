#ifndef __MOCK_NANO_POLL_H__
#define __MOCK_NANO_POLL_H__

#include "cmock.h"

extern "C" {
#include <poll.h>
}

class NanoPollMocker : public CMockMocker<NanoPollMocker>
{
public:
    MOCK_METHOD3(poll, int(pollfd *fds, nfds_t nfds, int timeout));
};

CMOCK_MOCK_FUNCTION3(
    NanoPollMocker,
    poll,
    int(pollfd *fds, nfds_t nfds, int timeout)
);

#endif // __MOCK_NANO_POLL_H__
