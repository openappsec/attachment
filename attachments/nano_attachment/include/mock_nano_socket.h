#ifndef __MOCK_NANO_SOCKET_H__
#define __MOCK_NANO_SOCKET_H__

#include "cmock.h"

extern "C" {
#include <sys/socket.h>
}

class NanoSocketMocker : public CMockMocker<NanoSocketMocker>
{
public:
    MOCK_METHOD3(socket, int(int domain, int type, int protocol));
    MOCK_METHOD3(connect, int(int sockfd, const struct sockaddr *addr, socklen_t addrlen));
    MOCK_METHOD1(close, int(int sockfd));
    MOCK_METHOD3(write, ssize_t(int fd, const void *buf, size_t count));
    MOCK_METHOD3(read, ssize_t(int fd, void *buf, size_t count));
};

CMOCK_MOCK_FUNCTION3(
    NanoSocketMocker,
    socket,
    int(int domain, int type, int protocol)
);

CMOCK_MOCK_FUNCTION3(
    NanoSocketMocker,
    connect,
    int(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
);

CMOCK_MOCK_FUNCTION1(
    NanoSocketMocker,
    close,
    int(int sockfd)
);

CMOCK_MOCK_FUNCTION3(
    NanoSocketMocker,
    write,
    ssize_t(int fd, const void *buf, size_t count)
);

CMOCK_MOCK_FUNCTION3(
    NanoSocketMocker,
    read,
    ssize_t(int fd, void *buf, size_t count)
);

#endif // __MOCK_NANO_SOCKET_H__
