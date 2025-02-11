#ifndef __MOCK_ACCESS_H__
#define __MOCK_ACCESS_H__

#include "cmock.h"

extern "C" {
#include <unistd.h>  // For the access function
}

class NanoAccessMocker : public CMockMocker<NanoAccessMocker>
{
public:
    MOCK_METHOD2(access, int(const char *path, int mode));
};

CMOCK_MOCK_FUNCTION2(
    NanoAccessMocker,
    access,
    int(const char *path, int mode)
);

#endif // __MOCK_ACCESS_H__
