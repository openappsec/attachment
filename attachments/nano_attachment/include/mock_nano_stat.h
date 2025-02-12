#ifndef __MOCK_NANO_STAT_H__
#define __MOCK_NANO_STAT_H__

#include "cmock.h"

extern "C" {
#include <sys/stat.h>
}

class NanoStatMocker : public CMockMocker<NanoStatMocker>
{
public:
    MOCK_METHOD2(mkdir, int(const char *pathname, mode_t mode));
};

CMOCK_MOCK_FUNCTION2(
    NanoStatMocker,
    mkdir,
    int(const char *pathname, mode_t mode)
);

#endif // __MOCK_NANO_STAT_H__
