#ifndef __MOCK_NANO_CONFIGURATION_H__
#define __MOCK_NANO_CONFIGURATION_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_configuration.h"
}

class NanoConfigurationMocker : public CMockMocker<NanoConfigurationMocker>
{
public:
    MOCK_METHOD2(
        init_attachment_config,
        NanoCommunicationResult(
            NanoAttachment *attachment,
            const char *conf_path
        )
    );
    MOCK_METHOD1(reset_attachment_config, NanoCommunicationResult(NanoAttachment *attachment));
};

CMOCK_MOCK_FUNCTION2(
    NanoConfigurationMocker,
    init_attachment_config,
    NanoCommunicationResult(
        NanoAttachment *attachment,
        const char *conf_path
    )
);

CMOCK_MOCK_FUNCTION1(
    NanoConfigurationMocker,
    reset_attachment_config,
    NanoCommunicationResult(NanoAttachment *attachment)
);

#endif // __MOCK_NANO_CONFIGURATION_H__
