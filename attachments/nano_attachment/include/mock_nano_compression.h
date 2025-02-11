#ifndef __MOCK_NANO_COMPRESSION_H__
#define __MOCK_NANO_COMPRESSION_H__

#include "cmock.h"
#include "nano_attachment_common.h"

extern "C" {
#include "nano_compression.h"
}

class NanoCompressionMocker : public CMockMocker<NanoCompressionMocker>
{
public:
    MOCK_METHOD3(
        nano_compress_body,
        HttpBody*(
            NanoAttachment *attachment,
            HttpBody *bodies,
            HttpSessionData *session_data_p
        )
    );

    MOCK_METHOD3(
        nano_decompress_body,
        HttpBody*(
            NanoAttachment *attachment,
            HttpBody *bodies,
            HttpSessionData *session_data_p
        )
    );

    MOCK_METHOD3(
        nano_free_compressed_body,
        void(
            NanoAttachment *attachment,
            HttpBody *bodies,
            HttpSessionData *session_data_p
        )
    );
};

CMOCK_MOCK_FUNCTION3(
    NanoCompressionMocker,
    nano_compress_body,
    HttpBody*(
        NanoAttachment *attachment,
        HttpBody *bodies,
        HttpSessionData *session_data_p
    )
);

CMOCK_MOCK_FUNCTION3(
    NanoCompressionMocker,
    nano_decompress_body,
    HttpBody*(
        NanoAttachment *attachment,
        HttpBody *bodies,
        HttpSessionData *session_data_p
    )
);

CMOCK_MOCK_FUNCTION3(
    NanoCompressionMocker,
    nano_free_compressed_body,
    void(
        NanoAttachment *attachment,
        HttpBody *bodies,
        HttpSessionData *session_data_p
    )
);

#endif // __MOCK_NANO_COMPRESSION_H__
