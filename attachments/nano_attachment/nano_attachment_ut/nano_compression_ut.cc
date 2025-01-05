#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"
#include "compression_utils.h"

#include "mock_nano_socket.h"
#include "mock_nano_initializer.h"
#include "mock_nano_attachment_sender.h"
#include "mock_nano_configuration.h"
#include "mock_nano_compression.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_compression.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentTest : public Test
{
public:
    void
    SetUp() override
    {
        EXPECT_CALL(
            initializer_mocker,
            nano_attachment_init_process(_)
        ).WillOnce(
            Return(NanoCommunicationResult::NANO_OK)
        );
        attachment = InitNanoAttachment(
            static_cast<uint8_t>(AttachmentType::NGINX_ATT_ID),
            2,
            4,
            STDOUT_FILENO
        );
        EXPECT_NE(attachment, nullptr);

        session_data = InitSessionData(attachment, 1);
        EXPECT_NE(session_data, nullptr);
    }

    void
    TearDown() override
    {
        FiniSessionData(attachment, session_data);
        FiniNanoAttachment(attachment);
    }

    nano_str_t
    create_nano_str(const char *str)
    {
        nano_str_t nano_str;
        nano_str.data = reinterpret_cast<unsigned char *>(const_cast<char *>(str));
        nano_str.len = strlen(str);
        return nano_str;
    }

    nano_str_t body[3] = {
        create_nano_str("Hello"),
        create_nano_str("World"),
        create_nano_str("!")
    };

    HttpBody http_body_data = {
        body,
        3
    };

    AttachmentData req_body_data = {
        1,
        HttpChunkType::HTTP_REQUEST_BODY,
        session_data,
        (DataBuffer)&http_body_data
    };

    NanoAttachment *attachment;
    HttpSessionData *session_data;
    StrictMock<NanoInitializerMocker> initializer_mocker;
};

TEST_F(NanoAttachmentTest, CompressData)
{
    session_data->response_data.compression_type = CompressionType::GZIP;

    HttpBody * compressed_body_data = nullptr;
    HttpBody * decompressed_body_data = nullptr;

    compressed_body_data = nano_compress_body(attachment, &http_body_data, session_data);
    EXPECT_EQ(compressed_body_data->bodies_count, 3u);

    decompressed_body_data = nano_decompress_body(attachment, compressed_body_data, session_data);
    EXPECT_EQ(decompressed_body_data->bodies_count, 3u);
    EXPECT_EQ(decompressed_body_data->data[0].len, 5u);
    EXPECT_EQ(decompressed_body_data->data[1].len, 5u);
    EXPECT_EQ(decompressed_body_data->data[2].len, 1u);

    EXPECT_EQ(strncmp((char *)decompressed_body_data->data[0].data, "Hello", decompressed_body_data->data[0].len), 0);
    EXPECT_EQ(strncmp((char *)decompressed_body_data->data[1].data, "World", decompressed_body_data->data[1].len), 0);
    EXPECT_EQ(strncmp((char *)decompressed_body_data->data[2].data, "!", decompressed_body_data->data[2].len), 0);

    nano_free_compressed_body(attachment, compressed_body_data, session_data);
    nano_free_compressed_body(attachment, decompressed_body_data, session_data);
}
