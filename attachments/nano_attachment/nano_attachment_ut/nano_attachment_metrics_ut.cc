#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"

#include "mock_nano_initializer.h"

extern "C" {
#include "nano_attachment.h"
#include "nano_attachment_metric.h"
}

using namespace std;
using namespace testing;

class NanoAttachmentMetricTest : public Test
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
        setenv("CLOUDGUARD_UID", "Testing", 1);
        attachment = InitNanoAttachment(
            static_cast<uint8_t>(AttachmentType::NGINX_ATT_ID),
            2,
            4,
            STDOUT_FILENO
        );
        EXPECT_NE(attachment, nullptr);
    }

    void
    TearDown() override
    {
        FiniNanoAttachment(attachment);
    }

    NanoAttachment *attachment;
    StrictMock<NanoInitializerMocker> initializer_mocker;
};

TEST_F(NanoAttachmentMetricTest, CheckMetricsFunctions)
{
    updateMetricField(attachment, AttachmentMetricType::INJECT_VERDICTS_COUNT, 100u);
    updateMetricField(attachment, AttachmentMetricType::DROP_VERDICTS_COUNT, 200u);
    updateMetricField(attachment, AttachmentMetricType::ACCEPT_VERDICTS_COUNT, 300u);
    updateMetricField(attachment, AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT, 400u);
    updateMetricField(attachment, AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT, 400u);
    updateMetricField(attachment, AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT, 200u);
    updateMetricField(attachment, AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT, 50u);
    updateMetricField(attachment, AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT, 150u);
    updateMetricField(attachment, AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT, 50u);
    updateMetricField(attachment, AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT, 50u);
    updateMetricField(attachment, AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT, 20u);

    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::INJECT_VERDICTS_COUNT)], 100u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::DROP_VERDICTS_COUNT)], 200u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::ACCEPT_VERDICTS_COUNT)], 300u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT)], 400u);
    
    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        400u
    );
    
    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        50u
    );

    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        40u
    );

    reset_metric_data(attachment);

    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::INJECT_VERDICTS_COUNT)], 0u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::DROP_VERDICTS_COUNT)], 0u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::ACCEPT_VERDICTS_COUNT)], 0u);
    EXPECT_EQ(attachment->metric_data[static_cast<int>(AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT)], 0u);
    
    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        0u
    );

    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        0u
    );

    EXPECT_EQ(
        attachment->metric_data[static_cast<int>(AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT)],
        0u
    );
}
