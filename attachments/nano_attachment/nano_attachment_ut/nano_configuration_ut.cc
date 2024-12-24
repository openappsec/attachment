#include "cptest.h"
#include "nano_attachment_common.h"
#include "attachment_types.h"
#include "http_configuration.h"

#include <fstream>

extern "C" {
#include "nano_attachment.h"
#include "nano_configuration.h"
#include "nano_utils.h"
}

using namespace std;
using namespace testing;

class NanoConfigurationTest : public Test
{
public:
    string
    createIPRangesString(const vector<string> &ip_ranges)
    {
        stringstream ip_ranges_string_stream;
        ip_ranges_string_stream << "[";
        for (auto iterator = ip_ranges.begin(); iterator < ip_ranges.end() - 1; iterator++) {
            ip_ranges_string_stream << "\"" << *iterator << "\"" << ", ";
        }
        ip_ranges_string_stream << "\"" << ip_ranges.back() << "\"]";

        return ip_ranges_string_stream.str();
    }

    NanoAttachment attachment;
    LoggingData logging_data;
    const string static_resources_path = "/dev/shm/static_resources/";
    const vector<string> ip_ranges = { "8.8.8.8", "9.9.9.9-10.10.10.10", "0:0:0:0:0:0:0:1-0:0:0:0:0:0:0:4"};
    const string attachment_configuration_file_name = "cp_nano_http_attachment_conf";
};

TEST_F(NanoConfigurationTest, InitAttachmentConfiguration)
{
    NanoCommunicationResult res;
    string valid_configuration =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/abc\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"is_fail_open_mode_enabled\": 0,\n"
            "\"fail_open_timeout\": 1234,\n"
            "\"is_fail_open_mode_hold_enabled\": 0,\n"
            "\"fail_open_hold_timeout\": 4321,\n"
            "\"sessions_per_minute_limit_verdict\": \"Accept\",\n"
            "\"max_sessions_per_minute\": 0,\n"
            "\"num_of_nginx_ipc_elements\": 200,\n"
            "\"keep_alive_interval_msec\": 10000,\n"
            "\"dbg_level\": 2,\n"
            "\"nginx_inspection_mode\": 1,\n"
            "\"operation_mode\": 0,\n"
            "\"req_body_thread_timeout_msec\": 155,\n"
            "\"req_proccessing_timeout_msec\": 42,\n"
            "\"registration_thread_timeout_msec\": 101,\n"
            "\"res_proccessing_timeout_msec\": 420,\n"
            "\"res_header_thread_timeout_msec\": 1,\n"
            "\"res_body_thread_timeout_msec\": 80,\n"
            "\"waiting_for_verdict_thread_timeout_msec\": 60,\n"
            "\"req_header_thread_timeout_msec\": 10,\n"
            "\"ip_ranges\": " + createIPRangesString(ip_ranges) + ",\n"
            "\"static_resources_path\": \"" + static_resources_path + "\""
        "}\n";
    ofstream valid_configuration_file(attachment_configuration_file_name);
    valid_configuration_file << valid_configuration;
    valid_configuration_file.close();

    attachment.shared_verdict_signal_path[0] = '\0';
    attachment.worker_id = 2;
    attachment.num_of_workers = 4;
    attachment.nano_user_id = getuid();
    attachment.nano_group_id = getgid();
    attachment.registration_socket = -1;
    attachment.attachment_type = static_cast<uint8_t>(AttachmentType::NGINX_ATT_ID);
    attachment.nano_service_ipc = NULL;
    attachment.comm_socket = -1;
    attachment.logging_data = &logging_data;

    res = set_logging_fd(&attachment, STDOUT_FILENO);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);

    setenv("CLOUDGUARD_UID", "Testing", 1);
    res = set_docker_id(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);

    res = set_unique_id(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);

    attachment.is_configuration_updated = NanoCommunicationResult::NANO_ERROR;
    attachment.current_config_version = 0;
    attachment.dbg_level = nano_http_cp_debug_level_e::DBG_LEVEL_TRACE;

    res = init_attachment_config(&attachment, attachment_configuration_file_name.c_str());
    EXPECT_EQ(res, NanoCommunicationResult::NANO_OK);

    EXPECT_EQ(attachment.is_configuration_updated, NanoCommunicationResult::NANO_OK);
    EXPECT_EQ(attachment.dbg_level, nano_http_cp_debug_level_e::DBG_LEVEL_INFO);
    EXPECT_EQ(attachment.fail_mode_verdict, 1);
    EXPECT_EQ(attachment.fail_open_timeout, 1234u);
    EXPECT_EQ(attachment.fail_mode_delayed_verdict, 1);
    EXPECT_EQ(attachment.fail_open_delayed_timeout, 4321u);
    EXPECT_EQ(attachment.sessions_per_minute_limit_verdict, AttachmentVerdict::ATTACHMENT_VERDICT_ACCEPT);
    EXPECT_EQ(attachment.max_sessions_per_minute, 0u);
    EXPECT_EQ(attachment.req_max_proccessing_ms_time, 42u);
    EXPECT_EQ(attachment.res_max_proccessing_ms_time, 420u);
    EXPECT_EQ(attachment.registration_thread_timeout_msec, 101u);
    EXPECT_EQ(attachment.req_header_thread_timeout_msec, 10u);
    EXPECT_EQ(attachment.req_body_thread_timeout_msec, 155u);
    EXPECT_EQ(attachment.res_header_thread_timeout_msec, 1u);
    EXPECT_EQ(attachment.res_body_thread_timeout_msec, 80u);
    EXPECT_EQ(attachment.waiting_for_verdict_thread_timeout_msec, 60u);
    EXPECT_EQ(attachment.num_of_nano_ipc_elements, 200u);
    EXPECT_EQ(attachment.keep_alive_interval_msec, 10000u);
    EXPECT_EQ(attachment.inspection_mode, NanoHttpInspectionMode::BLOCKING_THREAD);

    res = reset_attachment_config(&attachment);
    EXPECT_EQ(res, NanoCommunicationResult::NANO_ERROR);
}
