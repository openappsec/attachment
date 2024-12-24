// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file nano_initializer.h
#ifndef __NANO_INITIALIZER_H__
#define __NANO_INITIALIZER_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nano_attachment_common.h"
#include "shmem_ipc_2.h"

#define LOGGING_DIRECTORY_PATH "/var/log/nano_attachment" ///< Default logging directory path.
#define LOGGING_FILE_NAME "nano_attachment" ///< Default logging file name.
#define LOGGING_FILE_PATH LOGGING_DIRECTORY_PATH "/" LOGGING_FILE_NAME

typedef enum nano_attachment_registration_state {
    NOT_REGISTERED,
    PENDING,
    REGISTERED
} nano_attachment_registration_state; ///< Indicates the current attachment registation stage.

typedef struct NanoAttachment {
    char unique_id[MAX_NGINX_UID_LEN]; // Holds the unique identifier for this instance.
    char container_id[MAX_NGINX_UID_LEN]; // Holds the container id of the attachment.
    char shared_verdict_signal_path[MAX_SHARED_MEM_PATH_LEN]; // Holds the path associating the attachment and service.
    uint8_t worker_id; // Holds the worker number of the attachment.
    uint8_t num_of_workers; // Holds the number of workers in the attachment.
    uint32_t nano_user_id; // Holds the user id of the attachment.
    uint32_t nano_group_id; // Holds the group id of the attachment.
    int registration_socket; // Holds the file descriptor used for registering the instance.
    nano_attachment_registration_state registration_state; // Holds the current attachment registation stage.

    uint8_t attachment_type; // Holds the type of the attachment.
    SharedMemoryIPC *nano_service_ipc; // Holds the shared memory IPC of the nano service.
    int comm_socket; // Holds the communication socket of the attachment.

    int is_default_fd; // Holds a value indicating if the logging file descriptor is the default one.
    int logging_fd; // Holds the file descriptor for logging.
    LoggingData *logging_data; // Holds the logging data of the attachment.

    NanoCommunicationResult is_configuration_updated; // Holds the result of the configuration update.
    unsigned int current_config_version; // Holds the current configuration version.

    int fail_mode_verdict; ///< Fail open verdict incase of a timeout.
    int fail_mode_delayed_verdict; ///< Fail open verdict incase of a timeout when waiting for delayed verdict.
    nano_http_cp_debug_level_e dbg_level; ///< Default debug level.
    int num_of_connection_attempts; ///< Maximum number of attempted connections.
    unsigned int fail_open_timeout; ///< Fail open timeout in milliseconds.
    unsigned int fail_open_delayed_timeout; ///< Fail open delayed timeout in milliseconds.
    AttachmentVerdict sessions_per_minute_limit_verdict; ///< Session per minute limit verdict.
    unsigned int max_sessions_per_minute; ///< Masimum session per minute.
    unsigned int req_max_proccessing_ms_time; ///< Total Request processing timeout in milliseconds.
    unsigned int res_max_proccessing_ms_time; ///< Total Response processing timeout in milliseconds.
    unsigned int registration_thread_timeout_msec; ///< Registration timeout in milliseconds.
    unsigned int req_start_thread_timeout_msec; ///< Request start processing timeout in milliseconds.
    unsigned int req_header_thread_timeout_msec; ///< Request header processing timeout in milliseconds.
    unsigned int req_body_thread_timeout_msec; ///< Request body processing timeout in milliseconds.
    unsigned int res_header_thread_timeout_msec; ///< Response header processing timeout in milliseconds.
    unsigned int res_body_thread_timeout_msec; ///< Response body processing timeout in milliseconds.
    unsigned int waiting_for_verdict_thread_timeout_msec; ///< Wait thread processing timeout in milliseconds.
    unsigned int metric_timeout_timeout; ///< Metric timeout in milliseconds.
    NanoHttpInspectionMode inspection_mode; ///< Default inspection mode.
    unsigned int num_of_nano_ipc_elements; ///< Number of NANO IPC elements.
    uint64_t keep_alive_interval_msec; ///< Keep alive interval in milliseconds.

#ifdef __cplusplus
    uint64_t metric_data[static_cast<int>(AttachmentMetricType::METRIC_TYPES_COUNT)];
    uint64_t metric_average_data_divisor[static_cast<int>(AttachmentMetricType::METRIC_TYPES_COUNT)];
#else
    uint64_t metric_data[METRIC_TYPES_COUNT];
    uint64_t metric_average_data_divisor[METRIC_TYPES_COUNT];
#endif
} NanoAttachment;

///
/// @brief Initialize all the attachments resources and communication channels.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult
///         - #NANO_OK
///         - #NANO_ERROR
///         - #NANO_ABORT
///
NanoCommunicationResult nano_attachment_init_process(NanoAttachment *attachment);

///
/// @brief Preforms send information to the service via a socket.
///
/// This function writes data to the socket associated with the given NanoAttachment.
/// It writes data in parts if necessary, keeping track of the remaining data to be written.
/// If the write operation fails or exceeds the allowed timeout, it returns NANO_ERROR;
/// otherwise, it returns NANO_OK.
///
/// @param Points to the NanoAttachment struct.
/// @param socket The socket to write to.
/// @param data The pointer to the data to be written.
/// @param size The size of the data to be written, excluding the null terminator.
/// @param absolute_end_time The absolute till the writing is allowed.
/// @return NanoCommunicationResult Returns NANO_OK if the write operation is successful, otherwise NANO_ERROR.
///
NanoCommunicationResult write_to_service(
    NanoAttachment *attachment,
    int *socket,
    void *data,
    uint32_t size,
    struct timeval *absolute_end_time);

///
/// @brief Preforms receive information from the service via a socket.
///
/// This function reads data from the socket associated with the given NanoAttachment.
/// It reads data in parts if necessary, keeping track of the remaining data to be read.
/// It checks if the socket has data to be read prior to the read operation to avoid blocking indefinitely.
/// If the read operation fails or exceeds the allowed timeout, it returns NANO_ERROR;
/// otherwise, it returns NANO_OK.
///
/// @param attachment Points to the NanoAttachment struct.
/// @param socket The socket to read from.
/// @param data The pointer to the buffer where the read data will be stored.
/// @param size The size of the data to be read.
/// @param absolute_end_time The absolute till the reading is allowed.
/// @return NanoCommunicationResult Returns NANO_OK if the read operation is successful, otherwise NANO_ERROR.
///
NanoCommunicationResult read_from_service(
    NanoAttachment *attachment,
    int *socket,
    void *data,
    uint32_t size,
    struct timeval *absolute_end_time);

///
/// @brief Sets a unique identifier for the NanoAttachment based on its container ID and worker ID.
///
/// @param attachment Pointer to the NanoAttachment structure for which to set the unique ID.
/// @return NANO_OK if the unique ID was successfully set, otherwise an error code.
///
NanoCommunicationResult set_unique_id(NanoAttachment *attachment);

///
/// @brief Sets the container ID for the NanoAttachment by reading it from CONTAINER_ID_FILE_PATH value.
///
/// @param attachment Pointer to the NanoAttachment structure for which to set the container ID.
/// @return NANO_OK if the container ID was successfully set, otherwise an error code.
///
NanoCommunicationResult set_docker_id(NanoAttachment *attachment);

///
/// @brief Sets the file descriptor for logging in the NanoAttachment structure.
///
/// If an invalid fd passed, the default logging file descriptor is set to write to LOGGING_FILE_PATH variable.
///
/// @param attachment Pointer to the NanoAttachment struct to set the logging file descriptor.
/// @param logging_fd The file descriptor to set.
/// @return NANO_OK if the logging file descriptor is set successfully, NANO_ERROR otherwise.
///
NanoCommunicationResult set_logging_fd(NanoAttachment *attachment, int logging_fd);

///
/// @brief Closes the logging file descriptor in the NanoAttachment structure.
///
/// @param attachment Pointer to the NanoAttachment struct to close the logging file descriptor.
///
void close_logging_fd(NanoAttachment *attachment);

///
/// @brief Closes any existing communication to the service and tries to open a new one.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult
///         - #NANO_OK
///         - #NANO_ERROR
///
NanoCommunicationResult restart_communication(NanoAttachment *attachment);

///
/// @brief Checks that the shared memory with the service isn't corrupted, disconnect if it is.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult
///         - #NANO_OK
///         - #NANO_ERROR
///
NanoCommunicationResult handle_shmem_corruption(NanoAttachment *attachment);

///
/// @brief Closes all the communication channels with the service.
/// @param[in] attachment Points to initiated NanoAttachment struct.
///
void disconnect_communication(NanoAttachment *attachment);

///
/// @brief Checks if communication with the service is up and running.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult - 1 if communication is active, otherwise 0.
///
int isIpcReady(NanoAttachment *attachment);

///
/// @brief Register the attachment instance with the attachment manager to associate it with a service.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult
///         - #NANO_OK
///         - #NANO_ERROR
///
NanoCommunicationResult register_to_attachments_manager(NanoAttachment *attachment);

#endif // __NANO_INITIALIZER_H__
