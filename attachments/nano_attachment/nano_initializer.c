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

/// @file nano_initializer.c
#include "nano_initializer.h"

#include <poll.h>
#include <stdint.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include "nano_attachment_common.h"
#include "attachment_types.h"
#include "nano_configuration.h"
#include "nano_attachment_io.h"
#include "shmem_ipc_2.h"
#include "nano_utils.h"
#include "nano_attachment_sender_thread.h"
#include "nano_attachment_thread.h"

NanoCommunicationResult
write_to_service(
    NanoAttachment *attachment,
    int *socket,
    void *data,
    uint32_t size,
    struct timeval *absolute_end_time)
{
    int res = 0;
    // `remaining_size` and `cur_data_ptr` are used to keep track of where we are in the memory.
    // This allows us to write to the socket in parts (if we need to).
    uint32_t remaining_size = size;
    char *cur_data_ptr = data;

    while (remaining_size > 0) {
        // If the operation exceeded the allowed time, treat it as a failure.
        if (is_absolute_timeout_reached(absolute_end_time)) {
            close(*socket);
            *socket = -1;
            write_dbg(
                attachment,
                0,
                DBG_LEVEL_TRACE,
                "Reached timeout while communicating with the socket"
            );
            return NANO_TIMEOUT;
        }

        res = write(*socket, (void *)cur_data_ptr, remaining_size);

        // `res` is -1 in case of an error: write functions failed or socket wasn't available.
        if (res < 0) {
            close(*socket);
            *socket = -1;
            write_dbg(
                attachment,
                0,
                DBG_LEVEL_TRACE,
                "Failed to communicate with the socket, Error: %s",
                strerror(errno)
            );
            return NANO_ERROR;
        }

        remaining_size -= res;
        cur_data_ptr += res;
    }
    return NANO_OK;
}

NanoCommunicationResult
read_from_service(
    NanoAttachment *attachment,
    int *socket,
    void *data,
    uint32_t size,
    struct timeval *absolute_end_time)
{
    int res = 0;
    // `remaining_size` and `cur_data_ptr` are used to keep track of where we are in the memory.
    // This allows us to read from the socket in parts (if we need to).
    uint32_t remaining_size = size;
    char *cur_data_ptr = data;

    while (remaining_size > 0) {
        // If the operation exceeded the allowed time, treat it as a failure.
        if (is_absolute_timeout_reached(absolute_end_time)) {
            close(*socket);
            *socket = -1;
            write_dbg(
                attachment,
                0,
                DBG_LEVEL_TRACE,
                "Reached timeout while communicating with the socket"
            );
            return NANO_TIMEOUT;
        }

        // The read operation must not block the attachment indefinitely.
        // To avoid that we check whether the socket has data to be read prior to the read operation.
        // If the socket doesn't have data to be read from within a reasonable time, we treat this as an error.
        struct pollfd s_poll;
        s_poll.fd = *socket;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        res = poll(&s_poll, 1, 3000);

        if (res <= 0 || (s_poll.revents & POLLIN) == 0) {
            close(*socket);
            *socket = -1;
            write_dbg(
                attachment,
                0,
                DBG_LEVEL_TRACE,
                "Failed to communicate with the socket, Error: %s",
                strerror(errno)
            );
            return NANO_ERROR;
        }

        res = read(*socket, (void *)cur_data_ptr, remaining_size);
        remaining_size -= res;
        cur_data_ptr += res;
    }
    return NANO_OK;
}

///
/// @brief Send communication data to the communication socket.
///
/// This function sends various data (unique identifier, process UID, process GID)
/// to the service through the communication socket. It sends the data in the
/// following order:
/// 1. The length of the unique identifier for this instance.
/// 2. The unique identifier for this instance.
/// 3. The process UID.
/// 4. The process GID.
///
/// @param[in] attachment The NanoAttachment struct containing the data to send.
/// @returns A NanoCommunicationResult indicating the success of the operation.
///     - #NANO_OK: The data was successfully sent.
///     - #NANO_ERROR: An error occurred during data transmission.
///
NanoCommunicationResult
send_comm_data_to_comm_socket(NanoAttachment *attachment)
{
    NanoCommunicationResult res;
    uint8_t uid_size_to_send = strlen(attachment->unique_id);
    struct timeval timeout = get_absolute_timeout_val_sec(1);

    res = write_to_service(
        attachment,
        &attachment->comm_socket,
        &uid_size_to_send,
        sizeof(uid_size_to_send),
        &timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send unique id size");
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->comm_socket,
        attachment->unique_id,
        uid_size_to_send,
        &timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send unique id %s", attachment->unique_id);
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->comm_socket,
        &attachment->nano_user_id,
        sizeof(uint32_t),
        &timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send nano user id");
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->comm_socket,
        &attachment->nano_group_id,
        sizeof(uint32_t),
        &timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send nano group id");
        return NANO_ERROR;
    }

    return NANO_OK;
}

///
/// @brief Initialize the signaling socket for communication.
///
/// This function connects to the communication socket, sends communication data,
/// and waits for an acknowledgment from the service that communication has been
/// established. If any step fails, the function closes the communication socket
/// and returns an error.
///
/// @param[in] attachment The NanoAttachment struct containing socket information.
/// @returns A NanoCommunicationResult indicating the success of the operation.
///
///     - #NANO_OK: Signaling socket initialized successfully.
///     - #NANO_ERROR: An error occurred during initialization.
///
static NanoCommunicationResult
init_signaling_socket(NanoAttachment *attachment)
{
    uint8_t initialization_ack;
    HttpEventThreadCtx ctx;
    int t_res;
    NanoCommunicationResult res;
    struct timeval timeout = get_absolute_timeout_val_sec(1);

    write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "spawn RegistrationCommSocketThread");
    t_res = NanoRunInThreadTimeout(
        attachment,
        NULL,
        RegistrationCommSocketThread,
        (void *)&ctx,
        attachment->registration_thread_timeout_msec,
        "RegistrationCommSocketThread",
        REGISTRATION
    );

    if (!t_res || ctx.res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to connect to connection socket");
        close(attachment->comm_socket);
        attachment->comm_socket = -1;
        if (attachment->registration_state != PENDING) {
            attachment->registration_state = NOT_REGISTERED;
        }
        return NANO_ERROR;
    }

    res = send_comm_data_to_comm_socket(attachment);
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send comm data");
        close(attachment->comm_socket);
        attachment->comm_socket = -1;
        if (attachment->registration_state != PENDING) {
            attachment->registration_state = NOT_REGISTERED;
        }
        return NANO_ERROR;
    }

    // Get an acknowledgement form the service that communication has been established.
    res = read_from_service(
        attachment,
        &attachment->comm_socket,
        &initialization_ack,
        sizeof(initialization_ack),
        &timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to read communication ack");
        close(attachment->comm_socket);
        attachment->comm_socket = -1;
        if (attachment->registration_state != PENDING) {
            attachment->registration_state = NOT_REGISTERED;
        }
        return NANO_ERROR;
    }

    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Successfully connected on client socket %d",
        attachment->comm_socket
    );
    return NANO_OK;
}

static NanoCommunicationResult
createDirectory(NanoAttachment *attachment, const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_DEBUG,
            "Nano attachment logging directory already exists"
        );
        return NANO_OK;
    }
    if (mkdir(path, 0755) == 0) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_DEBUG,
            "Successfully created logging directory"
        );
        return NANO_OK;
    }

    write_dbg(
        attachment,
        0,
        DBG_LEVEL_WARNING,
        "Failed to create logging directory"
    );

    return NANO_ERROR;
}

NanoCommunicationResult
set_docker_id(NanoAttachment *attachment)
{
    size_t len = MAX_NGINX_UID_LEN;
    char *line = NULL;
    char *docker_ptr = NULL;
    char *containerd_ptr = NULL;
    FILE *file = fopen(CONTAINER_ID_FILE_PATH, "r");
    if (file == NULL) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to open %s", CONTAINER_ID_FILE_PATH);
        return NANO_ERROR;
    }
    write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "opened file %s", CONTAINER_ID_FILE_PATH);

    line = malloc(MAX_NGINX_UID_LEN);
    if (line == NULL) {
        write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Failed to allocate memory for reading docker id file");
        fclose(file);
        return NANO_ERROR;
    }

    // Reading the file line by line.
    bool uid_read = false;
    while (getline(&line, &len, file) != -1) {
        docker_ptr = strstr(line, "docker/");
        containerd_ptr = strstr(line, "cri-containerd-");

        if (docker_ptr != NULL)
        {
            // We've found a line with "docker/" so the identifier will be right after that.
            write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "checking for docker/");
            docker_ptr += strlen("docker/");
            strncpy(attachment->container_id, docker_ptr, MAX_CONTAINER_ID_LEN - 1);
            attachment->container_id[MAX_CONTAINER_ID_LEN - 1] = '\0';
            uid_read = true;
            break;
        }

        if (containerd_ptr != NULL)
        {
            write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "checking for cri-containerd-");
            containerd_ptr += strlen("cri-containerd-");
            strncpy(attachment->container_id, containerd_ptr, MAX_CONTAINER_ID_LEN - 1);
            attachment->container_id[MAX_CONTAINER_ID_LEN - 1] = '\0';
            uid_read = true;
            break;
        }
    }

    if (!uid_read) {
        const char *env_var_name = "CLOUDGUARD_UID"; // Replace with your environment variable name
        const char *env_value = getenv(env_var_name);

        if (env_value) {
            strncpy(attachment->container_id, env_value, MAX_CONTAINER_ID_LEN - 1);
            attachment->container_id[MAX_CONTAINER_ID_LEN - 1] = '\0';
            uid_read = true;
        }
    }

    free(line);
    fclose(file);

    if (!uid_read) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Severe error - failed to get uid!");
        return NANO_ERROR;
    }

    return NANO_OK;
}

///
///@brief Sends registration data to the registration socket.
///
/// This function sends registration data to the registration socket of the given NanoAttachment.
/// It sends the attachment type, worker ID, total number of workers,
/// and the size and content of the container id (docker ID).
/// If any of the send operations fail, it returns NANO_ERROR; otherwise, it returns NANO_OK.
///
///@param attachment The NanoAttachment containing the registration socket and other necessary information.
///@return NanoCommunicationResult Returns NANO_OK if the registration data is successfully sent, otherwise NANO_ERROR.
///
NanoCommunicationResult
send_registration_data_to_registration_socket(NanoAttachment *attachment)
{
    uint8_t attachment_type = attachment->attachment_type;
    uint8_t worker_id = attachment->worker_id + 1;
    uint8_t workers_amount = attachment->num_of_workers;
    struct timeval absolute_timeout = get_absolute_timeout_val_sec(1);
    uint8_t container_id_size = strlen(attachment->container_id);
    NanoCommunicationResult res;

    // Send to the attachment manager the following details:
    // 1. The type of the attachment (fixed NGINX).
    // 2. The number of this worker.
    // 3. The total amount of workers.
    // 4. The size of the docker ID.
    // 5. If the docker ID isn't empty (size 0), the docker id itself.
    // If any of these fail - return an error.
    res = write_to_service(
        attachment,
        &attachment->registration_socket,
        &attachment_type,
        sizeof(attachment_type),
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send attachment type");
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->registration_socket,
        &worker_id,
        sizeof(worker_id),
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send worker ID");
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->registration_socket,
        &workers_amount,
        sizeof(workers_amount),
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send workers amount");
        return NANO_ERROR;
    }

    res = write_to_service(
        attachment,
        &attachment->registration_socket,
        &container_id_size,
        sizeof(container_id_size),
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send container id size");
        return NANO_ERROR;
    }

    if (container_id_size > 0) {
        res = write_to_service(
            attachment,
            &attachment->registration_socket,
            attachment->container_id,
            container_id_size,
            &absolute_timeout
        );
        if (res != NANO_OK) {
            write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to send container id");
            return NANO_ERROR;
        }
    }

    return NANO_OK;
}


///
/// @brief Reads the verdict signal path from the registration socket.
///
/// This function reads the verdict signal path from the registration socket of the given NanoAttachment.
/// It first reads the length of the signal path, then reads the signal path itself.
/// If the read operations fail or the path length exceeds the maximum allowed length, it returns NANO_ERROR;
/// otherwise, it returns NANO_OK.
///
/// @param attachment The NanoAttachment containing the registration socket and other necessary information.
/// @return NanoCommunicationResult Returns NANO_OK if the signal path is successfully read, otherwise NANO_ERROR.
///
NanoCommunicationResult
read_verdict_signal_path_from_registration_socket(NanoAttachment *attachment)
{
    uint8_t path_length;
    int registration_socket = attachment->registration_socket;
    uint8_t worker_id = attachment->worker_id + 1;
    uint8_t workers_amount = attachment->num_of_workers;
    NanoCommunicationResult res;
    struct timeval absolute_timeout = get_absolute_timeout_val_sec(1);
    // Read from the attachment manager:
    // 1. The length of signal path.
    // 2. The signal path itself.
    // If that fails - return an error.
    res = read_from_service(
        attachment,
        &attachment->registration_socket,
        &path_length,
        sizeof(path_length),
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to read path length");
        return NANO_ERROR;
    }

    if (path_length >= MAX_SHARED_MEM_PATH_LEN) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Verdict path length is too long");
        return NANO_ERROR;
    }

    res = read_from_service(
        attachment,
        &attachment->registration_socket,
        attachment->shared_verdict_signal_path,
        path_length,
        &absolute_timeout
    );
    if (res != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to read socket path");
        return NANO_ERROR;
    }

    // Successfully go the shared communication path - add null termination and exit.
    attachment->shared_verdict_signal_path[path_length] = '\0';
    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Successfully registered on client. socket: %d, instance ID: %u, instances amount: %u, received path: %s",
        registration_socket,
        (uint32_t)worker_id,
        (uint32_t)workers_amount,
        attachment->shared_verdict_signal_path
    );
    return NANO_OK;
}

NanoCommunicationResult
register_to_attachments_manager(NanoAttachment *attachment)
{
    NanoCommunicationResult res;
    HttpEventThreadCtx ctx;
    int t_res;

    // If there was an old socket, close it.
    if (attachment->registration_socket > 0) {
        close(attachment->registration_socket);
        attachment->registration_socket = -1;
    }

    write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "spawn RegistrationSocketThread");
    t_res = NanoRunInThreadTimeout(
        attachment,
        NULL,
        RegistrationSocketThread,
        (void *)&ctx,
        attachment->registration_thread_timeout_msec,
        "RegistrationSocketThread",
        REGISTRATION
    );

    if (!t_res || ctx.res != NANO_OK) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_WARNING,
            "Failed to connect to registration socket"
        );
        close(attachment->registration_socket);
        attachment->registration_socket = -1;
        return NANO_ERROR;
    }

    res = send_registration_data_to_registration_socket(attachment);
    if (res != NANO_OK) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_WARNING,
            "Failed to send registration data"
        );
        close(attachment->registration_socket);
        attachment->registration_socket = -1;
        return NANO_ERROR;
    }

    res = read_verdict_signal_path_from_registration_socket(attachment);
    if (res != NANO_OK) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_WARNING,
            "Failed to read verdict signal path"
        );
        close(attachment->registration_socket);
        attachment->registration_socket = -1;
        return NANO_ERROR;
    }

    close(attachment->registration_socket);
    attachment->registration_socket = -1;
    return NANO_OK;
}

NanoCommunicationResult
set_unique_id(NanoAttachment *attachment)
{
    unsigned int unique_id_size = 0;
    long unsigned int nano_worker_id = attachment->worker_id + 1;

    if (strlen(attachment->container_id) > 0) {
        unique_id_size += snprintf(
            attachment->unique_id,
            MAX_NGINX_UID_LEN,
            "%s_%lu",
            attachment->container_id,
            nano_worker_id);
    } else {
        unique_id_size += snprintf(attachment->unique_id, MAX_NGINX_UID_LEN, "%lu", nano_worker_id);
    }

    if (unique_id_size <= 0) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to set attachment's unique_id");
        return NANO_ERROR;
    }

    if (unique_id_size >= MAX_NGINX_UID_LEN) {
        write_dbg(attachment, 0, DBG_LEVEL_INFO, "Unique ID is too long, trancheated to: %s", attachment->unique_id);
    }

    write_dbg(attachment, 0, DBG_LEVEL_INFO, "Successfully set attachment's unique_id: '%s'", attachment->unique_id);
    return NANO_OK;
}

NanoCommunicationResult
set_logging_fd(NanoAttachment *attachment, int logging_fd)
{
    char full_logging_path[128];

    if (logging_fd > 0) {
        attachment->is_default_fd = 0;
        attachment->logging_fd = logging_fd;
        write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Successfully set provided logging_fd");
        return NANO_OK;
    }

    if (createDirectory(attachment, LOGGING_DIRECTORY_PATH) != NANO_OK) {
        return NANO_ERROR;
    }

    snprintf(full_logging_path, sizeof(full_logging_path), "%s-%s.dbg", LOGGING_FILE_PATH, attachment->container_id);
    attachment->logging_fd = open(full_logging_path, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (attachment->logging_fd < 0) {
        return NANO_ERROR;
    }

    attachment->is_default_fd = 1;
    write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Successfully opened logging file");
    return NANO_OK;
}

void
close_logging_fd(NanoAttachment *attachment)
{
    if (attachment->logging_fd > 0 && attachment->is_default_fd) {
        close(attachment->logging_fd);
        attachment->logging_fd = -1;
    }
    free(attachment->logging_data);
    attachment->logging_data = NULL;
}

NanoCommunicationResult
nano_attachment_init_process(NanoAttachment *attachment)
{
    attachment->nano_user_id = getuid();
    attachment->nano_group_id = getgid();
    attachment->num_of_connection_attempts++;

    init_attachment_config(attachment, SHARED_ATTACHMENT_CONF_PATH);

    if (access(SHARED_REGISTRATION_SIGNAL_PATH, F_OK) != 0) {
        write_dbg(attachment, 0, DBG_LEVEL_TRACE, "Attachment registration manager is turned off");
        return NANO_ABORT;
    }

    if (attachment->registration_state == PENDING) {
        write_dbg(attachment, 0, DBG_LEVEL_INFO, "Registration to the Attachments Manager is in process");
        return NANO_ERROR;
    }

    if (attachment->registration_state == NOT_REGISTERED) {
        // Register with the attachment manager.
        if (register_to_attachments_manager(attachment) == NANO_ERROR) {
            write_dbg(attachment, 0, DBG_LEVEL_INFO, "Failed to register to Attachments Manager service");
            return NANO_ERROR;
        }
        attachment->registration_state = REGISTERED;
    }

    if (init_attachment_config(attachment, SHARED_ATTACHMENT_CONF_PATH) == NANO_ERROR) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to initialize attachment's configuration");
        return NANO_ERROR;
    }

    if (attachment->comm_socket < 0) {
        // Signal to the service to start communication.
        write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Registering to nano service");
        if (init_signaling_socket(attachment) == NANO_ERROR) {
            write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Failed to register to the Nano Service");
            return NANO_ERROR;
        }
    }

    // Initalize the the communication channel with the service.
    if (attachment->nano_service_ipc == NULL) {
        write_dbg(attachment, 0, DBG_LEVEL_INFO, "Initializing IPC channel");
        attachment->nano_service_ipc = initIpc(
            attachment->unique_id,
            attachment->nano_user_id,
            attachment->nano_group_id,
            0,
            attachment->num_of_nano_ipc_elements,
            attachment->logging_data,
            write_dbg_impl
        );
        if (attachment->nano_service_ipc == NULL) {
            restart_communication(attachment);
            write_dbg(attachment, 0, DBG_LEVEL_INFO, "Failed to initialize IPC with nano service");
            return NANO_ERROR;
        }
    }

    write_dbg(
        attachment,
        0,
        DBG_LEVEL_INFO,
        "NGINX attachment (UID='%s') successfully registered to nano service after %d attempts.",
        attachment->unique_id,
        attachment->num_of_connection_attempts
    );

    attachment->num_of_connection_attempts = 0;

    return NANO_OK;
}

NanoCommunicationResult
restart_communication(NanoAttachment *attachment)
{
    write_dbg(attachment, 0, DBG_LEVEL_TRACE, "Restarting communication channels with nano service");
    if (attachment->nano_service_ipc != NULL) {
        destroyIpc(attachment->nano_service_ipc, 0);
        attachment->nano_service_ipc = NULL;
    }

    if (init_signaling_socket(attachment) == NANO_ERROR) {
        if (register_to_attachments_manager(attachment) == NANO_ERROR) {
            write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Failed to register to Attachments Manager service");
            return NANO_ERROR;
        }

        if (init_signaling_socket(attachment) == NANO_ERROR) {
            write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Failed to init the signaling socket");
            return NANO_ERROR;
        }
    }
    attachment->nano_service_ipc = initIpc(
        attachment->unique_id,
        attachment->nano_user_id,
        attachment->nano_group_id,
        0,
        attachment->num_of_nano_ipc_elements,
        attachment->logging_data,
        write_dbg_impl
    );
    if (attachment->nano_service_ipc == NULL) {
        write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Failed to init IPC");
        return NANO_ERROR;
    }
    return NANO_OK;
}

void
disconnect_communication(NanoAttachment *attachment)
{
    write_dbg(attachment, 0, DBG_LEVEL_DEBUG, "Disconnecting communication channels with nano service");

    if (attachment->comm_socket > 0) {
        close(attachment->comm_socket);
        attachment->comm_socket = -1;
    }
    if (attachment->nano_service_ipc != NULL) {
        destroyIpc(attachment->nano_service_ipc, 0);
        attachment->nano_service_ipc = NULL;
    }
}

NanoCommunicationResult
handle_shmem_corruption(NanoAttachment *attachment)
{
    NanoCommunicationResult res;

    if (attachment->nano_service_ipc == NULL) {
        disconnect_communication(attachment);
        res = restart_communication(attachment);
        if (res != NANO_OK) {
            write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to restart communication");
            return NANO_ERROR;
        }
    }

    if (isCorruptedShmem(attachment->nano_service_ipc, 0)) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Shared memory is corrupted! restarting communication");
        disconnect_communication(attachment);
        return NANO_ERROR;
    }

    return NANO_OK;
}

int
isIpcReady(NanoAttachment *attachment)
{
    return attachment->nano_service_ipc != NULL && attachment->comm_socket > 0;
}
