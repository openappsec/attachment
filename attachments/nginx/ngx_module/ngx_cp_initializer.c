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

/// @file ngx_cp_initializer.c
#include "ngx_cp_initializer.h"

#include <poll.h>
#include <stdint.h>
#include <dirent.h>
#include <arpa/inet.h>

#include <ngx_log.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_files.h>

#include "nginx_attachment_common.h"
#include "ngx_cp_io.h"
#include "ngx_cp_utils.h"
#include "ngx_cp_static_content.h"
#include "ngx_cp_compression.h"
#include "attachment_types.h"
#include "ngx_http_cp_attachment_module.h"

typedef enum ngx_cp_attachment_registration_state {
    SET_UNIQUE_ID,
    RESGISTER_TO_NODE,
    LOAD_CONFIG,
    LOAD_IPC,
    DONE
} ngx_cp_attachment_registration_state_e; ///< Indicates the current initialization stage.

char unique_id[MAX_NGINX_UID_LEN] = ""; // Holds the unique identifier for this instance.
char shared_verdict_signal_path[128]; // Holds the path associating the attachment and service.

int registration_socket = -1; // Holds the file descriptor used for registering the instance.

struct sockaddr_un server;

uint32_t nginx_user_id, nginx_group_id; // Hold the process UID and GID respectively.

int
exchange_communication_data_with_service(
    int socket,
    void *data,
    uint32_t size,
    ngx_cp_comm_direction_e direction,
    struct timeval *remaining_timeout)
{
    int res = 0;
    ngx_int_t retry;
    // `remaining_size` and `cur_data_ptr` are used to keep track of where we are in the memory.
    // This allows us to read to\write from the socket in parts (if we need to).
    int remaining_size = size;
    char *cur_data_ptr = data;

    while (remaining_size > 0) {
        if (direction == WRITE_TO_SOCKET){
            res = write(socket, (void *)cur_data_ptr, remaining_size);
        } else {
             // The read operation must not block the attachment indefinitely.
             // To avoid that we check whether the socket has data to be read prior to the read operation.
             // If the socket doesn't have data to be read from within a reasonable time, we treat this as an error.
             for (retry = 0; retry < 3; retry++) {
                struct pollfd s_poll;
                s_poll.fd = socket;
                s_poll.events = POLLIN;
                s_poll.revents = 0;
                res = poll(&s_poll, 1, 1000);
                if (res > 0 && (s_poll.revents & POLLIN) != 0) break; // Socket is ready to be read from
                res = -1;
            }

            if (res != -1) {
                res = read(socket, (void *)cur_data_ptr, remaining_size);
            }
        }

        // `res` is -1 in case of an error: either write or read functions failed or socket wasn't available.
        if (res < 0) {
            close(socket);
            socket = -1;
            write_dbg(DBG_LEVEL_TRACE, "Failed to communicate with the socket, Error: %s", strerror(errno));
            break;
        }

        remaining_size -= res;
        cur_data_ptr += res;

        // If the operation exceeded the allowed time, treat it as a failure.
        if (is_timeout_reached(remaining_timeout)) {
            close(socket);
            socket = -1;
            write_dbg(DBG_LEVEL_TRACE, "Reached timeout while communicating with the socket");
            break;
        }
    }
    return res;
}

///
/// @brief Initialize socket communication with the serive.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
/// 
static ngx_int_t
init_signaling_socket()
{
    uint8_t initialization_ack;
    int res = 0;
    uint8_t uid_size_to_send = strlen(unique_id);
    struct timeval timeout = get_timeout_val_sec(1);

    // Close the old socket if there was one.
    if (comm_socket > 0) {
        close(comm_socket);
        comm_socket = -1;
    }

    // Setup a new socket
    comm_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (comm_socket < 0) {
        write_dbg(DBG_LEVEL_WARNING, "Could not create socket, Error: %s", strerror(errno));
        return NGX_ERROR;
    }

    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, shared_verdict_signal_path, sizeof(server.sun_path) - 1);

    if (connect(comm_socket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) == -1) {
        close(comm_socket);
        comm_socket = -1;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Could not connect to nano service. Path: %s, Error: %s",
            server.sun_path,
            strerror(errno)
        );
        return NGX_ERROR;
    }

    // Pass the following information to the service (in this order):
    // 1. The length of the unique identifier for this instance.
    // 2. The unique identifier for this instance.
    // 3. The process UID.
    // 4. The process GID.
    // If any of them fail - return an error.
    res = exchange_communication_data_with_service(
        comm_socket,
        &uid_size_to_send,
        sizeof(uid_size_to_send),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send unique id size");
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        comm_socket,
        unique_id,
        uid_size_to_send,
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send unique id %s", unique_id);
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(comm_socket, &nginx_user_id, sizeof(uint32_t), WRITE_TO_SOCKET, &timeout);
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send nginx user id");
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        comm_socket,
        &nginx_group_id,
        sizeof(uint32_t),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send nginx group id");
        return NGX_ERROR;
    }

    // Get an acknowledgement form the service that communication has been established.
    timeout = get_timeout_val_sec(1);
    res = exchange_communication_data_with_service(
        comm_socket,
        &initialization_ack,
        sizeof(initialization_ack),
        READ_FROM_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to read registration ack");
        return NGX_ERROR;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Successfully connected on client socket %d", comm_socket);
    return NGX_OK;
}

#define MAX_CONTAINER_LEN 12 // Maximum size for container identifier

ngx_int_t
get_docker_id(char **_docker_id)
{
    // We keep the container ID as a static variable so we won't have to read it multiple times.
    // The `already_evaluated` variable indicate if we already have the identifier.
    static char docker_id[MAX_CONTAINER_LEN + 1];
    static int already_evaluated = 0;
    const char *container_id_file_path = "/proc/self/cgroup";
    if (already_evaluated) {
        // Already found the identifier before, just return the answer.
        *_docker_id = docker_id;
        return  NGX_OK;
    }

    docker_id[0] = '\0';

    FILE *file = fopen(container_id_file_path, "r");
    if (file == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to open %s", container_id_file_path);
        return NGX_ERROR;
    }
    write_dbg(DBG_LEVEL_DEBUG, "opened file %s", container_id_file_path);

    // Reading the file line by line.
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, file) != -1) {
        char *docker_ptr = strstr(line, "docker/");
        if (docker_ptr == NULL) continue;

        // We've found a line with "docker/" so the identifier will be right after that.
        docker_ptr += strlen("docker/");
        snprintf(docker_id, MAX_CONTAINER_LEN + 1, "%s", docker_ptr);
        break;
    }
    free(line);
    fclose(file);

    // Return the answer and set the indication so we won't have to 
    *_docker_id = docker_id;
    already_evaluated = 1;
    return  NGX_OK;
}

///
/// @brief Register the attachment instance with the attachment manager to associate it with a service.
/// @param[in] request Points to an HTTP request, needed to get the number of workers.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
register_to_attachments_manager(ngx_http_request_t *request)
{
    uint8_t path_length;
    int res = 0;
    uint8_t family_name_size = strlen(unique_id);
    uint8_t attachment_type = NGINX_ATT_ID;
    uint8_t worker_id = ngx_worker + 1;
    uint8_t workers_amount = get_num_of_workers(request);
    char *family_name = NULL;
    int cur_errno = 0; // temp fix for errno changing during print
    struct timeval timeout = get_timeout_val_sec(1);

    if (get_docker_id(&family_name) == NGX_ERROR) {
    	write_dbg(DBG_LEVEL_WARNING, "Could not evaluate family name");
        return NGX_ERROR;
    }
    family_name_size = strlen(family_name);

    // If there was an old socket, close it.
    if (registration_socket > 0) {
        close(registration_socket);
        registration_socket = -1;
    }

    // Connect a new socket.
    registration_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (registration_socket < 0) {
    	write_dbg(DBG_LEVEL_WARNING, "Could not create socket, Error: %s", strerror(errno));
        return NGX_ERROR;
    }

    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, SHARED_REGISTRATION_SIGNAL_PATH, sizeof(server.sun_path) - 1);

    if (connect(registration_socket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) == -1) {
        cur_errno = errno;
        close(registration_socket);
        registration_socket = -1;
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Could not connect to nano service. Path: %s, Error: %s, Errno: %d",
            server.sun_path,
            strerror(errno),
            cur_errno
        );
        if (cur_errno == ENOENT) {
            strncpy(shared_verdict_signal_path, SHARED_VERDICT_SIGNAL_PATH, 128);
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    // Send to the attachment manager the following details:
    // 1. The type of the attachment (fixed NGINX).
    // 2. The number of this worker.
    // 3. The total amount of workers.
    // 4. The size of the docker ID.
    // 5. If the docker ID isn't empty (size 0), the docker id itself.
    // If any of these fail - return an error.
    res = exchange_communication_data_with_service(
        registration_socket,
        &attachment_type,
        sizeof(attachment_type),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send attachment type");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        registration_socket,
        &worker_id,
        sizeof(worker_id),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send worker ID");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        registration_socket,
        &workers_amount,
        sizeof(workers_amount),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send workers amount");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        registration_socket,
        &family_name_size,
        sizeof(family_name_size),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send family name size");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    if (family_name_size > 0) {
        res = exchange_communication_data_with_service(
            registration_socket,
            family_name,
            family_name_size,
            WRITE_TO_SOCKET,
            &timeout
        );
        if (res <= 0) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to send family name");
            close(registration_socket);
            registration_socket = -1;
            return NGX_ERROR;
        }
    }

    // Read from the attachment manager:
    // 1. The length of signal path.
    // 2. The signal path itself.
    // If that fails - return an error.
    timeout = get_timeout_val_sec(1);
    res = exchange_communication_data_with_service(
        registration_socket,
        &path_length,
        sizeof(path_length),
        READ_FROM_SOCKET,
        &timeout
    );

    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to read path length");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    res = exchange_communication_data_with_service(
        registration_socket,
        shared_verdict_signal_path,
        path_length,
        READ_FROM_SOCKET,
        &timeout
    );
    if (res <= 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to read socket path");
        close(registration_socket);
        registration_socket = -1;
        return NGX_ERROR;
    }

    // Successfully go the shared communication path - add null termination and exit.
    shared_verdict_signal_path[path_length] = '\0';
    int32_t dbg_id = worker_id;
    int32_t dbg_size = workers_amount_to_send;
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Successfully registered on client. socket: %d, instance ID: %d, instances amount: %d, received path: %s",
        registration_socket,
        dbg_id,
        dbg_size,
        shared_verdict_signal_path
    );
    close(registration_socket);
    registration_socket = -1;
    return NGX_OK;
}

const char *
get_unique_id()
{
    return unique_id;
}

static ngx_int_t
set_unique_id()
{
    int is_container_env = 0;
    static const int max_container_id_len = 12;
    const char *container_id_file_path = "/proc/self/cgroup";

    unsigned int unique_id_size = 0;
    if (strlen(unique_id) > 0) return NGX_OK;

    FILE *file = fopen(container_id_file_path, "r");
    if (file == NULL) {
    	write_dbg(DBG_LEVEL_WARNING, "Failed to open %s", container_id_file_path);
    	return NGX_ERROR;
    }

    char *line = NULL;
    char docker_id[max_container_id_len + 1];
    memset(docker_id, '\0', max_container_id_len + 1);
    size_t len = 0;
    while (getline(&line, &len, file) != -1) {
        char *docker_ptr = strstr(line, "docker/");
        if (docker_ptr == NULL) continue;

        is_container_env = 1;
        docker_ptr += strlen("docker/");
        snprintf(docker_id, max_container_id_len + 1, "%s", docker_ptr);
        break;
    }
    free(line);
    fclose(file);
    long unsigned int ngx_worker_id = ngx_worker + 1;
    if (is_container_env) {
        unique_id_size += strlen(docker_id) + 1 + get_number_of_digits(ngx_worker_id) + 1;
        snprintf(unique_id, unique_id_size, "%s_%lu", docker_id, ngx_worker_id);
    } else {
        unique_id_size += get_number_of_digits(ngx_worker_id) + 1;
        snprintf(unique_id, unique_id_size, "%lu", ngx_worker_id);
    }

    write_dbg(DBG_LEVEL_INFO, "Successfully set attachment's unique_id: '%s'", unique_id);
    return NGX_OK;
}

ngx_int_t
ngx_cp_attachment_init_process(ngx_http_request_t *request)
{
    ngx_pool_t *memory_pool;
    nginx_user_id = getuid();
    nginx_group_id = getgid();
    static int need_registration = 1;
    num_of_connection_attempts++;

    // Best-effort attempt to read the configuration before we start.
    init_general_config(SHARED_ATTACHMENT_CONF_PATH);

    // Initalizing the various elements of the system (if needed):
    // 1. Get the unique identifier.
    // 2. Register with the attachment manager.
    // 3. Signal to the service to start communication.
    // 4. Make sure that the configuration is up-to-date.
    if (access(SHARED_REGISTRATION_SIGNAL_PATH, F_OK) != 0) {
        write_dbg(DBG_LEVEL_TRACE, "Attachment registration manager is turned off");
        return NGX_ABORT;
    }

    if (strncmp(unique_id, "", 1) == 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Setting attachment's unique id");
        if (set_unique_id() == NGX_ERROR) {
    	    write_dbg(DBG_LEVEL_INFO, "Failed to set attachment's unique_id");
            return NGX_ERROR;
        }
    }

    if (need_registration) {
        if (register_to_attachments_manager(request) == NGX_ERROR) {
            write_dbg(DBG_LEVEL_INFO, "Failed to register to Attachments Manager service");
            return NGX_ERROR;
        }
        need_registration = 0;
    }

    if (comm_socket < 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Registering to nano service");
        if (init_signaling_socket() == NGX_ERROR) {
            write_dbg(DBG_LEVEL_DEBUG, "Failed to register to the Nano Service");
            need_registration = 1;
            return NGX_ERROR;
        }
    }

    if (init_general_config(SHARED_ATTACHMENT_CONF_PATH) == NGX_ERROR) {
        write_dbg(DBG_LEVEL_INFO, "Failed to initialize attachment's configuration");
        return NGX_ERROR;
    }

    // Initalize the the communication channel with the service.
    // If we encounter repeated failures - we will restart the whole communication.
    static const int  max_ipc_init_retry_count = 10;
    static int max_retry_count = max_ipc_init_retry_count;
    if (nano_service_ipc == NULL) {
        write_dbg(DBG_LEVEL_INFO, "Initializing IPC channel");
        nano_service_ipc = initIpc(
            unique_id,
            nginx_user_id,
            nginx_group_id,
            0,
            num_of_nginx_ipc_elements,
            write_dbg_impl
        );
        if (nano_service_ipc == NULL) {
            if (max_retry_count-- == 0) {
                restart_communication(request);
                max_retry_count = max_ipc_init_retry_count;
            }
            write_dbg(DBG_LEVEL_INFO, "Failed to initialize IPC with nano service");
            return NGX_ERROR;
        }
    }
    max_retry_count = max_ipc_init_retry_count;

    // Initialize internal resources.
    if (!is_static_resources_table_initialized()) {
        memory_pool = get_memory_pool();
        if (memory_pool == NULL) {
            write_dbg(DBG_LEVEL_WARNING, "Cannot initialize static resources. No memory pool has been allocated.");
            return NGX_ERROR;
        }
        write_dbg(DBG_LEVEL_DEBUG, "Initializing static resources");
        if (init_static_resources(memory_pool) != NGX_OK) {
            write_dbg(DBG_LEVEL_WARNING, "Failed to initialize static resources");
            return NGX_ERROR;
        }
    }

    if (!is_compression_debug_printing_initialized()) {
        write_dbg(DBG_LEVEL_DEBUG, "Initializing compression debug message printing");
        initialize_compression_debug_printing();
    }

    // we want to indicate about successful registration only once in default level
    write_dbg(dbg_is_needed ? DBG_LEVEL_DEBUG : DBG_LEVEL_INFO, "NGINX attachment (UID='%s') successfully registered to nano service after %d attempts.", unique_id, num_of_connection_attempts);

    dbg_is_needed = 1;
    num_of_connection_attempts = 0;

    return NGX_OK;
}

int
restart_communication(ngx_http_request_t *request)
{
    write_dbg(DBG_LEVEL_TRACE, "Restarting communication channels with nano service");
    if (nano_service_ipc != NULL) {
        destroyIpc(nano_service_ipc, 0);
        nano_service_ipc = NULL;
    }

    if (init_signaling_socket() == NGX_ERROR) {
        if (register_to_attachments_manager(request) == NGX_ERROR) {
            write_dbg(DBG_LEVEL_DEBUG, "Failed to register to Attachments Manager service");
            return -1;
        }

        if (init_signaling_socket() == NGX_ERROR) return -1;
    }
    nano_service_ipc = initIpc(unique_id, nginx_user_id, nginx_group_id, 0, num_of_nginx_ipc_elements, write_dbg_impl);
    if (nano_service_ipc == NULL) return -2;
    return 0;
}

void
disconnect_communication()
{
    if (comm_socket > 0) {
        close(comm_socket);
        comm_socket = -1;
    }
    if (nano_service_ipc != NULL) {
        destroyIpc(nano_service_ipc, 0);
        nano_service_ipc = NULL;
    }
}

ngx_int_t
handle_shmem_corruption()
{
    if (nano_service_ipc == NULL) return NGX_OK;

    if (isCorruptedShmem(nano_service_ipc, 0)) {
        write_dbg(DBG_LEVEL_WARNING, "Shared memory is corrupted! restarting communication");
        disconnect_communication();
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
isIpcReady()
{
    return nano_service_ipc != NULL && comm_socket > 0;
}
