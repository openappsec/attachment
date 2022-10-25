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

/// @file ngx_cp_initializer.h
#ifndef __NGX_CP_INITIALIZER_H__
#define __NGX_CP_INITIALIZER_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef enum ngx_cp_comm_direction {
    READ_FROM_SOCKET,
    WRITE_TO_SOCKET
} ngx_cp_comm_direction_e; ///< Indicate whether communication exchange is to read or to write from a socket. 

///
/// @brief Initialize all the attachments resources and communication channels.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///         - #NGX_ABORT
///
ngx_int_t ngx_cp_attachment_init_process(ngx_http_request_t *);

///
/// @brief Preforms send\receive information to\from the service via a socket.
/// @param[in] socket The file descriptor of the socket to work with.
/// @param[in, out] data An allocated memory which data will be read from (if sending) or written to (if recieving).
/// @param[in] size The number of bytes in the allocated memoty.
/// @param[in] direction Sets whether we read from the socket or write to it:
///     - #READ_FROM_SOCKET
///     - #WRITE_TO_SOCKET
/// @param[in] remaining_timeout Points to the maximal time point the function is allowed to reach.
/// @return int - positive if successful, other values indicate an error. 
///
int exchange_communication_data_with_service(
    int socket,
    void *data,
    uint32_t size,
    ngx_cp_comm_direction_e direction,
    struct timeval *remaining_timeout);

///
/// @brief Get an identifier that distinguish between different instances running on the same machine.
/// @return A null-terminated string that is unique to this instance.
///
const char * get_unique_id();

///
/// @brief Get an identifier for the current docker instance.
/// @param[out] _docker_id Will point to the null terminated string (which shouldn't be freed) indentifier
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t get_docker_id(char **_docker_id);

///
/// @brief Closes any existing communication to the service and tries to open a new one.
/// @param[in] request Points to an HTTP request, needed to get the number of workers.
/// @returns int - 0 on success, negative number on failure.
///
int restart_communication(ngx_http_request_t *request);

///
/// @brief Checks that the shared memory with the service isn't corrupted, disconnect if it is.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
ngx_int_t handle_shmem_corruption();

///
/// @brief Closes all the communication channels with the service.
///
void disconnect_communication();

///
/// @brief Checks if communication with the service is up and running.
/// @returns ngx_int_t - 1 if communication is active, otherwise 0.
///
ngx_int_t isIpcReady();

#endif // __NGX_CP_INITIALIZER_H__
