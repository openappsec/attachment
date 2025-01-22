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

#include "shmem_ipc_2.h"

#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

#include "shared_ring_queue.h"
#include "shared_ipc_debug.h"

#define UNUSED(x) (void)(x)

const int corrupted_shmem_error = CORRUPTED_SHMEM_ERROR;
static const size_t max_one_way_queue_name_length = MAX_ONE_WAY_QUEUE_NAME_LENGTH;
static const size_t max_shmem_path_length = 72;

struct SharedMemoryIPC {
    char shm_name[32];
    SharedRingQueue *rx_queue;
    SharedRingQueue *tx_queue;
    SharedRingGlobalData *global_data;
    LoggingData logging_data;
};

// LCOV_EXCL_START Reason: Handing it to Envoy prototype development

void
debugInitial(
    const LoggingData *loggin_data,
    uint32_t worker_id,
    int is_error,
    const char *func,
    const char *file,
    int line_num,
    const char *fmt,
    ...
)
{
    UNUSED(is_error);
    UNUSED(func);
    UNUSED(file);
    UNUSED(line_num);
    UNUSED(loggin_data);
    UNUSED(worker_id);

    // Temporarily disabled till Shmem debugging is properly fixed.
    // va_list args;
    // va_start(args, fmt);
    // vprintf(fmt, args);
    // va_end(args);

    UNUSED(fmt);
}

void (*debug_int)(
    const LoggingData *loggin_data,
    uint32_t worker_id,
    int is_error,
    const char *func,
    const char *file,
    int line_num,
    const char *fmt,
    ...
) = debugInitial;


static int
isTowardsOwner(int is_owner, int is_tx)
{
    if (is_owner) return !is_tx;
    return is_tx;
}

static SharedRingQueue *
createOneWayIPCQueue(
    LoggingData *logging_data,
    const char *name,
    const uint32_t user_id,
    const uint32_t group_id,
    int is_tx_queue,
    int is_owner,
    uint16_t num_of_queue_elem,
    SharedRingGlobalData *global_data
)
{
    SharedRingQueue *ring_queue = NULL;
    char queue_name[max_one_way_queue_name_length];
    char shmem_path[max_shmem_path_length];
    const char *direction = isTowardsOwner(is_owner, is_tx_queue) ? "rx" : "tx";
    snprintf(queue_name, sizeof(queue_name) - 1, "__cp_nano_%s_shared_memory_%s__", direction, name);

    writeDebug(
        logging_data,
        TraceLevel,
        "Creating one way IPC queue. Name: %s, direction: %s, size: %d",
        name,
        direction,
        num_of_queue_elem
    );
    ring_queue = createSharedRingQueue(
        logging_data,
        queue_name,
        num_of_queue_elem,
        is_owner,
        isTowardsOwner(is_owner, is_tx_queue),
        global_data
    );
    if (ring_queue == NULL) {
        writeDebug(
            logging_data,
            WarningLevel,
            "Failed to create %s shared ring queue of size=%d for '%s'\n",
            direction,
            num_of_queue_elem,
            queue_name
        );
        return NULL;
    }
    int ret = snprintf(shmem_path, sizeof(shmem_path) - 1, "/dev/shm/%s", queue_name);
    if (ret < 0 || (size_t)ret < (strlen(direction) + strlen(name))) {
        return NULL;
    }

    if (is_owner && chmod(shmem_path, 0666) == -1) {
        writeDebug(logging_data, WarningLevel, "Failed to set the permissions");
        destroySharedRingQueue(logging_data, ring_queue, global_data, is_owner, isTowardsOwner(is_owner, is_tx_queue));
        return NULL;
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Successfully created one way IPC queue. "
        "Name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u, direction: %s, path: %s",
        queue_name,
        user_id,
        group_id,
        is_owner,
        num_of_queue_elem,
        direction,
        shmem_path
    );
    return ring_queue;
}

LoggingData *
initLoggingData(int dbg_level, int worker_id, int fd)
{
    LoggingData *logging_data = malloc(sizeof(LoggingData));
    if (logging_data == NULL) {
        return NULL;
    }
    logging_data->dbg_level = dbg_level;
    logging_data->worker_id = worker_id;
    logging_data->fd = fd;
    return logging_data;
}

SharedMemoryIPC *
initIpc(
    const char queue_name[32],
    uint32_t user_id,
    uint32_t group_id,
    int is_owner,
    uint16_t num_of_queue_elem,
    const LoggingData *logging_data,
    void (*debug_func)(
        const LoggingData *loggin_data,
        uint32_t worker_id,
        int is_error,
        const char *func,
        const char *file,
        int line_num,
        const char *fmt,
        ...
    )
)
{
    UNUSED(debug_func);
    SharedMemoryIPC *ipc = NULL;
    // debug_int = debug_func;
    debug_int = debugInitial;

    writeDebug(
        logging_data,
        TraceLevel,
        "Initializing new IPC. "
        "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u\n",
        queue_name,
        user_id,
        group_id,
        is_owner,
        num_of_queue_elem
    );

    ipc = malloc(sizeof(SharedMemoryIPC));
    if (ipc == NULL) {
        writeDebug(logging_data, WarningLevel, "Failed to allocate Shared Memory IPC for '%s'\n", queue_name);
        debug_int = debugInitial;
        return NULL;
    }

    ipc->logging_data.dbg_level = logging_data->dbg_level;
    ipc->logging_data.worker_id = logging_data->worker_id;
    ipc->logging_data.fd = logging_data->fd;

    ipc->global_data = createSharedRingGlobalData(&(ipc->logging_data));
    if (ipc->global_data == NULL) {
        writeDebug(logging_data, WarningLevel, "Failed to allocate global data for '%s'\n", queue_name);
        debug_int = debugInitial;
        free(ipc);
        return NULL;
    }

    ipc->rx_queue = NULL;
    ipc->tx_queue = NULL;

    ipc->rx_queue = createOneWayIPCQueue(
        &(ipc->logging_data),
        queue_name,
        user_id,
        group_id,
        0,
        is_owner,
        num_of_queue_elem,
        ipc->global_data
    );
    if (ipc->rx_queue == NULL) {
        writeDebug(
            &(ipc->logging_data),
            WarningLevel,
            "Failed to allocate rx queue. "
            "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u",
            queue_name,
            user_id,
            group_id,
            is_owner,
            num_of_queue_elem
        );

        destroyIpc(ipc, is_owner);
        debug_int = debugInitial;
        return NULL;
    }

    ipc->tx_queue = createOneWayIPCQueue(
        &(ipc->logging_data),
        queue_name,
        user_id,
        group_id,
        1,
        is_owner,
        num_of_queue_elem,
        ipc->global_data
    );
    if (ipc->tx_queue == NULL) {
        writeDebug(
            &(ipc->logging_data),
            WarningLevel,
            "Failed to allocate rx queue. "
            "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u",
            queue_name,
            user_id,
            group_id,
            is_owner,
            num_of_queue_elem
        );
        destroyIpc(ipc, is_owner);
        debug_int = debugInitial;
        return NULL;
    }

    writeDebug(&(ipc->logging_data), TraceLevel, "Successfully allocated IPC");

    strncpy(ipc->shm_name, queue_name, sizeof(ipc->shm_name));
    return ipc;
}

void
resetIpc(SharedMemoryIPC *ipc, uint16_t num_of_data_segments)
{
    writeDebug(&(ipc->logging_data), TraceLevel, "Reseting IPC queues\n");
    resetRingQueue(&(ipc->logging_data), ipc->rx_queue, num_of_data_segments);
    resetRingQueue(&(ipc->logging_data), ipc->tx_queue, num_of_data_segments);
}

void
destroyIpc(SharedMemoryIPC *shmem, int is_owner)
{
    writeDebug(&(shmem->logging_data), TraceLevel, "Destroying IPC queues\n");

    if (shmem->rx_queue != NULL) {
        destroySharedRingQueue(
            &(shmem->logging_data),
            shmem->rx_queue,
            shmem->global_data,
            is_owner,
            isTowardsOwner(is_owner, 0)
        );
        shmem->rx_queue = NULL;
    }
    if (shmem->tx_queue != NULL) {
        destroySharedRingQueue(
            &(shmem->logging_data),
            shmem->tx_queue,
            shmem->global_data,
            is_owner,
            isTowardsOwner(is_owner, 1)
        );
        shmem->tx_queue = NULL;
    }
    free(shmem->global_data);
    debug_int = debugInitial;
    free(shmem);
}

void
dumpIpcMemory(SharedMemoryIPC *ipc)
{
    writeDebug(&(ipc->logging_data), WarningLevel, "Ipc memory dump:\n");
    writeDebug(&(ipc->logging_data), WarningLevel, "RX queue:\n");
    dumpRingQueueShmem(&(ipc->logging_data), ipc->rx_queue);
    writeDebug(&(ipc->logging_data), WarningLevel, "TX queue:\n");
    dumpRingQueueShmem(&(ipc->logging_data), ipc->tx_queue);
}

int
sendData(SharedMemoryIPC *ipc, const uint16_t data_to_send_size, const char *data_to_send)
{
    writeDebug(&(ipc->logging_data), TraceLevel, "Sending data of size %u\n", data_to_send_size);
    return pushToQueue(&(ipc->logging_data), ipc->tx_queue, ipc->global_data, data_to_send, data_to_send_size);
}

int
sendChunkedData(
    SharedMemoryIPC *ipc,
    const uint16_t *data_to_send_sizes,
    const char **data_elem_to_send,
    const uint8_t num_of_data_elem
)
{
    writeDebug(&(ipc->logging_data), TraceLevel, "Sending %u chunks of data\n", num_of_data_elem);

    return pushBuffersToQueue(
        &(ipc->logging_data),
        ipc->tx_queue,
        ipc->global_data,
        data_elem_to_send,
        data_to_send_sizes,
        num_of_data_elem
    );
}

int
receiveData(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data)
{
    int res = peekToQueue(&(ipc->logging_data), ipc->rx_queue, ipc->global_data, received_data, received_data_size);
    writeDebug(
        &(ipc->logging_data),
        TraceLevel,
        "Received data from queue. Res: %d, data size: %u\n",
        res,
        *received_data_size
    );
    return res;
}

int
popData(SharedMemoryIPC *ipc)
{
    int res = popFromQueue(&(ipc->logging_data), ipc->rx_queue, ipc->global_data);
    writeDebug(&(ipc->logging_data), TraceLevel, "Popped data from queue. Res: %d\n", res);
    return res;
}

int
isDataAvailable(SharedMemoryIPC *ipc)
{
    int res = !isQueueEmpty(ipc->rx_queue);
    writeDebug(&(ipc->logging_data), TraceLevel, "Checking if there is data pending to be read. Res: %d\n", res);
    return res;
}

int
isCorruptedShmem(SharedMemoryIPC *ipc, int is_owner)
{
    if (isCorruptedQueue(&(ipc->logging_data), ipc->rx_queue, ipc->global_data, isTowardsOwner(is_owner, 0)) ||
        isCorruptedQueue(&(ipc->logging_data), ipc->tx_queue, ipc->global_data, isTowardsOwner(is_owner, 1))
    ) {
        writeDebug(
            &(ipc->logging_data),
            WarningLevel,
            "Detected corrupted shared memory queue. Shared memory name: %s",
            ipc->shm_name
        );
        return 1;
    }

    return 0;
}
// LCOV_EXCL_STOP
