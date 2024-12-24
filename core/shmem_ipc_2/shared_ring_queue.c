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

#include "shared_ring_queue.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "shared_ipc_debug.h"

static const uint16_t empty_buff_mgmt_magic = 0xfffe;
static const uint16_t skip_buff_mgmt_magic = 0xfffd;
static const uint32_t max_write_size = 0xfffc;
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);

// LCOV_EXCL_START Reason: Handing it to Envoy prototype development

static int
getNumOfDataSegmentsNeeded(LoggingData *logging_data, uint16_t data_size)
{
    int res = (data_size + SHARED_MEMORY_SEGMENT_ENTRY_SIZE - 1) / SHARED_MEMORY_SEGMENT_ENTRY_SIZE;
    writeDebug(
        logging_data,
        TraceLevel,
        "Checking amount of segments needed. Res: %d, data size: %u, shmem entry size: %u",
        res,
        data_size,
        SHARED_MEMORY_SEGMENT_ENTRY_SIZE
    );
    return res;
}

static int
isThereEnoughMemoryInQueue(
    LoggingData *logging_data,
    SharedRingGlobalData *global_data,
    uint16_t write_pos,
    uint16_t read_pos,
    uint8_t num_of_elem_to_push
)
{
    int res;

    writeDebug(
        logging_data,
        TraceLevel, "Checking if memory has space for new elements. "
        "Num of elements to push: %u, write index: %u, read index: %u, amount of queue segments: %u",
        num_of_elem_to_push,
        write_pos,
        read_pos,
        global_data->g_num_of_data_segments
    );
    if (num_of_elem_to_push >= global_data->g_num_of_data_segments) {
        writeDebug(
            logging_data,
            TraceLevel,
            "Amount of elements to push is larger then amount of available elements in the queue"
        );
        return 0;
    }

    // add skipped elements during write that does not fit from cur write position till end of queue
    if (write_pos + num_of_elem_to_push > global_data->g_num_of_data_segments) {
        num_of_elem_to_push += global_data->g_num_of_data_segments - write_pos;
    }

    // removing the aspect of circularity in queue and simulating as if the queue continued at its end
    if (write_pos + num_of_elem_to_push >= global_data->g_num_of_data_segments) {
        read_pos += global_data->g_num_of_data_segments;
    }

    res = write_pos + num_of_elem_to_push < read_pos || write_pos >= read_pos;
    writeDebug(logging_data, TraceLevel, "Finished checking if there is enough place in shared memory. Res: %d", res);
    return res;
}

static int
isGetPossitionSucceccful(
    SharedRingQueue *queue,
    SharedRingGlobalData *global_data,
    uint16_t *read_pos,
    uint16_t *write_pos
)
{
    if (global_data->g_num_of_data_segments == 0) return 0;

    *read_pos = queue->read_pos;
    *write_pos = queue->write_pos;

    if (queue->num_of_data_segments != global_data->g_num_of_data_segments) return 0;
    if (queue->size_of_memory != global_data->g_memory_size) return 0;
    if (*read_pos > global_data->g_num_of_data_segments) return 0;
    if (*write_pos > global_data->g_num_of_data_segments) return 0;

    return 1;
}

void
resetRingQueue(LoggingData *logging_data, SharedRingQueue *queue, uint16_t num_of_data_segments)
{
    (void)logging_data;
    uint16_t *buffer_mgmt;
    unsigned int idx;

    queue->read_pos = 0;
    queue->write_pos = 0;
    queue->num_of_data_segments = num_of_data_segments;
    buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    for (idx = 0; idx < queue->num_of_data_segments; idx++) {
        buffer_mgmt[idx] = empty_buff_mgmt_magic;
    }
}

SharedRingGlobalData *
createSharedRingGlobalData(LoggingData *logging_data)
{
    SharedRingGlobalData *global_data = (SharedRingGlobalData *)malloc(sizeof(SharedRingGlobalData));
    if (global_data == NULL) {
        writeDebug(logging_data, WarningLevel, "Failed to allocate memory for global data\n");
        return NULL;
    }

    global_data->g_rx_fd = -1;
    global_data->g_tx_fd = -1;
    global_data->g_memory_size = -1;
    global_data->g_rx_location_name[0] = '\0';
    global_data->g_tx_location_name[0] = '\0';
    global_data->g_num_of_data_segments = 0;

    return global_data;
}

SharedRingQueue *
createSharedRingQueue(
    LoggingData *logging_data,
    const char *shared_location_name,
    uint16_t num_of_data_segments,
    int is_owner,
    int is_tx,
    SharedRingGlobalData *global_data
)
{
    SharedRingQueue *queue = NULL;
    uint16_t *buffer_mgmt;
    uint16_t shmem_fd_flags = is_owner ? O_RDWR | O_CREAT : O_RDWR;
    int32_t fd = -1;
    uint32_t size_of_memory;
    unsigned int idx;

    writeDebug(logging_data, TraceLevel, "Creating a new shared ring queue");

    if (num_of_data_segments > max_num_of_data_segments) {
        writeDebug(
            logging_data,
            WarningLevel,
            "createSharedRingQueue: Cannot create data segment with %d elements (max number of elements is %u)\n",
            num_of_data_segments,
            max_num_of_data_segments
        );
        return NULL;
    }

    global_data->g_num_of_data_segments = num_of_data_segments;

    fd = shm_open(shared_location_name, shmem_fd_flags, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == -1) {
        writeDebug(
            logging_data,
            WarningLevel,
            "createSharedRingQueue: Failed to open shared memory for '%s'. Errno: %d\n",
            shared_location_name,
            errno
        );
        return NULL;
    }

    size_of_memory = sizeof(SharedRingQueue) + (num_of_data_segments * sizeof(DataSegment));
    if (is_owner && ftruncate(fd, size_of_memory + 1) != 0) {
        writeDebug(
            logging_data,
            WarningLevel,
            "createSharedRingQueue: Failed to ftruncate shared memory '%s' to size '%x'\n",
            shared_location_name,
            size_of_memory
        );
        close(fd);
        return NULL;
    }

    queue = (SharedRingQueue *)mmap(0, size_of_memory, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (queue == NULL) {
        writeDebug(
            logging_data,
            WarningLevel,
            "createSharedRingQueue: Error allocating queue for '%s' of size=%x\n",
            shared_location_name,
            size_of_memory
        );
        close(fd);
        return NULL;
    }

    if (is_owner) {
        snprintf(queue->shared_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
        queue->num_of_data_segments = num_of_data_segments;
        queue->read_pos = 0;
        queue->write_pos = 0;
        queue->size_of_memory = size_of_memory;
        buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
        for (idx = 0; idx < queue->num_of_data_segments; idx++) {
            buffer_mgmt[idx] = empty_buff_mgmt_magic;
        }
        queue->owner_fd = fd;
    } else {
        queue->user_fd = fd;
    }

    global_data->g_memory_size = size_of_memory;
    if (is_tx) {
        global_data->g_tx_fd = fd;
        snprintf(global_data->g_tx_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
    } else {
        global_data->g_rx_fd = fd;
        snprintf(global_data->g_rx_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Successfully created a new shared ring queue. "
        "Shared memory path: %s, number of segments: %u, is owner: %d, "
        "fd flags: %u, fd: %d, memory size: %u, read index: %u, write index: %u",
        shared_location_name,
        queue->num_of_data_segments,
        is_owner,
        shmem_fd_flags,
        fd,
        queue->size_of_memory,
        queue->read_pos,
        queue->write_pos
    );

    return queue;
}

void
destroySharedRingQueue(
    LoggingData *logging_data,
    SharedRingQueue *queue,
    SharedRingGlobalData *global_data,
    int is_owner,
    int is_tx
)
{
    uint32_t size_of_memory = global_data->g_memory_size;
    int32_t fd = 0;

    if(is_owner) {
        queue->owner_fd = 0;
    } else {
        queue->user_fd = 0;
    }

    if (is_tx) {
        fd = global_data->g_tx_fd;
        global_data->g_tx_fd = -1;
    } else {
        fd = global_data->g_rx_fd;
        global_data->g_rx_fd = -1;
    }

    if (munmap(queue, size_of_memory) != 0) {
        writeDebug(logging_data, WarningLevel, "destroySharedRingQueue: Failed to unmap shared ring queue\n");
    }
    if (fd > 0) close(fd);
    fd = 0;

    // shm_open cleanup
    if(is_owner) {
        shm_unlink(is_tx ? global_data->g_tx_location_name : global_data->g_rx_location_name);
    }
    writeDebug(logging_data, TraceLevel, "Successfully destroyed shared ring queue. Is owner: %d", is_owner);
}

void
dumpRingQueueShmem(LoggingData *logging_data, SharedRingQueue *queue)
{
    uint16_t segment_idx;
    uint16_t data_idx;
    uint16_t *buffer_mgmt = NULL;
    char data_byte;

    writeDebug(
        logging_data,
        WarningLevel,
        "owner_fd: %d, user_fd: %d, size_of_memory: %d, write_pos: %d, read_pos: %d, num_of_data_segments: %d\n",
        queue->owner_fd,
        queue->user_fd,
        queue->size_of_memory,
        queue->write_pos,
        queue->read_pos,
        queue->num_of_data_segments
    );

    writeDebug(logging_data, WarningLevel, "mgmt_segment:");
    buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    for (segment_idx = 0; segment_idx < queue->num_of_data_segments; segment_idx++) {
        writeDebug(logging_data, WarningLevel, "%s%u", (segment_idx == 0 ? " " : ", "), buffer_mgmt[segment_idx]);
    }

    writeDebug(logging_data, WarningLevel, "\ndata_segment: ");
    for (segment_idx = 0; segment_idx < queue->num_of_data_segments; segment_idx++) {
        writeDebug(
            logging_data,
            WarningLevel,
            "\nMgmt index: %u, value: %u,\nactual data: ",
            segment_idx,
            buffer_mgmt[segment_idx]
        );
        for (data_idx = 0; data_idx < SHARED_MEMORY_SEGMENT_ENTRY_SIZE; data_idx++) {
            data_byte = queue->data_segment[segment_idx].data[data_idx];
            writeDebug(logging_data, WarningLevel, isprint(data_byte) ? "%c" : "%02X", data_byte);
        }
    }
    writeDebug(logging_data, WarningLevel, "\nEnd of memory\n");
}

int
peekToQueue(
    LoggingData *logging_data,
    SharedRingQueue *queue,
    SharedRingGlobalData *global_data,
    const char **output_buffer,
    uint16_t *output_buffer_size
)
{
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;

    if (!isGetPossitionSucceccful(queue, global_data, &read_pos, &write_pos)) {
        writeDebug(logging_data, WarningLevel, "Corrupted shared memory - cannot peek");
        return -1;
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Reading data from queue. Read index: %u, number of queue elements: %u",
        read_pos,
        global_data->g_num_of_data_segments
    );

    if (read_pos == write_pos) {
        writeDebug(logging_data, WarningLevel, "peekToQueue: Failed to read from an empty queue\n");
        return -1;
    }

    if (read_pos >= global_data->g_num_of_data_segments) {
        writeDebug(
            logging_data,
            WarningLevel,
            "peekToQueue: Failed to read from a corrupted queue! (read_pos= %d > num_of_data_segments=%d)\n",
            read_pos,
            global_data->g_num_of_data_segments
        );
        return CORRUPTED_SHMEM_ERROR;
    }

    if (buffer_mgmt[read_pos] == skip_buff_mgmt_magic) {
        for ( ; read_pos < global_data->g_num_of_data_segments &&
                buffer_mgmt[read_pos] == skip_buff_mgmt_magic;
                ++read_pos) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
    }

    if (read_pos == global_data->g_num_of_data_segments) read_pos = 0;

    *output_buffer_size = buffer_mgmt[read_pos];
    *output_buffer = queue->data_segment[read_pos].data;

    queue->read_pos = read_pos;

    writeDebug(
        logging_data,
        TraceLevel,
        "Successfully read data from queue. Data size: %u, new Read index: %u",
        *output_buffer_size,
        queue->read_pos
    );
    return 0;
}

int
pushBuffersToQueue(
    LoggingData *logging_data,
    SharedRingQueue *queue,
    SharedRingGlobalData *global_data,
    const char **input_buffers,
    const uint16_t *input_buffers_sizes,
    const uint8_t num_of_input_buffers
)
{
    int idx;
    uint32_t large_total_elem_size = 0;
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t total_elem_size;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    uint16_t end_pos;
    uint16_t num_of_segments_to_write;
    char *current_copy_pos;

    if (!isGetPossitionSucceccful(queue, global_data, &read_pos, &write_pos)) {
        writeDebug(logging_data, WarningLevel, "Corrupted shared memory - cannot push new buffers");
        return -1;
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Writing new data to queue. write index: %u, number of queue elements: %u, number of elements to push: %u",
        write_pos,
        global_data->g_num_of_data_segments,
        num_of_input_buffers
    );

    for (idx = 0; idx < num_of_input_buffers; idx++) {
        large_total_elem_size += input_buffers_sizes[idx];

        if (large_total_elem_size > max_write_size) {
            writeDebug(
                logging_data,
                WarningLevel,
                "Requested write size %u exceeds the %u write limit",
                large_total_elem_size,
                max_write_size
            );
            return -2;
        }
    }
    total_elem_size = (uint16_t)large_total_elem_size;

    num_of_segments_to_write = getNumOfDataSegmentsNeeded(logging_data, total_elem_size);

    writeDebug(
        logging_data,
        TraceLevel,
        "Checking if there is enough space to push new data. Total new data size: %u, number of segments needed: %u",
        total_elem_size,
        num_of_segments_to_write
    );


    if (!isThereEnoughMemoryInQueue(logging_data, global_data, write_pos, read_pos, num_of_segments_to_write)) {
        writeDebug(logging_data, DebugLevel, "Cannot write to a full queue");
        return -3;
    }

    if (write_pos >= global_data->g_num_of_data_segments) {
        writeDebug(
            logging_data,
            DebugLevel,
            "Cannot write to a location outside the queue. Write index: %u, number of queue elements: %u",
            write_pos,
            global_data->g_num_of_data_segments
        );
        return -4;
    }

    if (write_pos + num_of_segments_to_write > global_data->g_num_of_data_segments) {
        for ( ; write_pos < global_data->g_num_of_data_segments; ++write_pos) {
            buffer_mgmt[write_pos] = skip_buff_mgmt_magic;
        }
        write_pos = 0;
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Setting new management data. Write index: %u, total elements in index: %u",
        write_pos,
        total_elem_size
    );

    buffer_mgmt[write_pos] = total_elem_size;
    current_copy_pos = queue->data_segment[write_pos].data;
    for (idx = 0; idx < num_of_input_buffers; idx++) {
        writeDebug(
            logging_data,
            TraceLevel,
            "Writing data to queue. Data index: %u, data size: %u, copy destination: %p",
            idx,
            input_buffers_sizes[idx],
            current_copy_pos
        );
        memcpy(current_copy_pos, input_buffers[idx], input_buffers_sizes[idx]);
        current_copy_pos += input_buffers_sizes[idx];
    }
    write_pos++;

    end_pos = write_pos + num_of_segments_to_write - 1;
    for ( ; write_pos < end_pos; ++write_pos) {
        buffer_mgmt[write_pos] = skip_buff_mgmt_magic;
    }

    if (write_pos >= global_data->g_num_of_data_segments) write_pos = 0;
    queue->write_pos = write_pos;
    writeDebug(logging_data, TraceLevel, "Successfully pushed data to queue. New write index: %u", write_pos);

    return 0;
}

int
pushToQueue(
    LoggingData *logging_data,
    SharedRingQueue *queue,
    SharedRingGlobalData *global_data,
    const char *input_buffer,
    const uint16_t input_buffer_size
)
{
    return pushBuffersToQueue(logging_data, queue, global_data, &input_buffer, &input_buffer_size, 1);
}

int
popFromQueue(LoggingData *logging_data, SharedRingQueue *queue, SharedRingGlobalData *global_data)
{
    uint16_t num_of_read_segments;
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t end_pos;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;

    if (!isGetPossitionSucceccful(queue, global_data, &read_pos, &write_pos)) {
        writeDebug(logging_data, WarningLevel, "Corrupted shared memory - cannot pop data");
        return -1;
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Removing data from queue. new data to queue. Read index: %u, number of queue elements: %u",
        read_pos,
        global_data->g_num_of_data_segments
    );

    if (read_pos == write_pos) {
        writeDebug(logging_data, TraceLevel, "Cannot pop data from empty queue");
        return -1;
    }
    num_of_read_segments = getNumOfDataSegmentsNeeded(logging_data, buffer_mgmt[read_pos]);

    if (read_pos + num_of_read_segments > global_data->g_num_of_data_segments) {
        for ( ; read_pos < global_data->g_num_of_data_segments; ++read_pos ) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
        read_pos = 0;
    }

    end_pos = read_pos + num_of_read_segments;

    for ( ; read_pos < end_pos; ++read_pos ) {
        buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
    }

    if (read_pos < global_data->g_num_of_data_segments && buffer_mgmt[read_pos] == skip_buff_mgmt_magic) {
        for ( ; read_pos < global_data->g_num_of_data_segments; ++read_pos ) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
    }

    writeDebug(
        logging_data,
        TraceLevel,
        "Size of data to remove: %u, number of queue elements to free: %u, current read index: %u, end index: %u",
        buffer_mgmt[read_pos],
        num_of_read_segments,
        read_pos,
        end_pos
    );

    if (read_pos == global_data->g_num_of_data_segments) read_pos = 0;

    queue->read_pos = read_pos;
    writeDebug(logging_data, TraceLevel, "Successfully popped data from queue. New read index: %u", read_pos);

    return 0;
}

int
isQueueEmpty(SharedRingQueue *queue)
{
    return queue->read_pos == queue->write_pos;
}

int
isCorruptedQueue(LoggingData *logging_data, SharedRingQueue *queue, SharedRingGlobalData *global_data, int is_tx)
{
    writeDebug(
        logging_data,
        TraceLevel,
        "Checking if shared ring queue is corrupted. "
        "g_num_of_data_segments = %u, queue->num_of_data_segments = %u, queue->read_pos = %u, queue->write_pos = %u, "
        "g_memory_size = %d, queue->size_of_memory = %d, "
        "queue->shared_location_name = %s, g_tx_location_name = %s, g_rx_location_name = %s, is_tx = %d",
        global_data->g_num_of_data_segments,
        queue->num_of_data_segments,
        queue->read_pos,
        queue->write_pos,
        global_data->g_memory_size,
        queue->size_of_memory,
        queue->shared_location_name,
        global_data->g_tx_location_name,
        global_data->g_rx_location_name,
        is_tx
    );

    if (global_data->g_num_of_data_segments == 0) return 0;

    if (queue->num_of_data_segments != global_data->g_num_of_data_segments) return 1;
    if (queue->size_of_memory != global_data->g_memory_size) return 1;
    if (queue->read_pos > global_data->g_num_of_data_segments) return 1;
    if (queue->write_pos > global_data->g_num_of_data_segments) return 1;
    if (strcmp(
            queue->shared_location_name,
            is_tx ? global_data->g_tx_location_name : global_data->g_rx_location_name
            ) != 0
        ) return 1;

    return 0;
}
// LCOV_EXCL_STOP
