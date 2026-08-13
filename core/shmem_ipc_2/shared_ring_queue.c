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
#include <stddef.h>

#include "shared_ipc_debug.h"

#define AGENT_METADATA_FILE_PATH "/dev/shm/agent-metadata"

static const uint16_t empty_buff_mgmt_magic = 0xfffe;
static const uint16_t skip_buff_mgmt_magic = 0xfffd;
static const uint32_t max_write_size = 0xfffc;
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);

static uint16_t g_effective_segment_size = 0;
static int g_effective_size_initialized = 0;

static int
isLargerDataSegmentSupported()
{
    struct stat st;
    FILE *file;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    char *effective_size_str;

    effective_size_str = getenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    if (effective_size_str != NULL) {
        return (atoi(effective_size_str) > SHARED_MEMORY_SEGMENT_ENTRY_SIZE_BC) ? 1 : 0;
    }

    if (stat(AGENT_METADATA_FILE_PATH, &st) != 0) {
        return 0;
    }

    file = fopen(AGENT_METADATA_FILE_PATH, "r");
    if (file == NULL) {
        return 0;
    }

    while ((read_len = getline(&line, &len, file)) != -1) {
        if (read_len > 0 && line[read_len - 1] == '\n') {
            line[read_len - 1] = '\0';
        }
        char *eq_pos = strchr(line, '=');
        if (eq_pos != NULL) {
            *eq_pos = '\0';
            char *key = line;
            char *value = eq_pos + 1;
            if (strlen(key) > 0 && strlen(value) > 0) {
                setenv(key, value, 1);
            }
        }
    }
    free(line);
    fclose(file);

    effective_size_str = getenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    if (effective_size_str != NULL) {
        return (atoi(effective_size_str) > SHARED_MEMORY_SEGMENT_ENTRY_SIZE_BC) ? 1 : 0;
    }

    return 0;
}

static uint16_t
getEffectiveSegmentSize()
{
    if (!g_effective_size_initialized) {
        g_effective_size_initialized = 1;
        g_effective_segment_size = isLargerDataSegmentSupported() ? sizeof(DataSegment) : sizeof(DataSegmentBC);
    }
    return g_effective_segment_size;
}

// Fixed header prefix shared by every released SharedRingQueue layout (fields before mgmt_segment).
#define SHARED_RING_QUEUE_HEADER_PREFIX_SIZE (offsetof(SharedRingQueue, mgmt_segment))

static uint16_t
deriveSegmentSizeFromExistingQueue(LoggingData *logging_data, int fd, const char *shared_location_name)
{
    struct stat st;
    SharedRingQueue header;
    uint32_t payload_size;
    uint32_t divisor;
    uint32_t derived_size;

    if (fstat(fd, &st) != 0) return 0;
    if ((size_t)st.st_size < SHARED_RING_QUEUE_HEADER_PREFIX_SIZE) return 0;

    if (pread(fd, &header, SHARED_RING_QUEUE_HEADER_PREFIX_SIZE, 0) !=
        (ssize_t)SHARED_RING_QUEUE_HEADER_PREFIX_SIZE)
    {
        return 0;
    }

    if (header.num_of_data_segments == 0 || header.num_of_data_segments > max_num_of_data_segments) return 0;
    if (header.size_of_memory <= (int32_t)SHARED_RING_QUEUE_HEADER_PREFIX_SIZE) return 0;

    // The owner stamped: size_of_memory = header prefix + (num_of_data_segments + 1) * segment size
    // (the extra segment is the management segment). Accept the derived size only if it reconstructs
    // the stamped memory size exactly and is one of the two sizes ever released.
    payload_size = header.size_of_memory - SHARED_RING_QUEUE_HEADER_PREFIX_SIZE;
    divisor = (uint32_t)header.num_of_data_segments + 1;
    derived_size = payload_size / divisor;
    if (derived_size * divisor != payload_size) return 0;
    if (derived_size != SHARED_MEMORY_SEGMENT_ENTRY_SIZE && derived_size != SHARED_MEMORY_SEGMENT_ENTRY_SIZE_BC) {
        return 0;
    }

    writeDebug(
        logging_data,
        DebugLevel,
        "Derived segment size %u from existing shared memory queue '%s' (memory size: %d, data segments: %u)",
        derived_size,
        shared_location_name,
        header.size_of_memory,
        header.num_of_data_segments
    );
    return (uint16_t)derived_size;
}

static uint32_t
getEffectiveSharedRingQueueSize()
{
    return (sizeof(SharedRingQueue) - sizeof(DataSegment)) + getEffectiveSegmentSize();
}

static char *
getDataSegmentAddress(SharedRingQueue *queue, uint16_t segment_idx)
{
    uint16_t effective_segment_size = getEffectiveSegmentSize();
    if (effective_segment_size == SHARED_MEMORY_SEGMENT_ENTRY_SIZE) {
        return queue->data_segment[segment_idx].data;
    }
    char *queue_data_start = (char*)queue + sizeof(SharedRingQueue) - sizeof(DataSegment) + effective_segment_size;
    return queue_data_start + (segment_idx * effective_segment_size);
}

// LCOV_EXCL_START Reason: Handing it to Envoy prototype development

static int
getNumOfDataSegmentsNeeded(LoggingData *logging_data, uint16_t data_size)
{
    uint16_t effective_entry_size = getEffectiveSegmentSize();
    int res = (data_size + effective_entry_size - 1) / effective_entry_size;
    writeDebug(
        logging_data,
        TraceLevel,
        "Checking amount of segments needed. Res: %d, data size: %u, shmem entry size: %u",
        res,
        data_size,
        effective_entry_size
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

    g_effective_size_initialized = 0;
    g_effective_segment_size = 0;

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

    // Backward compatibility with mixed agent/attachment versions: when attaching to a queue
    // the owner already created, the geometry stamped in its header is authoritative - metadata
    // files and environment variables only describe intent and can disagree with what the owner
    // actually built (which ends in an isCorruptedQueue fail-open loop).
    if (!is_owner) {
        uint16_t negotiated_size = getEffectiveSegmentSize();
        uint16_t adopted_size = deriveSegmentSizeFromExistingQueue(logging_data, fd, shared_location_name);
        if (adopted_size != 0 && adopted_size != negotiated_size) {
            writeDebug(
                logging_data,
                WarningLevel,
                "Adopting segment size %u from existing shared memory queue '%s' (negotiated size was %u)",
                adopted_size,
                shared_location_name,
                negotiated_size
            );
            g_effective_segment_size = adopted_size;
            g_effective_size_initialized = 1;
        }
    }

    uint16_t effective_seg_size = getEffectiveSegmentSize();
    uint32_t effective_queue_size = getEffectiveSharedRingQueueSize();
    size_of_memory = effective_queue_size + (num_of_data_segments * effective_seg_size);
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
        for (data_idx = 0; data_idx < getEffectiveSegmentSize(); data_idx++) {
            data_byte = getDataSegmentAddress(queue, segment_idx)[data_idx];
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
    *output_buffer = getDataSegmentAddress(queue, read_pos);

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
    current_copy_pos = getDataSegmentAddress(queue, write_pos);
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
