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

/// @file nano_utils.c
#include "nano_utils.h"

#include "nano_attachment_common.h"

#include <time.h>
#include <stdarg.h>
#include <math.h>
#include <unistd.h>
#include <stdio.h>


///
/// @brief Gets the current time using a fast, coarse-grained clock.
///
/// This function uses CLOCK_MONOTONIC_COARSE to retrieve the current time,
/// which provides a fast timestamp. The function returns
/// the current time as a struct timeval, which represents seconds and microseconds.
///
/// @return struct timeval The current time as seconds and microseconds.
///
static struct timeval
getCurrTimeFast()
{
    struct timeval curr_time;
    struct timespec curr_time_mono;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_time_mono);

    curr_time.tv_sec = curr_time_mono.tv_sec;
    curr_time.tv_usec = curr_time_mono.tv_nsec/1000.0;
    return curr_time;
}

void
write_dbg_impl(
    const LoggingData *logging_data,
    uint32_t session_id,
    int _dbg_level,
    const char *func,
    const char *file,
    int line_num,
    const char *fmt,
    ...
)
{
    if (logging_data == NULL) return;

    if (_dbg_level < logging_data->dbg_level) return;

    char debug_str[2048] = {0};
    char session_id_str[32] = {0};
    char unique_id[32] = "uniqueId";
    va_list args;
    time_t ttime;
    int millisec;
    struct timeval tv;
    char time_stamp[64];
    char str_uid[140];
    int pid = 0;

    time(&ttime);
    tv = getCurrTimeFast();
    millisec = lrint(tv.tv_usec/1000.0);
    if (millisec>=1000) {
        // Allow for rounding up to nearest second
        millisec -=1000;
        tv.tv_sec++;
    }
    strftime(time_stamp, sizeof(time_stamp), "%FT%T", localtime(&ttime));

    if (!pid) pid = getpid();

    if (session_id > 0) {
        snprintf(session_id_str, sizeof(session_id_str) - 1, "<session id %d> ", session_id);
    }

    // Prints the debug given all the data and a formatter.
    snprintf(
        str_uid,
        sizeof(str_uid) - 1,
        "|%s.%03d: %s@%s:%d [uid %s | pid %d] %s| ",
        time_stamp,
        millisec,
        func,
        file,
        line_num,
        unique_id,
        pid,
        session_id_str
    );

    va_start(args, fmt);
    vsnprintf(debug_str, sizeof(debug_str) - 1, fmt, args);

    va_end(args);
    dprintf(logging_data->fd, "%s%s\n", str_uid, debug_str);
}

struct timeval
get_absolute_timeout_val_sec(const int delta_time_in_sec)
{
    struct timeval time;

    time = getCurrTimeFast();
    time.tv_sec += delta_time_in_sec;
    return time;
}

int
is_absolute_timeout_reached(struct timeval *timeout)
{
    struct timeval curr_time;

    curr_time = getCurrTimeFast();
    return (timercmp(timeout, &curr_time, <));
}
