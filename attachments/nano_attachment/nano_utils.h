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

/// @file nano_utils.h
#ifndef __NANO_UTILS_H__
#define __NANO_UTILS_H__

#include <sys/time.h>
#include <assert.h>

#include "nano_initializer.h"

typedef struct LoggingData {
    int dbg_level;
    int worker_id;
    int fd;
} LoggingData;

#ifndef __FILENAME__
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define write_dbg(attachment, session_id, _dbg_level, fmt, ...) \
    {                                                           \
        write_dbg_impl(                                         \
            attachment->logging_data,                           \
            session_id,                                         \
            _dbg_level,                                         \
            __func__,                                           \
            __FILENAME__,                                       \
            __LINE__,                                           \
            fmt,                                                \
            ##__VA_ARGS__                                       \
        );                                                      \
        if ((_dbg_level) == DBG_LEVEL_ASSERT) assert(0);        \
    }

///
/// @brief Writing into debug implementation.
/// @param[in] LoggingData Logging data.
/// @param[in] session_id Session ID.
/// @param[in] _dbg_level Debug level to write into.
/// @param[in] func Function name from which the write debug was called from.
/// @param[in] file File from which the debug function was called from.
/// @param[in] line_num Line number of the write debug was called on.
/// @param[in] fmt Debug formatter.
/// @param[in] ... Extra values to write into the debug using the formatter.
///
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
);

///
/// @brief Get delta current time + delta_time_in_sec value in seconds.
/// @param[in] delta_time_in_sec Delta time to return
/// @returns timeval struct with tv_sec value of += delta_time_in_sec.
///
struct timeval get_absolute_timeout_val_sec(const int delta_time_in_sec);

///
/// @brief Check if a timeout has been reached.
///
/// This function compares the specified timeout value with the current time
/// to determine if the timeout has been reached.
///
/// @param[in] timeout A pointer to a struct timeval representing the timeout value.
/// @return 1 if the timeout has been reached, 0 otherwise.
///
int is_absolute_timeout_reached(struct timeval *timeout);

#endif // __NANO_UTILS_H__
