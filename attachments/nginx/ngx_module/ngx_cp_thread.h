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

/// @file ngx_cp_thread.h
#ifndef __NGX_CP_THREAD_H__
#define __NGX_CP_THREAD_H__

#include <stdbool.h>

typedef void *(*CpThreadRoutine)(void *); ///< Func

///
/// @brief Runs the provided routine with the provided arguments as a thread
/// @details Runs the provided routine as thread_func(args) in a thread. Depending on the inspection
/// mode runs it with a timeout.
/// This provided routine updates metrics if needed such as THREAD_TIMEOUT and THREAD_FAILURE.
/// @param[in, out] thread_func A pointer to the provided routine to run in a thread.
/// @param[in, out] arg Routine's arguments.
/// @param[in, out] timeout_msecs Called thread timeout.
/// @param[in, out] func_name The name of the provided routine.
/// @return int
///     - #0 Thread success.
///     - #1 Thread fail.
///
int ngx_cp_run_in_thread_timeout(CpThreadRoutine thread_func, void *arg, int timeout_msecs, char *);

#endif // __NGX_CP_THREAD_H__
