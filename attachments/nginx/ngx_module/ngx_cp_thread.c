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

/// @file ngx_cp_thread.c
#include "ngx_cp_thread.h"
#include "ngx_cp_utils.h"
#include "ngx_cp_hook_threads.h"
#include "ngx_cp_failing_state.h"
#include "ngx_cp_hooks.h"
#include "ngx_cp_metric.h"

#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>

static int success_count = 0;
///
/// @brief runs the provided routine with the arguments in a non thread and without a timeout.
/// @param[in, out] thread_func A pointer to the provided routine to run in a thread.
/// @param[in, out] arg Routine's arguments.
/// @param[in, out] func_name Called thread timeout.
/// @returns 1
///
int
ngx_cp_run_without_thread_timeout(CpThreadRoutine thread_func, void *arg, char *func_name)
{
    write_dbg(DBG_LEVEL_TRACE, "Executing cb in blocking mode, fn=%s", func_name);

    thread_func(arg);

    return 1;
}

int
ngx_cp_run_in_thread_timeout(CpThreadRoutine thread_func, void *arg, int timeout_msecs, char *func_name)
{
    int status = 0;
    int ret = 0;
    void *res = NULL;
    pthread_t thread;
    struct timespec ts;
    struct ngx_http_cp_event_thread_ctx_t *ctx = (struct ngx_http_cp_event_thread_ctx_t *)arg;

    if (inspection_mode == NO_THREAD) return ngx_cp_run_without_thread_timeout(thread_func, arg, func_name);

    /// Runs the routine in a dedicated thread.
    write_dbg(DBG_LEVEL_TRACE, "Executing cb in dedicated thread, fn=%s", func_name);
    if (pthread_create(&thread, NULL, thread_func, arg) != 0) {
        updateMetricField(THREAD_FAILURE, 1);
        write_dbg(DBG_LEVEL_TRACE, "pthread_create failed with errno=%d, fn=%s", errno, func_name);
        return 0;
    }

    if (inspection_mode == BLOCKING_THREAD) {
        // Runs the function in a blocking thread.
        status = pthread_join(thread, &res);
        write_dbg(DBG_LEVEL_TRACE, "pthread_join returned from blocking call. status=%d, fn=%s", status, func_name);
        return status == 0;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        updateMetricField(THREAD_FAILURE, 1);
        write_dbg(
            DBG_LEVEL_ERROR,
            "clock_gettime(CLOCK_REALTIME) failed. Status: %s",
            strerror(errno)
        );
        return 0;
    }

    // Convert milliseconds to timespec
    long long tv_nsec = ts.tv_nsec + (timeout_msecs % 1000) * 1000000;

    ts.tv_sec += timeout_msecs / 1000 + tv_nsec / 1000000000;
    ts.tv_nsec = tv_nsec % 1000000000;

    status = pthread_timedjoin_np(thread, NULL, &ts);

    if (status != 0) {
        /// Handling failed thread.
        handle_inspection_failure(inspection_failure_weight, fail_mode_verdict, ctx->session_data_p);
        write_dbg(
            status == ETIMEDOUT ? DBG_LEVEL_DEBUG : DBG_LEVEL_WARNING,
            "pthread_timejoin_np returns with %d (%s), successes so far %d, fn=%s",
            status,
            strerror(status),
            success_count,
            func_name
        );

        ret = pthread_cancel(thread);
        write_dbg(DBG_LEVEL_DEBUG, "pthread_cancel returns with ret=%d, fn=%s", ret, func_name);

        ret = pthread_join(thread, &res);
        if (ret != 0) {
            updateMetricField(THREAD_FAILURE, 1);
            write_dbg(DBG_LEVEL_WARNING, "pthread_join failed while fail open is enabled. RET=%d, fn=%s", ret, func_name);
            return ret != 0;
        }

        if (res == PTHREAD_CANCELED) {
            updateMetricField(THREAD_TIMEOUT, 1);
            write_dbg(DBG_LEVEL_DEBUG, "thread was canceled, fn=%s", func_name);
        } else {
            updateMetricField(THREAD_FAILURE, 1);
        }

        write_dbg(DBG_LEVEL_DEBUG, "pthread_join returns with ret=%d", ret);
    }
    else {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Successfully executed thread. successes so far=%d, fn=%s",
            success_count,
            func_name
        );
        success_count++;
    }

    return status == 0;
}
