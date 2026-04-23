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

/// @file ngx_cp_failing_state.c
#include "ngx_cp_failing_state.h"

#include "ngx_cp_utils.h"
#include "ngx_cp_initializer.h"
#include "ngx_cp_metric.h"

#define FIVE_ERRORS_PER_FIFTEEN_SECONDS 0

///
/// @struct failure_state
/// @brief Holds failure state data.
///
typedef struct failure_state {
    ngx_uint_t    max_allowed_failed_requests; ///< Maximum allowed failed requests.
    ngx_uint_t    failing_interval_boundry; ///< Intervals between each failure.
    ngx_uint_t    transparent_period_sec; ///< Transperancy mode period.
} failure_state;

///
/// @struct ngx_http_cp_periodic_failure
/// @brief Holds NGINX periodic failure data.
///
typedef struct ngx_http_cp_periodic_failure {
    ngx_uint_t     max_allowed_failed_requests; ///< Maximum allowed failed requests.
    ngx_uint_t     current_failed_requests; ///< Current failed requests.
    ngx_flag_t     is_transparent_mode_active; ///< Transparent mode flag.
    ngx_uint_t     transparent_interval_boundry; ///< Transparent internval boundary.
    struct timeval transparent_interval; ///< Transparent time interval.
    struct timeval failing_interval; ///<  Falling data time interval.
} ngx_http_cp_periodic_failure;

/// Failure state session monitors.
static const failure_state failed_sessions_monitor[] = {{5, 20, 60}, {5, 20, 300}, {5, 20, 600}};
static const ngx_uint_t failed_sessions_monitor_length = 3;

static ngx_http_cp_periodic_failure current_periodic_failure = {
    .max_allowed_failed_requests = 0,
    .current_failed_requests = 0,
    .is_transparent_mode_active = 0,
    .transparent_interval_boundry = 0,
    .transparent_interval = {0, 0},
    .failing_interval = {0, 0}
};

static ngx_uint_t current_fail_state = FIVE_ERRORS_PER_FIFTEEN_SECONDS;
static ngx_flag_t should_update_timeout = 0;

///
/// @brief Resetting current failure state.
///
static void
reset_failure_state()
{
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Resetting failing interval to default. Interval: %u seconds",
        failed_sessions_monitor[current_fail_state].failing_interval_boundry
    );

    current_periodic_failure.max_allowed_failed_requests =
        failed_sessions_monitor[current_fail_state].max_allowed_failed_requests;

    current_periodic_failure.failing_interval =
        get_timeout_val_sec(failed_sessions_monitor[current_fail_state].failing_interval_boundry);
}

ngx_int_t
is_in_transparent_mode()
{
    static int transparent_mode_is_active = 0;
    if (current_periodic_failure.is_transparent_mode_active && !is_timeout_reached(&current_periodic_failure.transparent_interval)) {
        if (!transparent_mode_is_active) {
            write_dbg(
                DBG_LEVEL_INFO,
                "NGINX is in transparent mode. Transparent timeout: %u seconds",
                current_periodic_failure.transparent_interval_boundry
            );

            updateMetricField(TOTAL_TRANSPARENTS_TIME, (uint64_t)current_periodic_failure.transparent_interval_boundry);
        }

        transparent_mode_is_active = 1;
        return 1;
    }
    transparent_mode_is_active = 0;

    current_periodic_failure.is_transparent_mode_active = 0;
    current_periodic_failure.current_failed_requests = 0;
    reset_failure_state();

    return 0;
}

void
reset_transparent_mode()
{
    current_fail_state = 0;
    should_update_timeout = 0;
    memset(&current_periodic_failure, 0, sizeof(current_periodic_failure));

    current_periodic_failure.max_allowed_failed_requests = failed_sessions_monitor[current_fail_state].max_allowed_failed_requests;
    current_periodic_failure.current_failed_requests = 0;
    current_periodic_failure.is_transparent_mode_active = 0;
    current_periodic_failure.transparent_interval_boundry = failed_sessions_monitor[current_fail_state].transparent_period_sec;
    current_periodic_failure.failing_interval = get_timeout_val_sec(failed_sessions_monitor[current_fail_state].failing_interval_boundry);
}

///
/// @brief Activate transparent mode.
///
static void
activate_transparent_mode()
{
    write_dbg(
        DBG_LEVEL_WARNING,
        "Activating transparency mode. Transparency period: %u seconds",
        failed_sessions_monitor[current_fail_state].transparent_period_sec
    );
    current_periodic_failure.is_transparent_mode_active = 1;
    current_periodic_failure.transparent_interval = get_timeout_val_sec(failed_sessions_monitor[current_fail_state].transparent_period_sec);
    current_periodic_failure.transparent_interval_boundry = failed_sessions_monitor[current_fail_state].transparent_period_sec;
}

///
/// @brief Reports the provided session's metric.
/// @param[in, out] state Session's data to report the time metric of.
///
void
ngx_http_cp_report_time_metrics(ngx_http_cp_session_data *state)
{
    struct timespec session_end_time;
    clock_gettime(CLOCK_REALTIME, &session_end_time);

    double begin_usec = (state->session_start_time.tv_sec * 1000000) + (state->session_start_time.tv_nsec / 1000);
    double end_usec = (session_end_time.tv_sec * 1000000) + (session_end_time.tv_nsec / 1000);
    double overall_process_time = end_usec - begin_usec;

    updateMetricField(AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT, overall_process_time);
    updateMetricField(MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT, overall_process_time);
    updateMetricField(MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT, overall_process_time);

    updateMetricField(AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT, state->req_proccesing_time);
    updateMetricField(MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT, state->req_proccesing_time);
    updateMetricField(MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT, state->req_proccesing_time);

    updateMetricField(AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT, state->res_proccesing_time);
    updateMetricField(MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT, state->res_proccesing_time);
    updateMetricField(MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT, state->res_proccesing_time);
}

void
handle_inspection_failure(int weight, ngx_int_t fail_mode_verdict, ngx_http_cp_session_data *state)
{
    if (state->verdict != TRAFFIC_VERDICT_INSPECT) {
        // Skipping already inspected data.
        write_dbg(DBG_LEVEL_TRACE, "Skipping already inspected data");
        return;
    }

    ngx_http_cp_report_time_metrics(state);

    if (fail_mode_verdict == NGX_OK) {
        // Increase open fail counter.
        updateMetricField(INSPECTION_OPEN_FAILURES_COUNT, 1);
        state->verdict = TRAFFIC_VERDICT_ACCEPT;
    } else {
        // Increase close fail counter.
        updateMetricField(INSPECTION_CLOSE_FAILURES_COUNT, 1);
        state->verdict = TRAFFIC_VERDICT_DROP;
    }

    current_periodic_failure.current_failed_requests += weight;

    if (is_timeout_reached(&current_periodic_failure.failing_interval)) {
        // Enough time had passed without errors. Limits can be reset
        reset_failure_state();
        return;
    }

    if (current_periodic_failure.current_failed_requests <= current_periodic_failure.max_allowed_failed_requests) {
        write_dbg(
            DBG_LEVEL_TRACE,
            "Failure count did not reach maximum allowed limit. Current failure count: %u, Max failure limit: %u",
            current_periodic_failure.current_failed_requests,
            current_periodic_failure.max_allowed_failed_requests
        );

        return;
    }

    activate_transparent_mode();

    if (current_fail_state < failed_sessions_monitor_length) {
        // Setting new transparent interval.
        current_fail_state++;

        write_dbg(
            DBG_LEVEL_DEBUG,
            "Setting new transparent interval. New interval: %u seconds",
            failed_sessions_monitor[current_fail_state].transparent_period_sec
        );
    } else {
        // Reached impossible fail state, setting highest level of state.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Reached impossible fail state - Setting highest level instead. Current fail state: %u, New fail state: %u",
            current_fail_state,
            failed_sessions_monitor_length - 1
        );
        current_fail_state = failed_sessions_monitor_length - 1;
    }
}

void
handle_inspection_success(ngx_http_cp_session_data *state)
{
    updateMetricField(INSPECTION_SUCCESSES_COUNT, 1);
    ngx_http_cp_report_time_metrics(state);
    if (!is_timeout_reached(&current_periodic_failure.failing_interval)) return;
    if (current_periodic_failure.current_failed_requests != 0 || should_update_timeout == 1) return;

    current_fail_state = 0;
}
