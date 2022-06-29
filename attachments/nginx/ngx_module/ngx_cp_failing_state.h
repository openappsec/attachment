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

/// @file ngx_cp_failing_state.h
#ifndef __NGX_CP_FAILING_STATE_H__
#define __NGX_CP_FAILING_STATE_H__

#include <ngx_config.h>
#include <ngx_core.h>

#include "nginx_attachment_common.h"
#include "ngx_cp_hooks.h"

///
/// @brief Returns if transparent mode is activated.
/// @returns ngx_int_t
///      - #0 if transparent mode is off.
///      - #1 if transparent mode is on.
///
ngx_int_t is_in_transparent_mode(void);

///
/// @brief Handles inspection failure.
/// @details Updates metric fields with the provided data.
/// Metric fields included such as:
///      - #INSPECTION_OPEN_FAILURES_COUNT
///      - #INSPECTION_CLOSE_FAILURES_COUNT
/// @param[in, out] weight Failure's weight.
/// @param[in, out] fail_mode_verdict Fail mode verdict.
/// @param[in, out] state NGINX session data.
///
void handle_inspection_failure(int weight, ngx_int_t fail_mode_verdict, ngx_http_cp_session_data *state);

///
/// @brief Handles inspection success.
/// @details The function updates "INSPECTION_SUCCESSES_COUNT" metric.
/// Furthermore the function updates time verdicts metrics.
/// @param[in, out] state NGINX session data.
///
void handle_inspection_success(ngx_http_cp_session_data *state);

///
/// @brief Resets transparent mode.
/// @details Reset transparent mode to 0, and all the related parameters.
///
void reset_transparent_mode(void);

#endif // __NGX_CP_FAILING_STATE_H__
