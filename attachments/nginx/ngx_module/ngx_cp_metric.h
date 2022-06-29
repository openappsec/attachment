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

/// @file ngx_cp_metric.h
#ifndef __NGX_CP_METRIC_H__
#define __NGX_CP_METRIC_H__

#include <nginx_attachment_common.h>
#include <ngx_config.h>
#include <ngx_core.h>

///
/// @brief Depending on the metric type, set the provided value in the metric.
/// @param[in] metric_type Metric type to update.
/// @param[in] value Value to set.
///
void updateMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value);

///
/// @brief Goes over all the metrics and resets them to 0.
///
void reset_metric_data();

#endif // __NGX_CP_METRIC_H__
