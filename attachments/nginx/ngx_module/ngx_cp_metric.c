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

/// @file ngx_cp_metric.c
#include <ngx_config.h>

#include "ngx_cp_metric.h"
#include "ngx_cp_utils.h"

uint64_t metric_data[METRIC_TYPES_COUNT];
uint64_t metric_average_data_divisor[METRIC_TYPES_COUNT];

void
reset_metric_data()
{
    int i;
    for (i = 0 ; i < METRIC_TYPES_COUNT ; i++) {
        metric_data[i] = 0;
        metric_average_data_divisor[i] = 0;
    }
}

///
/// @brief Increment the provided metric type by the value.
/// @param[in] metric_type Metric type.
/// @param[in] value Value to increment the metric type.
///
static void
updateCounterMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value)
{
    metric_data[metric_type] += value;
}

///
/// @brief Update the average metric field.
/// @param[in] metric_type Metric type.
/// @param[in] value Value to add to the average metric.
///
static void
updateAverageMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value)
{
    metric_data[metric_type] =
        (((metric_data[metric_type] * metric_average_data_divisor[metric_type]) + value) / (metric_average_data_divisor[metric_type] + 1));
    metric_average_data_divisor[metric_type] += 1;
}

///
/// @brief Sets the value as metric if it is higher than the current metric's value.
/// @param[in] metric_type Metric type to set the value in.
/// @param[in] value Value to set.
///
static void
updateMaxMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value)
{
    if (metric_data[metric_type] < value) metric_data[metric_type] = value;
}

///
/// @brief Sets the value as metric if it is lower than the current metric's value.
/// @param[in] metric_type Metric type to set the value in.
/// @param[in] value Value to set.
///
static void
updateMinMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value)
{
    if (metric_data[metric_type] == 0) {
        metric_data[metric_type] = value;
    } else if (metric_data[metric_type] > value) {
        metric_data[metric_type] = value;
    }
}

void
updateMetricField(ngx_http_plugin_metric_type_e metric_type, uint64_t value)
{
    switch (metric_type) {
        case CPU_USAGE:
        case AVERAGE_VM_MEMORY_USAGE:
        case AVERAGE_RSS_MEMORY_USAGE:
        case AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT:
        case AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT:
        case AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
        case AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
        case AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
            if (value != 0) updateAverageMetricField(metric_type, value);
            break;
        }
        case MAX_VM_MEMORY_USAGE:
        case MAX_RSS_MEMORY_USAGE:
        case MAX_REQ_BODY_SIZE_UPON_TIMEOUT:
        case MAX_RES_BODY_SIZE_UPON_TIMEOUT:
        case MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
        case MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
        case MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
            if (value != 0) updateMaxMetricField(metric_type, value);
            break;
        }
        case MIN_REQ_BODY_SIZE_UPON_TIMEOUT:
        case MIN_RES_BODY_SIZE_UPON_TIMEOUT:
        case MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
        case MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
        case MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
            if (value != 0) updateMinMetricField(metric_type, value);
            break;
        }
        default:
            updateCounterMetricField(metric_type, value);
    }
}

