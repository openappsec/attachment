#include "nano_attachment_metric.h"

#include "nano_initializer.h"
#include "nano_attachment_common.h"

void
reset_metric_data(NanoAttachment *attachment)
{
    int i;
    for (i = 0 ; i < METRIC_TYPES_COUNT ; i++) {
        attachment->metric_data[i] = 0;
        attachment->metric_average_data_divisor[i] = 0;
    }
}

static void
updateCounterMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
{
    attachment->metric_data[metric_type] += value;
}

static void
updateAverageMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
{
    attachment->metric_data[metric_type] =
        (((attachment->metric_data[metric_type] * attachment->metric_average_data_divisor[metric_type]) + value) /
        (attachment->metric_average_data_divisor[metric_type] + 1));
    attachment->metric_average_data_divisor[metric_type] += 1;
}

static void
updateMaxMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
{
    if (attachment->metric_data[metric_type] < value) attachment->metric_data[metric_type] = value;
}

static void
updateMinMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
{
    if (attachment->metric_data[metric_type] == 0) {
        attachment->metric_data[metric_type] = value;
    } else if (attachment->metric_data[metric_type] > value) {
        attachment->metric_data[metric_type] = value;
    }
}

void
updateMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
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
            if (value != 0) updateAverageMetricField(attachment, metric_type, value);
            break;
        }
        case MAX_VM_MEMORY_USAGE:
        case MAX_RSS_MEMORY_USAGE:
        case MAX_REQ_BODY_SIZE_UPON_TIMEOUT:
        case MAX_RES_BODY_SIZE_UPON_TIMEOUT:
        case MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
        case MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
        case MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
            if (value != 0) updateMaxMetricField(attachment, metric_type, value);
            break;
        }
        case MIN_REQ_BODY_SIZE_UPON_TIMEOUT:
        case MIN_RES_BODY_SIZE_UPON_TIMEOUT:
        case MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
        case MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
        case MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
            if (value != 0) updateMinMetricField(attachment, metric_type, value);
            break;
        }
        default:
            updateCounterMetricField(attachment, metric_type, value);
    }
}
