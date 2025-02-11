#ifndef __NANO_ATTACHMENT_METRIC_H__
#define __NANO_ATTACHMENT_METRIC_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

///
/// @brief Updates a specified metric field of the NanoAttachment structure.
///
/// This function updates the value of a specified metric field within the NanoAttachment structure.
/// It selects the appropriate update strategy (counter, average, maximum, or minimum) based on the type
/// of the metric provided. For average, maximum, and minimum metrics, the function updates the metric value
/// only if the provided value is non-zero. For counter metrics, the value is always incremented.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param metric_type The type of the metric to be updated. This determines the update strategy used.
/// @param value The value to update the metric with. For average, maximum, and minimum metrics,
///              this value must be non-zero to be considered.
///
void updateMetricField(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value);

///
/// @brief Resets all metric data fields of the NanoAttachment structure.
///
/// This function resets the metric data and the average data divisor fields within the NanoAttachment structure
/// to zero. It is typically used to initialize or clear the metric data before starting a new measurement session
/// or after completing an existing session.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
void reset_metric_data(NanoAttachment *attachment);

#endif // __NANO_ATTACHMENT_METRIC_H__
