/// @file nano_configuration.h
#ifndef __NANO_CONFIGURATION_H__
#define __NANO_CONFIGURATION_H__

#include <sys/time.h>
#include <assert.h>

#include "nano_attachment_common.h"
#include "nano_initializer.h"

///
/// @brief Initializes the general configuration for a NanoAttachment object.
///
/// This function initializes the general configuration for the specified NanoAttachment object
/// using the configuration file located at the specified path. It updates various configuration
/// parameters such as debug level, fail-open/fail-close mode, session limits, timeouts, and others
/// based on the configuration file.
///
/// @param attachment A pointer to the NanoAttachment object to initialize the configuration for.
/// @param conf_path The path to the configuration file.
/// @return A NanoCommunicationResult indicating the result of the operation.
///
NanoCommunicationResult init_attachment_config(NanoAttachment *attachment, const char *conf_path);

///
/// @brief Resets the configuration of a NanoAttachment object.
///
/// This function resets the configuration of the specified NanoAttachment object by
/// marking it as not updated, incrementing the current configuration version, and
/// reinitializing the general configuration using the specified configuration path.
///
/// @param attachment A pointer to the NanoAttachment object to reset the configuration for.
/// @return A NanoCommunicationResult indicating the result of the operation.
///
NanoCommunicationResult reset_attachment_config(NanoAttachment *attachment);

#endif // __NANO_CONFIGURATION_H__
