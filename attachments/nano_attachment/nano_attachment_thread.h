#ifndef __NANO_ATTACHMENT_THREAD_H__
#define __NANO_ATTACHMENT_THREAD_H__

#include <stdbool.h>

#include "nano_initializer.h"

typedef void *(*CpThreadRoutine)(void *); ///< Func

typedef enum TransactionType
{
    START,
    REQUEST,
    RESPONSE,
    METRICS,
    REGISTRATION
} TransactionType;

///
/// @brief Runs a function in a thread with a timeout.
///
/// This function runs the specified thread function in a dedicated thread with a timeout.
/// If the function does not complete within the specified timeout, it is cancelled.
///
/// @param[in] attachment The NanoAttachment object.
/// @param[in] data The AttachmentData object.
/// @param[in] thread_func The function to run in the thread.
/// @param[in] arg The argument to pass to the thread function.
/// @param[in] timeout_msecs The timeout value in milliseconds.
/// @param[in] func_name The name of the function for debugging purposes.
/// @param[in] transaction_type The type of transaction (request or response), used for timeout.
///
/// @return Returns 1 if the function completes within the timeout, 0 otherwise.
///
int
NanoRunInThreadTimeout(
    NanoAttachment *attachment,
    AttachmentData *data,
    CpThreadRoutine thread_func,
    void *arg,
    int timeout_msecs,
    char *func_name,
    TransactionType transaction_type
);

#endif // __NANO_ATTACHMENT_THREAD_H__
