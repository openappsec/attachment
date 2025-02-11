#ifndef __NANO_ATTACHMENT_SENDER_H__
#define __NANO_ATTACHMENT_SENDER_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

///
/// @brief Sends start request data to the nano service.
///
/// This function handles the sending of starting meta data, request headers and end request to the nano service.
/// It creates a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the data to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendRequestFilter(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends start request data to the nano service.
///
/// This function handles the sending of starting meta data to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the data to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendMetadata(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends request headers to the nano service.
///
/// This function handles the sending of request headers to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the headers to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendRequestHeaders(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends response headers to the nano service.
///
/// This function handles the sending of response headers to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the headers to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendResponseHeaders(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends request body to the nano service.
///
/// This function handles the sending of request body to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the body to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendRequestBody(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends response body to the nano service.
///
/// This function handles the sending of response body to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the body to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendResponseBody(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends end request signal to the nano service.
///
/// This function handles the sending a request end signal to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the necessery data to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendRequestEnd(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends end response signal to the nano service.
///
/// This function handles the sending a response end signal to the nano service. It creates
/// a new thread to perform the sending operation, ensuring that the main execution flow
/// is not blocked. It also handles potential errors and timeouts that may occur during
/// the sending process.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param data A pointer to AttachmentData structure containing the necessery data to send and the session data.
///
/// @return An AttachmentVerdictResponse structure indicating the outcome of the operation.
///
AttachmentVerdictResponse SendResponseEnd(NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Sends metric data to the nano service and resets it on the attachment.
///
/// @param attachment A pointer to the NanoAttachment structure that contains metrics data.
///
/// @return An NanoCommunication enum indicating the outcome of the operation.
///         NANO_OK if the operation was successful, NANO_ERROR otherwise.
///
NanoCommunicationResult SendMetricData(NanoAttachment *attachment);

#endif // __NANO_ATTACHMENT_SENDER_H__
