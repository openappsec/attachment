#ifndef __NANO_ATTACHMENT_IO_H__
#define __NANO_ATTACHMENT_IO_H__

#include <unistd.h>

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "nano_attachment_sender_thread.h"
#include "shmem_ipc_2.h"

/// @brief Sends session data chunk to a nano service for inspection.
///
/// This function sends the provided data fragments to the nano service for inspection.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment to the nano service.
/// @param fragments An array of pointers to character arrays representing the data fragments to send.
/// @param fragments_sizes An array of uint16_t values representing the sizes of the data fragments.
/// @param num_of_data_elem An 8-bit integer representing the number of data elements (fragments) to send.
/// @param cur_session_id An unsigned 32-bit integer representing the current session ID.
/// @param chunk_type An enumeration representing the type of data chunk being sent.
///
/// @return NANO_OK if the data is sent successfully, NANO_ERROR otherwise.
///
NanoCommunicationResult
send_session_data_to_service(
    NanoAttachment *attachment,
    char **fragments,
    const uint16_t *fragments_sizes,
    uint8_t num_of_data_elem,
    uint32_t cur_session_id,
    AttachmentDataType chunk_type
);

///
/// @brief Connect to the communication socket.
///
/// This function creates a new socket and connects it to the verdict
/// Unix domain socket address. If the attachment already has a communication
/// socket open, it is closed before creating a new one.
///
/// @param[in] attachment The NanoAttachment struct containing socket information.
/// @returns A NanoCommunicationResult indicating the success of the operation.
///
NanoCommunicationResult connect_to_comm_socket(NanoAttachment *attachment);

///
/// @brief Create an unix socket and connect to the attachment registration service.
/// @param[in] attachment Points to initiated NanoAttachment struct.
/// @returns NanoCommunicationResult
///         - #NANO_OK
///         - #NANO_ERROR
///
NanoCommunicationResult connect_to_registration_socket(NanoAttachment *attachment);

/// @brief Receives and processes replies from a nano service regarding traffic inspection verdicts.
///
/// This function waits for replies from the service and handles each reply based on the verdict received.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment to the nano service.
/// @param session_data A pointer to a HttpSessionData which holds the session data.
/// @param web_response_data A pointer to a WebResponseData structure representing the response data.
/// @param modification_list A pointer to a pointer to a NanoHttpModificationList structure
///        representing a list of HTTP modifications.
///
/// @return NANO_OK if the function completes successfully
///         NANO_ERROR if an error occurs during processing
///         NANO_HTTP_FORBIDDEN if a drop verdict is received.
///
NanoCommunicationResult
service_reply_receiver(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    WebResponseData **web_response_data,
    NanoHttpModificationList **modification_list,
    AttachmentDataType chunk_type
);

///
/// @brief Sends request start metadata for inspection to the nano service.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param metadata Pointer to the HttpMetaData struct containing the HTTP metadata.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the HTTP event context.
/// @param cur_request_id The current request ID.
/// @param num_of_messages_sent Pointer to an unsigned int to store the number of messages sent.
/// @param is_verdict_requested Boolean value indicating if a verdict is requested.
///
void
nano_metadata_sender(
    NanoAttachment *attachment,
    HttpMetaData *metadata,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_of_messages_sent,
    bool is_verdict_requested
);

///
/// @brief Sends a response code for inspection.
///
/// This function sends a response code for inspection to a service.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param response_code The response code to send.
/// @param ctx The HttpEventThreadCtx context.
/// @param cur_request_id The current request ID.
/// @param num_messages_sent A pointer to the number of messages sent.
///
void
nano_send_response_code(
    NanoAttachment *attachment,
    uint16_t response_code,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
);

///
/// @brief Sends the content length to the intaker.
///
/// This function sends the content length to the intaker for processing.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param content_length The content length to send.
/// @param ctx The HttpEventThreadCtx context.
/// @param cur_request_id The current request ID.
/// @param num_messages_sent A pointer to the number of messages sent.
///
void
nano_send_response_content_length(
    NanoAttachment *attachment,
    uint64_t content_length,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
);

///
/// @brief Sends HTTP headers for inspection using a NanoAttachment.
///
/// This function takes a NanoAttachment pointer, an HttpHeaders struct containing the headers to send,
/// the type of the headers (request or response), the current request ID, and a pointer to store
/// the number of messages sent.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param headers Pointer to the HttpHeaders struct containing the headers to send.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the context of the current thread.
/// @param header_type Type of the headers (REQUEST_HEADER or RESPONSE_HEADER).
/// @param cur_request_id Current request ID.
/// @param num_messages_sent Pointer to an unsigned int to store the number of messages sent.
///
void
nano_header_sender(
    NanoAttachment *attachment,
    HttpHeaders *headers,
    HttpEventThreadCtx *ctx,
    AttachmentDataType header_type,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent,
    bool is_verdict_requested
);

///
/// @brief Sends the body of a request or response for inspection to a nano service.
///
/// This function iterates over the body chunks, creates fragments, and sends them
/// in bulk to the service. It also handles the final chunk and updates the number
/// of messages sent.
///
/// @param attachment Pointer to a NanoAttachment struct representing the attachment/module.
/// @param bodies Pointer to an HttpBody struct containing the HTTP request/response body data.
/// @param ctx Pointer to an HttpEventThreadCtx struct representing the HTTP event thread context.
/// @param body_type Enum value indicating whether the body is a request or response body.
/// @param cur_request_id Current request ID for logging and tracking purposes.
/// @param num_messages_sent Pointer to an unsigned int to track the number of messages sent.
///
void
nano_body_sender(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpEventThreadCtx *ctx,
    AttachmentDataType body_type,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
);

///
/// @brief Sends an end transaction event to a service for inspection.
///
/// @param attachment The NanoAttachment struct representing the attachment/module.
/// @param end_transaction_type The type of end transaction event (REQUEST_END or RESPONSE_END).
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the context of the current thread.
/// @param cur_request_id The ID of the current request.
/// @param num_messages_sent Pointer to an unsigned integer to store the number of messages sent.
/// @return NANO_OK if the end transaction event was sent successfully, NANO_ERROR otherwise.
///
void
nano_end_transaction_sender(
    NanoAttachment *attachment,
    AttachmentDataType end_transaction_type,
    HttpEventThreadCtx *ctx,
    SessionID cur_request_id,
    unsigned int *num_messages_sent
);

///
/// @brief Sends delayed transaction event to a service for inspection.
///
/// @param attachment The NanoAttachment struct representing the attachment/module.
/// @param ctx Pointer to the HttpEventThreadCtx struct containing the context of the current thread.
/// @param cur_request_id The ID of the current request.
/// @param num_messages_sent Pointer to an unsigned integer to store the number of messages sent.
///
void
nano_request_delayed_verdict(
    NanoAttachment *attachment,
    HttpEventThreadCtx *ctx,
    SessionID cur_request_id,
    unsigned int *num_messages_sent
);

///
/// @brief Sends attachment's metric data to the service.
///
/// @param attachment The NanoAttachment struct representing the attachment/module, which contains the metric data.
///
void
nano_send_metric_data_sender(NanoAttachment *attachment);

#endif // __NANO_ATTACHMENT_IO_H__
