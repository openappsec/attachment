#ifndef __NANO_ATTACHMENT_SENDER_THREAD_H__
#define __NANO_ATTACHMENT_SENDER_THREAD_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

/// @struct HttpEventThreadCtx
/// @brief Holds all the information needed to communicate with the attachment service.
typedef struct HttpEventThreadCtx
{
    NanoAttachment *attachment; ///< NanoAttachment.
    AttachmentData  *data; ///< Attachment data.
    HttpSessionData *session_data_p; ///< Provided session data.

    /// Connection results with the attachment service
    /// - #NANO_OK
    /// - #NANO_ERROR
    NanoCommunicationResult res;

    WebResponseData *web_response_data; ///< Web response data.
    NanoHttpModificationList *modifications; ///< Context's modification.
} HttpEventThreadCtx;

///
/// @brief Initializes a thread context structure for an NANO event thread.
///
/// This function initializes a thread context structure with the provided data
/// and default values for other fields.
///
/// @param ctx A pointer to a struct HttpEventThreadCtx structure representing the thread context to initialize.
/// @param attachment A pointer to a NanoAttachment structure representing the attachment data for the thread.
/// @param data A pointer to an AttachmentData structure representing the attachment data for the thread.
///
void
init_thread_ctx(HttpEventThreadCtx *ctx, NanoAttachment *attachment, AttachmentData *data);

///
/// @brief Connect attachment communication socket to the nano service.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * RegistrationCommSocketThread(void *_ctx);

///
/// @brief Connect attachment to registration socket to the nano service.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * RegistrationSocketThread(void *_ctx);

///
/// @brief Sends request start data to the nano service.
///
/// This thread function sends metadata to start a request interaction with the nano service.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendMetadataThread(void *_ctx);

///
/// @brief Sends request headers to the nano service.
///
/// This thread function sends request headers to the nano service using the provided
/// HttpEventThreadCtx context. It updates the session data and handles any
/// errors that occur during the header sending process.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendRequestHeadersThread(void *_ctx);

///
/// @brief Sends response headers to the nano service.
///
/// This thread function sends response headers to the nano service using the provided
/// HttpEventThreadCtx context. It updates the session data and handles any
/// errors that occur during the header sending process.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendResponseHeadersThread(void *_ctx);

///
/// @brief Sends request body to the nano service.
///
/// This thread function sends request body to the nano service using the provided
/// HttpEventThreadCtx context. It updates the session data and handles any
/// errors that occur during the body sending process.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendRequestBodyThread(void *_ctx);

///
/// @brief Sends response body to the nano service.
///
/// This thread function sends response body to the nano service using the provided
/// HttpEventThreadCtx context. It updates the session data and handles any
/// errors that occur during the body sending process.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendResponseBodyThread(void *_ctx);

///
/// @brief Sends request end data to the nano service.
///
/// This thread function sends signal to the nano service that the response has ended
/// and with it the whole session transaction.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendRequestEndThread(void *_ctx);

///
/// @brief Sends response end data to the nano service.
///
/// This thread function sends signal to the nano service that the response has ended
/// and with it the whole session transaction.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendResponseEndThread(void *_ctx);


///
/// @brief Thread function to send request filters.
///
/// This thread function sends metadata, request headers and end request
/// to the nano service using the provided HttpEventThreadCtx context.
/// It updates the session data and handles any errors that occur during the header sending process.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL
///
void * SendRequestFilterThread(void *_ctx);

///
/// @brief Send query for requesting delayed data verdict.
///
/// This thread function sends a delayed data query to the service and waits for the response.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendDelayedVerdictRequestThread(void *_ctx);

///
/// @brief Send data metric fo the service.
///
/// This thread function sends data metric to the service and resets it.
///
/// @param _ctx A pointer to the HttpEventThreadCtx context.
///
/// @return NULL.
///
void * SendMetricToServiceThread(void *_data);

#endif // __NANO_ATTACHMENT_SENDER_THREAD_H__
