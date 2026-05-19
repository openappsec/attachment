#ifndef __NANO_ATTACHMENT_SENDER_ASYNC_H__
#define __NANO_ATTACHMENT_SENDER_ASYNC_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

///
/// @brief Sends request start data to the nano service.
///
/// This async function sends metadata to start a request interaction with the nano service.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
/// @param metadata A pointer to HttpMetaData structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendMetadataAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpMetaData *metadata
);

///
/// @brief Sends request headers to the nano service.
///
/// This async function sends request headers to the nano service. It updates the session data
/// and handles any errors that occur during the header sending process.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
/// @param headers A pointer to HttpHeaders structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendRequestHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpHeaders *headers
);

///
/// @brief Sends request body to the nano service.
///
/// This async function sends request body to the nano service. It updates the session data
/// and handles any errors that occur during the body sending process.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
/// @param bodies A pointer to NanoHttpBody structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendRequestBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
);

///
/// @brief Sends request end data to the nano service.
///
/// This async function sends signal to the nano service that the request has ended
/// and with it the whole session transaction.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendRequestEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
);

///
/// @brief Async function to send request filters.
///
/// This async function sends metadata, request headers and end request
/// to the nano service. It updates the session data and handles any errors
/// that occur during the header sending process.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
/// @param start_data A pointer to HttpRequestFilterData structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendRequestFilterAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpRequestFilterData *start_data
);

///
/// @brief Send data metric to the service.
///
/// This async function sends data metric to the service and resets it.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendMetricToServiceAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
);

///
/// @brief Sends delayed verdict request to the nano service.
///
/// This async function sends a delayed verdict request to the nano service.
/// It is used when a verdict has been delayed and needs to be requested again.
///
/// @param attachment A pointer to a NanoAttachment structure.
/// @param session_data_p A pointer to HttpSessionData structure.
///
/// @return #NANO_OK on success.
///
NanoCommunicationResult SendDelayedVerdictRequestAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
);

#endif // __NANO_ATTACHMENT_SENDER_ASYNC_H__
