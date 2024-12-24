#ifndef __NANO_ATTACHMENT_H__
#define __NANO_ATTACHMENT_H__

#include "nano_attachment_common.h"
#include "nano_initializer.h"

///
/// @brief Initializes a NanoAttachment structure.
///
/// This function initializes a NanoAttachment structure with the specified parameters and default values.
///
/// @param attachment_type The type of attachment to initialize.
/// @param worker_id The ID of the worker associated with the attachment.
/// @param num_of_workers The total number of workers.
/// @param logging_fd The file descriptor for logging.
///
/// @return A pointer to the initialized NanoAttachment structure if the function completes, NULL otherwise.
///
NanoAttachment * InitNanoAttachment(uint8_t attachment_type, int worker_id, int num_of_workers, int logging_fd);

///
/// @brief Cleans up resources associated with a NanoAttachment structure and deallocates memory.
///
/// This function performs cleanup operations on a NanoAttachment structure and deallocates
/// the memory associated with it.
/// The function closes the logging file descriptor associated with the NanoAttachment
/// and frees the memory allocated for the structure.
///
/// @param attachment A pointer to the NanoAttachment structure to be cleaned up.
///
void FiniNanoAttachment(NanoAttachment *attachment);

///
/// @brief Restarts the configuration of a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment whose configuration is to be restarted.
///
/// @return A NanoCommunicationResult indicating the success or failure of the operation.

NanoCommunicationResult RestartAttachmentConfiguration(NanoAttachment *attachment);

///
/// @brief Initializes a HttpSessionData structure with default values.
///
/// This function dynamically allocates memory for a HttpSessionData structure
/// and initializes its fields with default values.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the session.
/// @param session_id The ID of the session to be initialized.
///
/// @return A pointer to the initialized HttpSessionData structure if the function completes, NULL otherwise.
///
HttpSessionData * InitSessionData(NanoAttachment *attachment, SessionID session_id);

///
/// @brief Cleans up and deallocates resources associated with a HttpSessionData structure.
///
/// This function performs cleanup operations on a HttpSessionData structure and deallocates
/// the memory associated with it. It writes a debug message indicating the session ID being
/// freed, and then frees the memory allocated for the HttpSessionData structure.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the session.
/// @param session_data A pointer to the HttpSessionData structure to be cleaned up.
///
void FiniSessionData(NanoAttachment *attachment, HttpSessionData *session_data);

///
/// @brief Updates a metric associated with a NanoAttachment.
///
/// This function updates a metric associated with a NanoAttachment structure
/// based on the provided metric type and value. It delegates the actual updating
/// of the metric to the helper function updateMetricField.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the metric.
/// @param metric The type of metric to be updated.
/// @param value The value to be incorporated into the metric calculation.
///
void UpdateMetric(NanoAttachment *attachment, AttachmentMetricType metric, uint64_t value);

///
/// @brief Sends metric data that been accumulated in the attachment to the service.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the metric.
///
void SendAccumulatedMetricData(NanoAttachment *attachment);

///
/// @brief Processes and sends attachment data to the appropriate handlers.
///
/// This function processes the attachment data based on its chunk type and sends
/// it to the appropriate handler functions. If the chunk type is not recognized,
/// it sets a default verdict of ATTACHMENT_VERDICT_INSPECT and returns an AttachmentVerdictResponse
/// structure containing the default verdict and the session ID from the provided AttachmentData.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the data.
/// @param data A pointer to the AttachmentData structure containing the data to be processed.
///
/// @return An AttachmentVerdictResponse structure containing the verdict and session ID.
///
AttachmentVerdictResponse SendDataNanoAttachment(NanoAttachment *attachment, AttachmentData *data);

AttachmentVerdictResponse SendDataNanoAttachmentWrapper(NanoAttachment *attachment, AttachmentData data);

///
/// @brief Sends a keep-alive signal using a socket connection.
///
/// @param attachment A pointer to a NanoAttachment struct containing attachment information.
///
void SendKeepAlive(NanoAttachment *attachment);

///
/// @brief Checks if a session is finalized based on the session's verdict.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
///
/// @return Returns 0 if the session is not finalized, 1 otherwise.
///
int IsSessionFinalized(NanoAttachment *attachment, HttpSessionData *session_data);

///
/// @brief Checks if the response contains modifications.
///
/// This function determines whether the provided response contains modifications.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment.
/// @param session_data A pointer to a HttpSessionData structure containing session data.
/// @param response A pointer to an AttachmentVerdictResponse structure representing the response.
///
/// @return 1 if the response contains modifications, 0 otherwise.
///
int IsResponseWithModification(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

///
/// @brief Retrieves response modifications from the given attachment and session data.
///
/// @param attachment Pointer to a NanoAttachment object.
/// @param session_data Pointer to HttpSessionData object containing session information.
/// @param response Pointer to an AttachmentVerdictResponse object.
///
/// @return NanoResponseModifications structure containing response modifications.
///
NanoResponseModifications GetResponseModifications(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

///
/// @brief Retrieves the type of web response associated with the given attachment and session data.
///
/// This function checks if the provided response object contains valid web response data.
/// If the response object is null, it logs a warning and returns NO_WEB_RESPONSE.
/// Otherwise, it returns the type of web response contained in the response object.
///
/// @param attachment    Pointer to the NanoAttachment structure associated with the request.
/// @param session_data  Pointer to the HttpSessionData structure containing session-related data.
/// @param response      Pointer to the AttachmentVerdictResponse structure containing response data.
///
/// @return The type of web response, or NO_WEB_RESPONSE if no response object is provided.
///
NanoWebResponseType GetWebResponseType(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

///
/// @brief Retrieves the block page data for a response.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param response The AttachmentVerdictResponse object containing the verdict.
///
/// @return
///
BlockPageData GetBlockPage(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

///
/// @brief Retrieves the redict page data for a response.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param response The AttachmentVerdictResponse object containing the verdict.
///
/// @return
///
RedirectPageData GetRedirectPage(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

///
/// @brief Free allocated resources of an AttachmentVerdictResponse.
///
/// This function frees the allocated resources of an AttachmentVerdictResponse.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param response The AttachmentVerdictResponse object to be freed.
///
void FreeAttachmentResponseContent(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
);

#endif // __NANO_ATTACHMENT_H__
