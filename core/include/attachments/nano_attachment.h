#ifndef __NANO_ATTACHMENT_H__
#define __NANO_ATTACHMENT_H__

#include "nano_attachment_common.h"

typedef struct NanoAttachment NanoAttachment;

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
/// @brief Retrieves the communication socket from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The communication socket file descriptor, or -1 if attachment is NULL.
///
int GetCommSocket(NanoAttachment *attachment);

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

///
/// @brief Sends attachment data asynchronously to the appropriate handlers.
///
/// This function processes the attachment data based on its chunk type and sends
/// it to the appropriate async handler functions.
///
/// @param attachment A pointer to the NanoAttachment structure associated with the data.
/// @param data A pointer to the AttachmentData structure containing the data to be processed.
///
/// @return A NanoCommunicationResult indicating the success or failure of the operation.
///
NanoCommunicationResult SendDataNanoAttachmentAsync(NanoAttachment *attachment, AttachmentData *data);

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
/// @brief Retrieves the response code for a response.
///
/// @param response The AttachmentVerdictResponse object containing the verdict.
///
/// @return
///
uint16_t GetResponseCode(
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

///
/// @brief Compresses NanoHttpBody and return allocated compressed body.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param bodies The bodies pointer to be compressed.
///
NanoHttpBody * compressBody(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    NanoHttpBody *bodies
);

///
/// @brief Compresses NanoHttpBody and return allocated compressed body.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param bodies The bodies pointer to be decompressed.
///
NanoHttpBody * decompressBody(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    NanoHttpBody *bodies
);

///
/// @brief Free allocated compressed body.
///
/// This function frees the allocated resources of NanoHttpBody object.
///
/// @param attachment The NanoAttachment object associated with the session.
/// @param session_data The HttpSessionData object representing the session.
/// @param bodies The bodies pointer to be freed.
///
void
freeCompressedBody(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    NanoHttpBody *bodies
);

///
/// @brief Checks if the failed session ID queue is empty.
///
/// This function checks whether the queue containing failed session IDs
/// associated with the NanoAttachment is empty.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return Returns true if the failed session ID queue is empty, false otherwise.
///
bool
IsFailedSessionIDQueueEmpty(NanoAttachment *attachment);

///
/// @brief Pops a session ID from the failed session ID queue.
///
/// This function removes and returns a session ID from the queue of failed
/// session IDs associated with the NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The session ID that was popped from the failed session ID queue.
///
SessionID
PopFailedSessionID(NanoAttachment *attachment);

///
/// @brief Checks if the queue is empty.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return Returns true if the queue is empty, false otherwise.
///
bool isNanoQueueEmpty(NanoAttachment *attachment);

///
/// @brief Pops a session ID from the queue and updates the table.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The session ID that was popped from the queue.
///
SessionID PopFromNanoQueue(NanoAttachment *attachment);

///
/// @brief Retrieves a verdict response for a given session ID from the table.
///
/// @param attachment A pointer to the NanoAttachment structure.
/// @param session_id The session ID to look up.
///
/// @return An AttachmentVerdictResponse structure containing the verdict for the session.
///
AttachmentVerdictResponse getAttachmentVerdictResponse(NanoAttachment *attachment, SessionID session_id);

///
/// @brief Retrieves the shared verdict signal path from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return A pointer to the shared verdict signal path string, or NULL if attachment is NULL.
///
const char * GetSharedVerdictSignalPath(NanoAttachment *attachment);

///
/// @brief Retrieves the worker ID from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The worker ID, or 0 if attachment is NULL.
///
uint8_t GetWorkerId(NanoAttachment *attachment);

///
/// @brief Retrieves the attachment type from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The attachment type, or 0 if attachment is NULL.
///
uint8_t GetAttachmentType(NanoAttachment *attachment);

///
/// @brief Retrieves the fail mode verdict from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The fail mode verdict, or NANO_OK if attachment is NULL.
///
int GetFailModeVerdict(NanoAttachment *attachment);

///
/// @brief Retrieves the fail mode delayed verdict from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The fail mode delayed verdict, or NANO_OK if attachment is NULL.
///
int GetFailModeDelayedVerdict(NanoAttachment *attachment);

///
/// @brief Retrieves the number of connection attempts from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The number of connection attempts, or 0 if attachment is NULL.
///
int GetNumOfConnectionAttempts(NanoAttachment *attachment);

///
/// @brief Retrieves the fail open timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The fail open timeout in milliseconds, or 50 if attachment is NULL.
///
unsigned int GetFailOpenTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the fail open delayed timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The fail open delayed timeout in milliseconds, or 150 if attachment is NULL.
///
unsigned int GetFailOpenDelayedTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the sessions per minute limit verdict from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The sessions per minute limit verdict, or ATTACHMENT_VERDICT_ACCEPT if attachment is NULL.
///
AttachmentVerdict GetSessionsPerMinuteLimitVerdict(NanoAttachment *attachment);

///
/// @brief Retrieves the maximum sessions per minute from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The maximum sessions per minute, or 0 if attachment is NULL.
///
unsigned int GetMaxSessionsPerMinute(NanoAttachment *attachment);

///
/// @brief Retrieves the request maximum processing timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The request maximum processing timeout in milliseconds, or 3000 if attachment is NULL.
///
uint32_t GetRequestProcessingTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the response maximum processing timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The response maximum processing timeout in milliseconds, or 3000 if attachment is NULL.
///
uint32_t GetResponseProcessingTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the registration thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The registration thread timeout in milliseconds, or 100 if attachment is NULL.
///
unsigned int GetRegistrationThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the request start thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The request start thread timeout in milliseconds, or 100 if attachment is NULL.
///
unsigned int GetReqStartThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the request header thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The request header thread timeout in milliseconds, or 100 if attachment is NULL.
///
unsigned int GetReqHeaderThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the request body thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The request body thread timeout in milliseconds, or 150 if attachment is NULL.
///
unsigned int GetReqBodyThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the response header thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The response header thread timeout in milliseconds, or 100 if attachment is NULL.
///
unsigned int GetResHeaderThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the response body thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The response body thread timeout in milliseconds, or 150 if attachment is NULL.
///
unsigned int GetResBodyThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the waiting for verdict thread timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The waiting for verdict thread timeout in milliseconds, or 150 if attachment is NULL.
///
unsigned int GetWaitingForVerdictThreadTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the hold verdict retries from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The number of hold verdict retries, or 10 if attachment is NULL.
///
unsigned int GetHoldVerdictRetries(NanoAttachment *attachment);

///
/// @brief Retrieves the hold verdict polling time from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The hold verdict polling time in milliseconds, or 1 if attachment is NULL.
///
unsigned int GetHoldVerdictPollingTime(NanoAttachment *attachment);

///
/// @brief Retrieves the metric timeout from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The metric timeout in milliseconds, or 100 if attachment is NULL.
///
unsigned int GetMetricTimeout(NanoAttachment *attachment);

///
/// @brief Retrieves the number of nano IPC elements from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The number of nano IPC elements, or 200 if attachment is NULL.
///
unsigned int GetNumOfNanoIpcElements(NanoAttachment *attachment);

///
/// @brief Retrieves the keep alive interval from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The keep alive interval in milliseconds, or 0 if attachment is NULL.
///
uint64_t GetKeepAliveInterval(NanoAttachment *attachment);

///
/// @brief Retrieves the async mode enabled flag from a NanoAttachment.
///
/// @param attachment A pointer to the NanoAttachment structure.
///
/// @return The async mode enabled flag, or 0 if attachment is NULL.
///
unsigned int GetIsAsyncModeEnabled(NanoAttachment *attachment);

#endif // __NANO_ATTACHMENT_H__
