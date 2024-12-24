#include "nano_attachment_io.h"

#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "nano_attachment_common.h"
#include "nano_utils.h"
#include "nano_attachment_metric.h"
#include "nano_attachment_util.h"
#include "nano_configuration.h"

#define MAX_HEADER_BULK_SIZE 10
#define RESPONSE_CODE_COUNT 3
#define CONTENT_LENGTH_COUNT 3
#define HEADER_DATA_COUNT 4
#define BODY_DATA_COUNT 5
#define END_TRANSACTION_DATA_COUNT 2
#define DELAYED_VERDICT_DATA_COUNT 2

/// @brief Sends a signal to the nano service to notify about new session data to inspect.
///
/// This function sends a signal to the nano service to notify it about new session data
/// that needs to be inspected.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment to the nano service.
/// @param cur_session_id An unsigned 32-bit integer representing the current session ID.
///
/// @return NANO_OK if the signal is sent successfully
///         NANO_ERROR if there is an error
///         NANO_TIMEOUT if a timeout occurs.
///
static NanoCommunicationResult
notify_signal_to_service(NanoAttachment *attachment, uint32_t cur_session_id)
{
    int res = 0;
    unsigned int bytes_written = 0;
    struct timeval absolute_timeout = get_absolute_timeout_val_sec(1);
    int failopen_enabled = (attachment->inspection_mode == NON_BLOCKING_THREAD);
    struct pollfd s_poll;

    write_dbg(
        attachment,
        cur_session_id,
        DBG_LEVEL_TRACE,
        "Sending signal to the service to notify about new session data to inspect"
    );

    s_poll.fd = attachment->comm_socket;
    s_poll.events = POLLOUT;
    res = poll(&s_poll, 1, 0);
    if (res > 0 && s_poll.revents & POLLHUP) {
        write_dbg(
            attachment,
            cur_session_id,
            DBG_LEVEL_DEBUG,
            "Polling communication socket failed"
        );
        return NANO_ERROR;
    }

    while (bytes_written < sizeof(cur_session_id)) {
        if (failopen_enabled && is_absolute_timeout_reached(&absolute_timeout)) {
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Reached timeout during attempt to signal nano service"
            );
            return NANO_TIMEOUT;
        }

        res = write(
            attachment->comm_socket,
            ((char *)&cur_session_id) + bytes_written,
            sizeof(cur_session_id) - bytes_written
        );

        if (res < 0) {
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to signal nano service, trying to restart communications"
            );
            return NANO_ERROR;
        }

        bytes_written += res;
    }

    return NANO_OK;
}

///
/// @brief Signals the service fora possible session data waiting for inspection on
///        on the shared mememory (IPC).
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment to the nano service.
/// @param cur_session_id An unsigned 32-bit integer representing the current session ID.
/// @param chunk_type An enumeration representing the type of HTTP chunk being sent.
///
/// @return NANO_OK if the ack response is received and matches the current session ID,
///         NANO_ERROR if there is an error in signaling or reading the response,
///         NANO_AGAIN if the response indicates an old session ID and polling should be retried,
///         NANO_TIMEOUT if a timeout occurs while waiting for the response.
///
static NanoCommunicationResult
signal_for_session_data(NanoAttachment *attachment, uint32_t cur_session_id, AttachmentDataType chunk_type)
{
    struct pollfd s_poll;
    NanoCommunicationResult res = NANO_OK;
    uint32_t reply_from_service;
    int timeout = attachment->fail_open_timeout;
    int retry;

    if (chunk_type == REQUEST_DELAYED_VERDICT) {
        timeout = attachment->fail_open_delayed_timeout;
    }
    if (attachment->inspection_mode != NON_BLOCKING_THREAD) {
        timeout = -1;
    }

    res = notify_signal_to_service(attachment, cur_session_id);
    if (res != NANO_OK) return res;

    write_dbg(
        attachment,
        cur_session_id,
        DBG_LEVEL_TRACE,
        "Successfully signaled to the service! pending to receive ack"
    );

    for (retry = 0; retry < 3; retry++) {
        s_poll.fd = attachment->comm_socket;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        res = poll(&s_poll, 1, timeout);
        if (res < 0) {
            // Polling from the nano service has failed.
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_TRACE,
                "Polling from nano service had fail, failure: %d",
                res);
            return NANO_ERROR;
        }

        if (res == 0) {
            write_dbg(attachment, cur_session_id, DBG_LEVEL_TRACE, "Polling from nano service reached timeout");
            continue;
        }

        res = read(attachment->comm_socket, ((char *)&reply_from_service), sizeof(reply_from_service));
        if (res <= 0) {
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to read ack from nano service"
            );
            return NANO_ERROR;
        }

        if (reply_from_service == cur_session_id) {
            // Read was successful and matches the current session Id.
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_TRACE,
                "Received signal from nano service to the current session. Current session id: %d",
                cur_session_id
            );
            return NANO_OK;
        } else if (reply_from_service == CORRUPTED_SESSION_ID) {
            // Recieved corrupted session ID, returning error.
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Received signal from nano service regarding a corrupted session. Current session id: %d",
                cur_session_id
            );
            return NANO_ERROR;
        } else {
            // Recieved old session Id, attempting to poll again.
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_DEBUG,
                "Received signal from nano service regarding a previous session."
                " Current session id: %d, Signaled session id: %d",
                cur_session_id,
                reply_from_service
            );
            return NANO_AGAIN;
        }
    }
    write_dbg(attachment, cur_session_id, DBG_LEVEL_WARNING, "Reached timeout during attempt to signal nano service");
    return NANO_TIMEOUT;
}

/// @brief Receives verdict data from the nano service.
///
/// This function attempts to receive verdict data from the nano service IPC channel.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment to the nano service.
/// @param session_id An unsigned 32-bit integer representing the current session ID.
///
/// @return A pointer to a HttpReplyFromService structure representing the received verdict data,
///         or NULL if the data could not be received after multiple attempts.
///
static HttpReplyFromService *
receive_data_from_service(NanoAttachment *attachment, uint32_t session_id)
{
    int res, retry;
    const char *reply_data;
    uint16_t reply_size;

    write_dbg(attachment, session_id, DBG_LEVEL_TRACE, "Receiving verdict data from nano service");

    for (retry = 0; retry < 5; retry++) {
        if (!isDataAvailable(attachment->nano_service_ipc)) {
            write_dbg(
                attachment,
                session_id,
                DBG_LEVEL_TRACE,
                "Service data is not available - trying again (retry = %d) in 1 u-seconds",
                retry
            );
            usleep(1);
            continue;
        }
        res = receiveData(attachment->nano_service_ipc, &reply_size, &reply_data);
        if (res < 0 || reply_data == NULL) {
            write_dbg(
                attachment,
                session_id,
                DBG_LEVEL_TRACE,
                "Failed to receive verdict data - trying again (retry = %d) in 1 u-seconds",
                retry
            );

            usleep(1);
            continue;
        }
        return (HttpReplyFromService *)reply_data;
    }
    return NULL;
}

NanoCommunicationResult
send_session_data_to_service(
    NanoAttachment *attachment,
    char **fragments,
    const uint16_t *fragments_sizes,
    uint8_t num_of_data_elem,
    uint32_t cur_session_id,
    AttachmentDataType chunk_type
)
{
    int attempt_num;
    NanoCommunicationResult res = NANO_OK;
    int err_code = 0;
    write_dbg(
        attachment,
        cur_session_id,
        DBG_LEVEL_TRACE,
        "Sending session data chunk for inspection"
    );

    for (attempt_num = 1; attempt_num <= 5; attempt_num++) {
        err_code = sendChunkedData(
            attachment->nano_service_ipc,
            fragments_sizes,
            (const char **)fragments,
            num_of_data_elem
        );

        write_dbg(
            attachment,
            cur_session_id,
            DBG_LEVEL_DEBUG,
            "Res code is %d, err code is %d",
            res,
            err_code
        );

        if (res == NANO_OK && err_code == 0) {
            return NANO_OK;
        }

        if (err_code != 0) {
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_DEBUG,
                "Failed to send data for inspection - attempt number %d",
                attempt_num
            );
        }

        // Notify the nano service to inspect new session data.
        // This notification is triggered when chunked data transmission fails.
        res = signal_for_session_data(attachment, cur_session_id, chunk_type);

        if (res == NANO_ERROR) {
            disconnect_communication(attachment);
            res = restart_communication(attachment);
            if (res == NANO_ERROR) return res;
        }
    }

    switch(err_code)
    {
        case -1:
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to send data for inspection - Corrupted shared memory"
            );
            break;
        case -2:
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to send data for inspection - Requested write size exceeds the write limit"
            );
            break;
        case -3:
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to send data for inspection - Cannot write to a full queue"
            );
            break;
        case -4:
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to send data for inspection - Attempted write to a location outside the queue"
            );
            break;
        default:
            write_dbg(
                attachment,
                cur_session_id,
                DBG_LEVEL_WARNING,
                "Failed to send data for inspection - Unknown error code %d",
                err_code
            );
            break;
    }
    return NANO_ERROR;
}

///
/// @brief Allocates memory for a modification buffer and copies the given data into it.
///
/// This function allocates memory for a modification buffer of size (data_size + 1)
/// bytes, copies the provided data into the buffer, and assigns the pointer to
/// the allocated memory to the 'target' parameter.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment.
/// @param session_id The ID of the session.
/// @param target A pointer to a pointer that will hold the address of the allocated memory.
///               Upon successful allocation, this pointer will be updated to point to the
///               allocated memory.
/// @param data_size The size of the data to be copied into the modification buffer.
/// @param data A pointer to the data to be copied into the modification buffer.
///
/// @return NANO_OK if the memory allocation and copying are successful, NANO_ERROR otherwise.
///
static NanoCommunicationResult
create_modification_buffer(
    NanoAttachment *attachment,
    SessionID session_id,
    char **target,
    uint16_t data_size,
    char *data
)
{
    *target = malloc(data_size + 1);
    if (*target == NULL) {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_WARNING,
            "Failed to allocate modification buffer of size: %d",
            data_size
        );
        return NANO_ERROR;
    }

    snprintf(*target, data_size + 1, "%s", data);
    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Successfully created modification buffer, size: %d",
        data_size
    );

    return NANO_OK;
}

///
/// @brief Creates a new Modification List node.
///
/// This function allocates memory for a new NanoHttpModificationList node,
/// initializes its fields with the provided modification data, and returns
/// a pointer to the created node.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment.
/// @param session_id The ID of the session.
/// @param modification A pointer to a HttpInjectData structure containing the modification data.
///
/// @return A pointer to the newly created NanoHttpModificationList node if successful,
///         or NULL if memory allocation fails or if an error occurs during the creation process.
///
static NanoHttpModificationList *
create_modification_node(NanoAttachment *attachment, SessionID session_id, HttpInjectData *modification)
{
    NanoCommunicationResult res;
    NanoHttpModificationList *modification_node = malloc(sizeof(NanoHttpModificationList));
    if (modification_node == NULL) {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_WARNING,
            "Failed to allocate modification node of size: %d",
            sizeof(NanoHttpModificationList)
        );
        return NULL;
    }

    res = create_modification_buffer(
        attachment,
        session_id,
        &modification_node->modification_buffer,
        modification->injection_size,
        modification->data
    );

    if (res != NANO_OK) {
        free(modification_node);
        return NULL;
    }

    modification_node->next = NULL;
    modification_node->modification.is_header = modification->is_header;
    modification_node->modification.mod_type = modification->mod_type;
    modification_node->modification.injection_pos = modification->injection_pos;
    modification_node->modification.injection_size = modification->injection_size;
    modification_node->modification.orig_buff_index = modification->orig_buff_index;

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_DEBUG,
        "Successfully created modification node. "
        "Is header: %d, "
        "Injection position: %d, "
        "Injection size: %d, "
        "Original buffer index: %d, "
        "Data: %s, "
        "Should change data: %d",
        modification_node->modification.is_header,
        modification_node->modification.injection_pos,
        modification_node->modification.injection_size,
        modification_node->modification.orig_buff_index,
        modification_node->modification_buffer,
        modification_node->modification.mod_type
    );

    return modification_node;
}

///
/// @brief Handles the response of an injection request by creating modification nodes
///        and updating the modification list.
///
/// This function iterates over the injection data and creates modification nodes for each injection,
/// updating the modification list accordingly. If an error occurs during node creation, it logs a warning
/// and frees the memory associated with previously created modification nodes.
///
/// @param attachment A pointer to a NanoAttachment structure representing the attachment.
/// @param session_id The ID of the session.
/// @param modification_list A pointer to a pointer to the head of the modification list.
/// @param inject_data A pointer to an array of HttpInjectData structures containing injection data.
/// @param modification_count The number of modifications in the injection data array.
///
static void
handle_inject_response(
    NanoAttachment *attachment,
    SessionID session_id,
    NanoHttpModificationList **modification_list,
    HttpInjectData *inject_data,
    uint8_t modification_count
)
{
    NanoHttpModificationList *new_modification = NULL;
    NanoHttpModificationList *current_modification = NULL;
    unsigned int modification_index;

    for (modification_index = 0; modification_index < modification_count; modification_index++) {
        // Go over the modifications and create nodes.
        new_modification = create_modification_node(attachment, session_id, inject_data);
        if (new_modification == NULL) {
            write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Failed to create modification node");
            while (*modification_list) {
                current_modification = *modification_list;
                *modification_list = (*modification_list)->next;
                free(current_modification->modification_buffer);
                free(current_modification);
            }
            return;
        }
        if (*modification_list == NULL) {
            *modification_list = new_modification;
            current_modification = *modification_list;
        } else {
            current_modification->next = new_modification;
            current_modification = current_modification->next;
        }
        // Moving the pointer to the next injection.
        inject_data = (HttpInjectData *)((char *)inject_data + sizeof(HttpInjectData) + inject_data->injection_size);
    }
}

///
/// @brief Create a custom web response by the provided data
///
/// @param[in] attachment Nano attachment.
/// @param[in] session_id Session ID.
/// @param[in] web_response_data Web response data.
/// @param[in, out] ctx_response_data Web response data to be set.
///
static void
handle_custom_web_response(
    NanoAttachment *attachment,
    SessionID session_id,
    WebResponseData **ctx_response_data,
    HttpWebResponseData *web_response_data
)
{
    nano_str_t title = {0, NULL};
    nano_str_t body = {0, NULL};
    nano_str_t uuid;
    size_t incident_prefix_size = strlen("Incident Id: ");
    WebResponseData *new_response_data = NULL;
    CustomResponseData *custom_response_data = NULL;

    uuid.len = web_response_data->uuid_size;
    if (uuid.len >= UUID_SIZE) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Custom response UUID is too long");
        return;
    }

    title.len = web_response_data->response_data.custom_response_data.title_size;
    if (title.len >= CUSTOM_RESPONSE_TITLE_SIZE) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Custom response title is too long");
        return;
    }

    body.len = web_response_data->response_data.custom_response_data.body_size;
    if (body.len >= CUSTOM_RESPONSE_BODY_SIZE) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Custom response body is too long");
        return;
    }

    new_response_data = malloc(sizeof(WebResponseData));
    if (new_response_data == NULL) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Failed to allocate memory for web response data");
        return;
    }

    write_dbg(attachment, session_id, DBG_LEVEL_TRACE, "Preparing to set custom web response page");
    custom_response_data = malloc(sizeof(CustomResponseData));
    if (custom_response_data == NULL) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Failed to allocate memory for custom response data");
        free(new_response_data);
        return;
    }

    // Setting custom web response title's data.
    if (title.len > 0) {
        title.data = (u_char *)web_response_data->response_data.custom_response_data.data;
    }

    // Setting custom web response body's data.
    if (body.len > 0) {
        body.data = (u_char *)web_response_data->response_data.custom_response_data.data + title.len;
    }

    uuid.data = (u_char *)web_response_data->response_data.custom_response_data.data + title.len + body.len;

    custom_response_data->response_code = web_response_data->response_data.custom_response_data.response_code;

    if (title.data != NULL) {
        memcpy(custom_response_data->title, title.data, title.len);
    }
    custom_response_data->title[title.len] = '\0';

    if (body.data != NULL) {
        memcpy(custom_response_data->body, body.data, body.len);
    }
    custom_response_data->body[body.len] = '\0';

    new_response_data->web_response_type = CUSTOM_WEB_RESPONSE;
    memcpy(new_response_data->uuid, "Incident Id: ", incident_prefix_size);
    memcpy(new_response_data->uuid + incident_prefix_size, uuid.data, uuid.len);
    new_response_data->uuid[incident_prefix_size + uuid.len] = '\0';

    new_response_data->data = custom_response_data;
    *ctx_response_data = new_response_data;
}

///
/// @brief Create a redirect response by the provided data
///
/// @param[in] attachment Nano attachment.
/// @param[in] session_id Session ID.
/// @param[in] web_response_data Web response data.
/// @param[in, out] ctx_response_data Web response data to be set.
///
static void
handle_redirect_response(
    NanoAttachment *attachment,
    SessionID session_id,
    WebResponseData **ctx_response_data,
    HttpWebResponseData *web_response_data
)
{
    nano_str_t uuid;
    nano_str_t redirect_location;
    WebResponseData *new_response_data = NULL;
    RedirectData *redirect_data = NULL;

    uuid.len = web_response_data->uuid_size;
    if (uuid.len >= UUID_SIZE) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Custom response UUID is too long");
        return;
    }

    redirect_location.len = web_response_data->response_data.redirect_data.redirect_location_size;
    if (redirect_location.len >= REDIRECT_RESPONSE_LOCATION_SIZE) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Custom response redirect location is too long");
        return;
    }

    new_response_data = malloc(sizeof(WebResponseData));
    if (new_response_data == NULL) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Failed to allocate memory for web response data");
        return;
    }

    write_dbg(attachment, session_id, DBG_LEVEL_TRACE, "Preparing to set redirect web response");

    redirect_data = malloc(sizeof(RedirectData));
    if (redirect_data == NULL) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Failed to allocate memory for custom response data");
        free(new_response_data);
        return;
    }

    redirect_location.data = (u_char *)web_response_data->response_data.redirect_data.redirect_location;

    memcpy(redirect_data->redirect_location, redirect_location.data, redirect_location.len);
    redirect_data->redirect_location[redirect_location.len] = '\0';

    uuid.data = (u_char *)web_response_data->response_data.redirect_data.redirect_location + redirect_location.len;

    new_response_data->web_response_type = REDIRECT_WEB_RESPONSE;
    memcpy(new_response_data->uuid, uuid.data, uuid.len);
    new_response_data->uuid[uuid.len] = '\0';
    new_response_data->data = redirect_data;
    *ctx_response_data = new_response_data;
}

///
/// @brief Handles drop response received from a service.
///
/// This function is responsible for processing different types of web responses
/// and taking appropriate actions based on the response type.
///
/// @param[in] attachment Pointer to the NanoAttachment structure associated with the request.
/// @param[in] session_id The session ID of the request.
/// @param[in, out] ctx_response_data Pointer to the pointer of WebResponseData holding context response data.
/// @param[in, out] web_response_data Pointer to the HttpWebResponseData containing the web response data.
///
static void
handle_drop_response(
    NanoAttachment *attachment,
    SessionID session_id,
    WebResponseData **ctx_response_data,
    HttpWebResponseData *web_response_data
)
{
    switch (web_response_data->web_response_type) {
        case CUSTOM_WEB_RESPONSE:
            handle_custom_web_response(attachment, session_id, ctx_response_data, web_response_data);
            break;
        case REDIRECT_WEB_RESPONSE:
            handle_redirect_response(attachment, session_id, ctx_response_data, web_response_data);
            break;
        default:
            write_dbg(
                attachment,
                session_id,
                DBG_LEVEL_WARNING,
                "Received an unknown web response type %d",
                web_response_data->web_response_type
            );
            break;
    }
}

NanoCommunicationResult
service_reply_receiver(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    WebResponseData **web_response_data,
    NanoHttpModificationList **modification_list,
    AttachmentDataType chunk_type
)
{
    HttpReplyFromService *reply_p;
    NanoHttpModificationList *current_modification = NULL;
    NanoCommunicationResult res;

    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_TRACE,
        "Receiving verdict replies for %d chunks of inspected data",
        session_data->remaining_messages_to_reply
    );

    if (session_data->remaining_messages_to_reply == 0) {
        session_data->verdict = TRAFFIC_VERDICT_INSPECT;
        return NANO_OK;
    }

    do {
        res = signal_for_session_data(attachment, session_data->session_id, chunk_type);
    } while (res == NANO_AGAIN);

    if (res != NANO_OK) {
        disconnect_communication(attachment);
        restart_communication(attachment);
        return NANO_ERROR;
    }

    while (session_data->remaining_messages_to_reply) {
        // For each expected message, receive the reply from the nano service.
        reply_p = receive_data_from_service(attachment, session_data->session_id);
        if (reply_p == NULL) {
            write_dbg(
                attachment,
                session_data->session_id,
                DBG_LEVEL_WARNING,
                "Failed to get reply from the nano service"
            );
            return NANO_ERROR;
        }

        // If reply isn't reconfiguration, it should be handled as part of session data related replies.
        // The reason is that the reconfiguration is not related to a specific session but to attachment as a whole.
        // It is a signal sent by the nano service to let the attachment know that it should reconfigure itself
        // due to a new configuration being applied and it is broadcasted to all attachment's instances.
        if (reply_p->verdict != TRAFFIC_VERDICT_RECONF) {
            if (reply_p->session_id != session_data->session_id) {
                // Verify if incoming reply is of a correct session.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_DEBUG,
                    "Ignoring verdict to an already handled request %d",
                    reply_p->session_id
                );
                popData(attachment->nano_service_ipc);
                continue;
            }

            session_data->remaining_messages_to_reply--;
        }

        session_data->verdict = reply_p->verdict;

        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_TRACE,
            "Verdict %d received",
            session_data->verdict
        );

        switch(session_data->verdict) {
            case TRAFFIC_VERDICT_INJECT: {
                // Verdict inject received from the nano service.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict inject received from the nano service"
                );
                updateMetricField(attachment, INJECT_VERDICTS_COUNT, 1);

                handle_inject_response(
                    attachment,
                    session_data->session_id,
                    modification_list,
                    reply_p->modify_data->inject_data,
                    reply_p->modification_count
                );

                session_data->verdict = TRAFFIC_VERDICT_INSPECT;
                break;
            }

            case TRAFFIC_VERDICT_DROP: {
                // After a drop verdict no more replies will be sent, so we can leave the loop
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict drop received from the nano service"
                );

                updateMetricField(attachment, DROP_VERDICTS_COUNT, 1);
                handle_drop_response(
                    attachment,
                    session_data->session_id,
                    web_response_data,
                    reply_p->modify_data->web_response_data
                );

                session_data->remaining_messages_to_reply = 0;
                while (*modification_list) {
                    current_modification = *modification_list;
                    *modification_list = (*modification_list)->next;
                    free(current_modification->modification.data);
                    free(current_modification);
                }
                popData(attachment->nano_service_ipc);
                return NANO_HTTP_FORBIDDEN;
            }

            case TRAFFIC_VERDICT_ACCEPT: {
                // After an accept verdict no more replies will be sent, so we can leave the loop
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict accept received from the nano service"
                );
                updateMetricField(attachment, ACCEPT_VERDICTS_COUNT, 1);
                session_data->remaining_messages_to_reply = 0;
                popData(attachment->nano_service_ipc);
                return NANO_OK;
            }

            case TRAFFIC_VERDICT_IRRELEVANT: {
                // After an irrelevant verdict, ignore the verdict and continue to the next response.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict irrelevant received from the nano service"
                );
                updateMetricField(attachment, IRRELEVANT_VERDICTS_COUNT, 1);
                break;
            }

            case TRAFFIC_VERDICT_RECONF: {
                // After a reconfiguration verdict, reset attachment config.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict reconf received from the nano service"
                );
                updateMetricField(attachment, RECONF_VERDICTS_COUNT, 1);
                reset_attachment_config(attachment);
                break;
            }

            case TRAFFIC_VERDICT_INSPECT: {
                // Inspect verdict, continue to the next response.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_TRACE,
                    "Verdict inspect received from the nano service"
                );
                updateMetricField(attachment, INSPECT_VERDICTS_COUNT, 1);
                break;
            }

            case TRAFFIC_VERDICT_DELAYED: {
                // After a delayed verdict, query the nano agent again to get an updated verdict.
                write_dbg(
                    attachment,
                    session_data->session_id,
                    DBG_LEVEL_DEBUG,
                    "Verdict delayed received from the nano service"
                );
                updateMetricField(attachment, HOLD_VERDICTS_COUNT, 1);
                break;
            }
        }
        popData(attachment->nano_service_ipc);
    }

    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_DEBUG,
        "No finalized verdict (ACCEPT, DROP) has been received from the nano service"
    );
    return NANO_OK;
}

///
/// @brief Set meta data fragment element data and size.
/// @param[in, out] meta_data_elems Fragments data array.
/// @param[in, out] meta_data_sizes Fragments data sizes array.
/// @param[in] data Data to set into the meta_data_elems array.
/// @param[in] size Size to be set into the meta_data_sizes array.
/// @param[in] idx Index of the arrays to set the data and size into.
///
static void
set_fragment_elem(char **meta_data_elems, uint16_t *meta_data_sizes, void *data, uint16_t size, uint idx)
{
    meta_data_elems[idx] = data;
    meta_data_sizes[idx] = size;
}

///
/// @brief Set meta data fragments identifiers.
/// @details The data identifiers will be set on the 0 and 1 slots of the array.
/// @param[in, out] meta_data_elems Fragments data array.
/// @param[in, out] meta_data_sizes Fragments data sizes array.
/// @param[in] data_type Data type identifier to be set.
/// @param[in] cur_request_id Request's Id.
///
static void
set_fragments_identifiers(
    char **meta_data_elems,
    uint16_t *meta_data_sizes,
    uint16_t *data_type,
    uint32_t cur_request_id
)
{
    set_fragment_elem(meta_data_elems, meta_data_sizes, data_type, sizeof(uint16_t), 0);
    set_fragment_elem(meta_data_elems, meta_data_sizes, &cur_request_id, sizeof(cur_request_id), 1);
}

///
/// @brief Checks if inspection is required for the given source IP address.
///
/// @param src_ip The source IP address to check for inspection requirement.
/// @return 1 if inspection is required, 0 if inspection can be skipped, -1 on error.
///
static int
IsInspectionRequiredForSource(NanoAttachment *attachment, SessionID session_id, const nano_str_t *src_ip)
{
    if (!isIPAddress((char *)src_ip->data)) {
        write_dbg(attachment, session_id, DBG_LEVEL_WARNING, "Input %s is not an IP adress", src_ip->data);
        return -1;
    }

    write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "IP is relevant: %s", src_ip->data);

    return !isSkipSource((char *)src_ip->data);
}

NanoCommunicationResult
connect_to_comm_socket(NanoAttachment *attachment)
{
    struct sockaddr_un server;
    int cur_errno = 0; // temp fix for errno changing during print

    // Close the old socket if there was one.
    if (attachment->comm_socket > 0) {
        close(attachment->comm_socket);
        attachment->comm_socket = -1;
    }

    // Connect a new socket.
    attachment->comm_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (attachment->comm_socket < 0) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Could not create socket, Error: %s", strerror(errno));
        return NANO_ERROR;
    }

    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, attachment->shared_verdict_signal_path, sizeof(server.sun_path) - 1);

    if (connect(attachment->comm_socket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) != -1) {
        return NANO_OK;
    }

    cur_errno = errno;
    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Could not connect to nano service. Path: %s, Error: %s, Errno: %d",
        server.sun_path,
        strerror(errno),
        cur_errno
    );

    return NANO_ERROR;
}

NanoCommunicationResult
connect_to_registration_socket(NanoAttachment *attachment)
{
    struct sockaddr_un server;
    int cur_errno = 0; // temp fix for errno changing during print

    // Connect a new socket.
    attachment->registration_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (attachment->registration_socket < 0) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Could not create socket, Error: %s", strerror(errno));
        return NANO_ERROR;
    }

    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, SHARED_REGISTRATION_SIGNAL_PATH, sizeof(server.sun_path) - 1);

    if (connect(attachment->registration_socket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) != -1) {
        return NANO_OK;
    }

    cur_errno = errno;
    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Could not connect to nano service. Path: %s, Error: %s, Errno: %d",
        server.sun_path,
        strerror(errno),
        cur_errno
    );

    return NANO_ERROR;
}

void
nano_metadata_sender(
    NanoAttachment *attachment,
    HttpMetaData *metadata,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_of_messages_sent,
    bool is_verdict_requested
)
{
    uint16_t chunk_type;
    NanoCommunicationResult res;
    char *fragments[META_DATA_COUNT + 2];
    uint16_t fragments_sizes[META_DATA_COUNT + 2];
    uint8_t meta_data_count = META_DATA_COUNT - 4;

    write_dbg(attachment, cur_request_id, DBG_LEVEL_TRACE, "Sending request start meta data for inspection");

    if(!IsInspectionRequiredForSource(attachment, cur_request_id, &metadata->client_ip)) {
        write_dbg(
            attachment,
            cur_request_id,
            DBG_LEVEL_DEBUG,
            "Skipping IP Source"
        );

        ctx->session_data_p->verdict = TRAFFIC_VERDICT_IRRELEVANT;
        ctx->res = NANO_DECLINED;
        return;
    }

    // Sets the fragments
    chunk_type = REQUEST_START;
    set_fragments_identifiers(fragments, fragments_sizes, &chunk_type, cur_request_id);

    // Add protocol length to fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &metadata->http_protocol.len,
        sizeof(uint16_t),
        HTTP_PROTOCOL_SIZE + 2
    );
    // Add protocol data to fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        metadata->http_protocol.data,
        metadata->http_protocol.len,
        HTTP_PROTOCOL_DATA + 2
    );

    // Add method data length to fragments.
    set_fragment_elem(fragments, fragments_sizes, &metadata->method_name.len, sizeof(uint16_t), HTTP_METHOD_SIZE + 2);
    // Add method data to fragments
    set_fragment_elem(
        fragments,
        fragments_sizes,
        metadata->method_name.data,
        metadata->method_name.len,
        HTTP_METHOD_DATA + 2
    );

    // Add host data length to the fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &metadata->host.len,
        sizeof(uint16_t),
        HOST_NAME_SIZE + 2
    );
    // Add host data to the fragments.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        metadata->host.data,
        metadata->host.len,
        HOST_NAME_DATA + 2
    );

    // Add listening IP metadata.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &metadata->listening_ip.len,
        sizeof(uint16_t),
        LISTENING_ADDR_SIZE + 2
    );
    set_fragment_elem(
        fragments,
        fragments_sizes,
        metadata->listening_ip.data,
        metadata->listening_ip.len,
        LISTENING_ADDR_DATA + 2
    );

    // Add listening port data.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &metadata->listening_port,
        sizeof(uint16_t),
        LISTENING_PORT + 2
    );

    // Add URI data.
    set_fragment_elem(fragments, fragments_sizes, &metadata->uri.len, sizeof(uint16_t), URI_SIZE + 2);
    set_fragment_elem(fragments, fragments_sizes, metadata->uri.data, metadata->uri.len, URI_DATA + 2);

    // Add client IP data.
    set_fragment_elem(fragments, fragments_sizes, &metadata->client_ip.len, sizeof(uint16_t), CLIENT_ADDR_SIZE + 2);
    set_fragment_elem(
        fragments,
        fragments_sizes,
        metadata->client_ip.data,
        metadata->client_ip.len,
        CLIENT_ADDR_DATA + 2
    );

    // Add client IP port.
    set_fragment_elem(
        fragments,
        fragments_sizes,
        &metadata->client_port,
        sizeof(uint16_t),
        CLIENT_PORT + 2
    );

    if (metadata->parsed_host.len > 0) {
        // Add parsed host data.
        set_fragment_elem(
            fragments,
            fragments_sizes,
            &metadata->parsed_host.len,
            sizeof(uint16_t),
            PARSED_HOST_SIZE + 2
        );
        set_fragment_elem(
            fragments,
            fragments_sizes,
            metadata->parsed_host.data,
            metadata->parsed_host.len,
            PARSED_HOST_DATA + 2
        );
        meta_data_count += 2;
    }

    if (metadata->parsed_uri.len > 0) {
        // Add parsed URI data.
        set_fragment_elem(
            fragments,
            fragments_sizes,
            &metadata->parsed_uri.len,
            sizeof(uint16_t),
            PARSED_URI_SIZE + 2
        );
        set_fragment_elem(
            fragments,
            fragments_sizes,
            metadata->parsed_uri.data,
            metadata->parsed_uri.len,
            PARSED_URI_DATA + 2
        );
        meta_data_count += 2;
    }

    // Sends all the data to the nano service.
    res = send_session_data_to_service(
        attachment,
        fragments,
        fragments_sizes,
        meta_data_count + 2,
        cur_request_id,
        chunk_type
    );

    if (res == NANO_ERROR) {
        // Failed to send the metadata to nano service.
        write_dbg(
            attachment,
            cur_request_id,
            DBG_LEVEL_WARNING,
            "Failed to send request meta data to the nano service. Session ID: %d",
            cur_request_id
        );
        ctx->res = NANO_ERROR;
        return;
    }

    if (res == NANO_OK) {
        *num_of_messages_sent += 1;
    }

    if (is_verdict_requested) {
        ctx->res = service_reply_receiver(
            attachment,
            ctx->session_data_p,
            &ctx->web_response_data,
            &ctx->modifications,
            chunk_type
        );
    }
}

void
nano_send_response_code(
    NanoAttachment *attachment,
    uint16_t response_code,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
)
{
    char *fragments[RESPONSE_CODE_COUNT];
    uint16_t fragments_sizes[RESPONSE_CODE_COUNT];
    uint16_t chunk_type = RESPONSE_CODE;
    NanoCommunicationResult res;

    write_dbg(attachment, cur_request_id, DBG_LEVEL_TRACE, "Sending response code (%d) for inspection", response_code);

    set_fragments_identifiers(fragments, fragments_sizes, &chunk_type, cur_request_id);
    set_fragment_elem(fragments, fragments_sizes, &response_code, sizeof(uint16_t), 2);

    res = send_session_data_to_service(
        attachment,
        fragments,
        fragments_sizes,
        RESPONSE_CODE_COUNT,
        cur_request_id,
        chunk_type
    );

    if (res != NANO_OK) {
        ctx->res = NANO_ERROR;
        return;
    }

    *num_messages_sent += 1;
}

void
nano_send_response_content_length(
    NanoAttachment *attachment,
    uint64_t content_length,
    HttpEventThreadCtx *ctx,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
)
{
    char *fragments[CONTENT_LENGTH_COUNT];
    uint16_t fragments_sizes[CONTENT_LENGTH_COUNT];
    uint16_t chunk_type = CONTENT_LENGTH;
    NanoCommunicationResult res;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Sending content length (%ld) to the intaker",
        content_length
    );

    set_fragments_identifiers(fragments, fragments_sizes, &chunk_type, cur_request_id);
    set_fragment_elem(fragments, fragments_sizes, &content_length, sizeof(content_length), 2);

    res = send_session_data_to_service(
        attachment,
        fragments,
        fragments_sizes,
        CONTENT_LENGTH_COUNT,
        cur_request_id,
        chunk_type
    );

    if (res != NANO_OK) {
        ctx->res = NANO_ERROR;
        return;
    }

    *num_messages_sent += 1;
}

///
/// @brief Sends a bulk of headers to the service using a NanoAttachment.
///
/// This function takes a NanoAttachment pointer,
/// an array of data fragments, an array of data fragment sizes, the number
/// of headers in the bulk, a flag indicating if this is the last bulk, the index of the current bulk part,
/// and the current request ID.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param data Array of data fragments containing the bulk of headers.
/// @param data_sizes Array of sizes corresponding to the data fragments.
/// @param header_type Type of the headers (REQUEST_HEADER or RESPONSE_HEADER).
/// @param num_headers Number of headers in the bulk.
/// @param is_last_part Flag indicating if this is the last bulk.
/// @param bulk_part_index Index of the current bulk part.
/// @param cur_request_id Current request ID.
///
/// @return NanoCommunicationResult NANO_OK if successful, NANO_ERROR otherwise.
///
static NanoCommunicationResult
send_header_bulk(
    NanoAttachment *attachment,
    char **data,
    uint16_t *data_sizes,
    AttachmentDataType header_type,
    const unsigned int num_headers,
    uint8_t is_last_part,
    uint8_t bulk_part_index,
    uint32_t cur_request_id
)
{
    NanoCommunicationResult res;

    set_fragments_identifiers(data, data_sizes, (uint16_t *)&header_type, cur_request_id);
    set_fragment_elem(data, data_sizes, &is_last_part, sizeof(is_last_part), 2);
    set_fragment_elem(data, data_sizes, &bulk_part_index, sizeof(bulk_part_index), 3);

    res = send_session_data_to_service(
        attachment,
        data,
        data_sizes,
        HEADER_DATA_COUNT * num_headers + 4,
        cur_request_id,
        REQUEST_HEADER
    );

    if (res != NANO_OK) {
        write_dbg(attachment, cur_request_id, DBG_LEVEL_TRACE, "Failed to send bulk of %iu headers", num_headers);
        return NANO_ERROR;
    }

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Successfully sent bulk number %ui with %d headers",
        bulk_part_index,
        num_headers
    );

    return NANO_OK;
}

///
/// @brief Adds an HTTP header to a bulk data structure.
///
/// This function takes an array of fragments, an array of fragment sizes,
/// an HttpHeaderData struct representing the header,
/// and an index to determine the position in the bulk data structure where the header should be added.
///
/// @param attachment Pointer to the NanoAttachment struct representing the attachment.
/// @param session_id The session ID associated with the attachment.
/// @param fragments Array of fragments to add the header to.
/// @param fragments_sizes Array of sizes corresponding to the fragments.
/// @param header Pointer to the HttpHeaderData struct representing the header to add.
/// @param index Index indicating where in the bulk data structure to add the header.
///
static inline void
add_header_to_bulk(
    NanoAttachment *attachment,
    uint32_t session_id,
    char **fragments,
    uint16_t *fragments_sizes,
    HttpHeaderData *header,
    unsigned int index
)
{
    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Sending current header (key: '%.*s', value: '%.*s') to inspection",
        header->key.len,
        header->key.data,
        header->value.len,
        header->value.data
    );

    unsigned int pos = index * HEADER_DATA_COUNT;
    set_fragment_elem(fragments, fragments_sizes, &header->key.len, sizeof(uint16_t), pos + HEADER_KEY_SIZE + 4);
    set_fragment_elem(fragments, fragments_sizes, header->key.data, header->key.len, pos + HEADER_KEY_DATA + 4);
    set_fragment_elem(fragments, fragments_sizes, &header->value.len, sizeof(uint16_t), pos + HEADER_VAL_SIZE + 4);
    set_fragment_elem(fragments, fragments_sizes, header->value.data, header->value.len, pos + HEADER_VAL_DATA + 4);
}

void
nano_header_sender(
    NanoAttachment *attachment,
    HttpHeaders *headers,
    HttpEventThreadCtx *ctx,
    AttachmentDataType header_type,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent,
    bool is_verdict_requested
)
{
    int is_final_header = 0;
    int bulk_index = 0;
    char *fragments[HEADER_DATA_COUNT * MAX_HEADER_BULK_SIZE + 4];
    uint16_t fragments_sizes[HEADER_DATA_COUNT * MAX_HEADER_BULK_SIZE + 4];
    size_t header_index = 0;
    int fragment_index = 0;
    NanoCommunicationResult send_bulk_result;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Sending %s headers for inspection",
        header_type == REQUEST_HEADER ? "request" : "response"
    );

    for (header_index = 0; header_index < headers->headers_count ; header_index++) {
        if (header_index == headers->headers_count - 1) {
            is_final_header = 1;
        }

        add_header_to_bulk(
            attachment,
            cur_request_id,
            fragments,
            fragments_sizes,
            &headers->data[header_index],
            fragment_index
        );

        fragment_index++;
        if (fragment_index < MAX_HEADER_BULK_SIZE && !is_final_header) continue;

        send_bulk_result = send_header_bulk(
            attachment,
            fragments,
            fragments_sizes,
            header_type,
            fragment_index,
            is_final_header,
            bulk_index,
            cur_request_id
        );
        if (send_bulk_result != NANO_OK) {
            write_dbg(
                attachment,
                cur_request_id,
                DBG_LEVEL_WARNING,
                "Failed to send request headers to the nano service. Session ID: %d",
                cur_request_id
            );
            ctx->res = NANO_ERROR;
            return;
        }

        bulk_index++;
        fragment_index = 0;
    }

    *num_messages_sent += bulk_index;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Exit after inspection of %d headers",
        headers->headers_count
    );

    if (is_verdict_requested) {
        ctx->res = service_reply_receiver(
            attachment,
            ctx->session_data_p,
            &ctx->web_response_data,
            &ctx->modifications,
            header_type
        );
    }
}

void
nano_body_sender(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpEventThreadCtx *ctx,
    AttachmentDataType body_type,
    uint32_t cur_request_id,
    unsigned int *num_messages_sent
)
{
    char *fragments[BODY_DATA_COUNT];
    uint16_t fragments_sizes[BODY_DATA_COUNT];
    uint8_t is_final_chunk = 0;
    uint8_t body_index = 0;
    nano_str_t *body = NULL;
    NanoCommunicationResult send_bulk_result;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Sending %s bodies for inspection",
        body_type == REQUEST_BODY ? "request" : "response"
    );

    for (body_index = 0; body_index < bodies->bodies_count ; body_index++) {
        if (body_index == bodies->bodies_count - 1) {
            is_final_chunk = 1;
        }

        set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&body_type, cur_request_id);

        set_fragment_elem(fragments, fragments_sizes, &is_final_chunk, sizeof(is_final_chunk), 2);
        set_fragment_elem(fragments, fragments_sizes, &body_index, sizeof(body_index), 3);

        body = &bodies->data[body_index];
        set_fragment_elem(fragments, fragments_sizes, body->data, body->len, 4);

        send_bulk_result = send_session_data_to_service(
            attachment,
            fragments,
            fragments_sizes,
            BODY_DATA_COUNT,
            cur_request_id,
            body_type
        );
        if (send_bulk_result != NANO_OK) {
            write_dbg(
                attachment,
                cur_request_id,
                DBG_LEVEL_WARNING,
                "Failed to send request body to the nano service. Session ID: %d",
                cur_request_id
            );
            ctx->res = NANO_ERROR;
            return;
        }
    }

    *num_messages_sent += body_index;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Exit after inspection of %d body chunks",
        bodies->bodies_count
    );

    ctx->res = service_reply_receiver(
        attachment,
        ctx->session_data_p,
        &ctx->web_response_data,
        &ctx->modifications,
        body_type
    );
}

void
nano_end_transaction_sender(
    NanoAttachment *attachment,
    AttachmentDataType end_transaction_type,
    HttpEventThreadCtx *ctx,
    SessionID cur_request_id,
    unsigned int *num_messages_sent
)
{
    char *fragments[END_TRANSACTION_DATA_COUNT];
    uint16_t fragments_sizes[END_TRANSACTION_DATA_COUNT];
    NanoCommunicationResult res;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Sending end %s event flag for inspection",
        end_transaction_type == REQUEST_END ? "request" : "response"
    );

    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&end_transaction_type, cur_request_id);

    res = send_session_data_to_service(
        attachment,
        fragments,
        fragments_sizes,
        END_TRANSACTION_DATA_COUNT,
        cur_request_id,
        attachment->fail_open_timeout
    );
    if (res != NANO_OK) {
        write_dbg(
            attachment,
            cur_request_id,
            DBG_LEVEL_TRACE,
            "Failed to send end %s event flag for inspection",
            end_transaction_type == REQUEST_END ? "request" : "response"
        );
        return;
    }

    *num_messages_sent += 1;

    ctx->res = service_reply_receiver(
        attachment,
        ctx->session_data_p,
        &ctx->web_response_data,
        &ctx->modifications,
        end_transaction_type
    );
}

void
nano_request_delayed_verdict(
    NanoAttachment *attachment,
    HttpEventThreadCtx *ctx,
    SessionID cur_request_id,
    unsigned int *num_messages_sent
)
{
    char *fragments[DELAYED_VERDICT_DATA_COUNT];
    uint16_t fragments_sizes[DELAYED_VERDICT_DATA_COUNT];
    AttachmentDataType wait_transaction_type = REQUEST_DELAYED_VERDICT;
    NanoCommunicationResult res;

    write_dbg(
        attachment,
        cur_request_id,
        DBG_LEVEL_TRACE,
        "Sending delayed event flag for inspection"
    );

    set_fragments_identifiers(fragments, fragments_sizes, (uint16_t *)&wait_transaction_type, cur_request_id);

    res = send_session_data_to_service(
        attachment,
        fragments,
        fragments_sizes,
        DELAYED_VERDICT_DATA_COUNT,
        cur_request_id,
        attachment->fail_open_timeout
    );
    if (res != NANO_OK) {
        write_dbg(
            attachment,
            cur_request_id,
            DBG_LEVEL_TRACE,
            "Failed to send delayed event flag for inspection"
        );
        return;
    }

    *num_messages_sent += 1;

    ctx->res = service_reply_receiver(
        attachment,
        ctx->session_data_p,
        &ctx->web_response_data,
        &ctx->modifications,
        wait_transaction_type
    );
}

void
nano_send_metric_data_sender(NanoAttachment *attachment)
{
    char *fragments;
    uint16_t fragments_sizes;
    uint16_t data_size;
    NanoCommunicationResult res;
    NanoHttpMetricData metric_data_to_send;

    write_dbg(
        attachment,
        0,
        DBG_LEVEL_DEBUG,
        "Sending metric data to service"
    );

    metric_data_to_send.data_type = METRIC_DATA_FROM_PLUGIN;
    data_size = METRIC_TYPES_COUNT * sizeof(metric_data_to_send.data[0]);
    memcpy(metric_data_to_send.data, attachment->metric_data, data_size);

    fragments = (char *)&metric_data_to_send;
    fragments_sizes = sizeof(NanoHttpMetricData);
    res = send_session_data_to_service(
        attachment,
        &fragments,
        &fragments_sizes,
        1,
        0,
        attachment->fail_open_timeout
    );

    if (res != NANO_OK) {
        write_dbg(
            attachment,
            0,
            DBG_LEVEL_TRACE,
            "Failed to send metric data to the nano service worker ID"
        );
        return;
    }

    reset_metric_data(attachment);
}
