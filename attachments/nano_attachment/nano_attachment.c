#include "nano_attachment.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nano_attachment_sender.h"
#include "nano_attachment_metric.h"
#include "nano_initializer.h"
#include "nano_configuration.h"
#include "nano_utils.h"
#include "attachment_types.h"
#include "nano_blockpage.h"

NanoAttachment *
InitNanoAttachment(uint8_t attachment_type, int worker_id, int num_of_workers, int logging_fd)
{
    // NanoAttachment *attachment = malloc(sizeof(NanoAttachment));
    NanoAttachment *attachment = calloc(1, sizeof(NanoAttachment));
    if (attachment == NULL) {
        return NULL;
    }

    // memset(attachment, 0, sizeof(NanoAttachment));

    attachment->shared_verdict_signal_path[0] = '\0';
    attachment->worker_id = worker_id;
    attachment->num_of_workers = num_of_workers;
    attachment->nano_user_id = getuid();
    attachment->nano_group_id = getgid();
    attachment->registration_socket = -1;
    attachment->registration_state = NOT_REGISTERED;
    attachment->attachment_type = attachment_type;
    attachment->nano_service_ipc = NULL;
    attachment->comm_socket = -1;
    attachment->logging_data = NULL;

    if (set_docker_id(attachment) == NANO_ERROR) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Could not evaluate container id");
        close_logging_fd(attachment);
        free(attachment);
        return NULL;
    }

    if (set_logging_fd(attachment, logging_fd) == NANO_ERROR) {
        free(attachment);
        return NULL;
    }

    attachment->logging_data = initLoggingData(
        attachment->logging_fd,
        DBG_LEVEL_INFO,
        attachment->worker_id
    );
    if (attachment->logging_data == NULL) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Failed to initialize logging data");
        return NULL;
    }

    if (set_unique_id(attachment) == NANO_ERROR) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Could not evaluate unique name");
        close_logging_fd(attachment);
        free(attachment);
        return NULL;
    }

    attachment->is_configuration_updated = NANO_ERROR;
    attachment->current_config_version = 0;

    attachment->fail_mode_verdict = NANO_OK;
    attachment->fail_mode_delayed_verdict = NANO_OK;
    attachment->dbg_level = DBG_LEVEL_INFO;
    attachment->num_of_connection_attempts = 0;
    attachment->fail_open_timeout = 50;
    attachment->fail_open_delayed_timeout = 150;
    attachment->sessions_per_minute_limit_verdict = ATTACHMENT_VERDICT_ACCEPT;
    attachment->max_sessions_per_minute = 0;
    attachment->req_max_proccessing_ms_time = 3000;
    attachment->res_max_proccessing_ms_time = 3000;
    attachment->registration_thread_timeout_msec = 100;
    attachment->req_start_thread_timeout_msec = 100;
    attachment->req_header_thread_timeout_msec = 100;
    attachment->req_body_thread_timeout_msec = 150;
    attachment->res_header_thread_timeout_msec = 100;
    attachment->res_body_thread_timeout_msec = 150;
    attachment->waiting_for_verdict_thread_timeout_msec = 150;
    attachment->metric_timeout_timeout = 100;
    attachment->inspection_mode = NON_BLOCKING_THREAD;
    attachment->num_of_nano_ipc_elements = 200;
    attachment->keep_alive_interval_msec = DEFAULT_KEEP_ALIVE_INTERVAL_MSEC;

    if (nano_attachment_init_process(attachment) != NANO_OK) {
        write_dbg(attachment, 0, DBG_LEVEL_WARNING, "Could not initialize nano attachment");
        close_logging_fd(attachment);
        free(attachment);
        return NULL;
    }

    reset_metric_data(attachment);
    return attachment;
};

void
FiniNanoAttachment(NanoAttachment *attachment)
{
    close_logging_fd(attachment);
    free(attachment);
};

NanoCommunicationResult
RestartAttachmentConfiguration(NanoAttachment *attachment)
{
    return reset_attachment_config(attachment);
};

HttpSessionData *
InitSessionData(NanoAttachment *attachment, SessionID session_id)
{
    HttpSessionData *session_data = malloc(sizeof(HttpSessionData));
    if (session_data == NULL) {
        return NULL;
    }

    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Initiating session data"
    );

    session_data->was_request_fully_inspected = 0;
    session_data->verdict = TRAFFIC_VERDICT_INSPECT;
    session_data->session_id = session_id;
    session_data->remaining_messages_to_reply = 0;
    session_data->req_proccesing_time = 0;
    session_data->res_proccesing_time = 0;
    session_data->processed_req_body_size = 0;
    session_data->processed_res_body_size = 0;

    return session_data;
};

void
FiniSessionData(NanoAttachment *attachment, HttpSessionData *session_data)
{
    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_DEBUG,
        "Freeing session data for session_id"
    );
    free(session_data);
};

void
UpdateMetric(NanoAttachment *attachment, AttachmentMetricType metric_type, uint64_t value)
{
    updateMetricField(attachment, metric_type, value);
}

void
SendAccumulatedMetricData(NanoAttachment *attachment)
{
    SendMetricData(attachment);
}

AttachmentVerdictResponse
SendDataNanoAttachment(NanoAttachment *attachment, AttachmentData *data)
{
    switch (data->chunk_type) {
        case HTTP_REQUEST_FILTER: {
            return SendRequestFilter(attachment, data);
        }
        case HTTP_REQUEST_METADATA: {
            return SendMetadata(attachment, data);
        }
        case HTTP_REQUEST_HEADER: {
            return SendRequestHeaders(attachment, data);
        }
        case HTTP_REQUEST_BODY: {
            return SendRequestBody(attachment, data);
        }
        case HTTP_REQUEST_END: {
            return SendRequestEnd(attachment, data);
        }
        case HTTP_RESPONSE_HEADER: {
            return SendResponseHeaders(attachment, data);
        }
        case HTTP_RESPONSE_BODY: {
            return SendResponseBody(attachment, data);
        }
        case HTTP_RESPONSE_END: {
            return SendResponseEnd(attachment, data);
        }
        default:
            break;
    }

    AttachmentVerdictResponse response = {
        .verdict = ATTACHMENT_VERDICT_INSPECT,
        .session_id = data->session_id,
        .modifications = NULL
    };
    return response;
}

// LCOV_EXCL_START Reason: Simple wrapper.
AttachmentVerdictResponse SendDataNanoAttachmentWrapper(NanoAttachment *attachment, AttachmentData data)
{
    return SendDataNanoAttachment(attachment, &data);
}
// LCOV_EXCL_STOP

///
/// @brief Connects to the keep-alive socket.
///
/// @param attachment A pointer to a NanoAttachment struct containing attachment information.
///
/// @return An int representing an opened socket, if failed returns -1.
///
static int
connect_to_keep_alive_socket(NanoAttachment *attachment)
{
    struct sockaddr_un server;
    int keep_alive_socket;

    // Connect a new socket.
    keep_alive_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (keep_alive_socket < 0) {
        write_dbg(
            attachment,
            attachment->worker_id,
            DBG_LEVEL_WARNING,
            "Could not create socket, Error: %s",
            strerror(errno)
        );
        return keep_alive_socket;
    }

    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, SHARED_KEEP_ALIVE_PATH, sizeof(server.sun_path) - 1);

    if (connect(keep_alive_socket, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) != -1 ) {
        return keep_alive_socket;
    }

    write_dbg(
        attachment,
        attachment->worker_id,
        DBG_LEVEL_DEBUG,
        "Could not connect to nano service. Path: %s, Error: %s, Errno: %d",
        server.sun_path,
        strerror(errno),
        errno
    );
    close(keep_alive_socket);

    return -1;
}

///
/// @brief Sends the keep-alive signal to the alive socket.
///
/// @param attachment A pointer to a NanoAttachment struct containing attachment information.
/// @param keep_alive_socket Socket descriptor for the keep-alive socket.
///
/// @return A NanoCommunicationResult indicating the result of the communication operation.
///
static NanoCommunicationResult
send_keep_alive_to_alive_socket(NanoAttachment *attachment, int keep_alive_socket)
{
    uint8_t container_id_size = strlen(attachment->container_id);
    struct timeval timeout = get_absolute_timeout_val_sec(1);
    NanoCommunicationResult res;

    // Exchanging worker id with the nano service.
    res = write_to_service(
        attachment,
        &keep_alive_socket,
        &attachment->worker_id,
        sizeof(attachment->worker_id),
        &timeout
    );
    if (res != NANO_OK) {
        // Failed to send worker id
        write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to send worker id");
        return NANO_ERROR;
    }

    // Exchanging container id size with the nano service.
    res = write_to_service(
        attachment,
        &keep_alive_socket,
        &container_id_size,
        sizeof(container_id_size),
        &timeout
    );
    if (res != NANO_OK) {
        // Failed to send container id size.
        write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to send container id size");
        return NANO_ERROR;
    }

    if (container_id_size > 0) {
        // Exchanging container id with the nano service.
        res = write_to_service(
            attachment,
            &keep_alive_socket,
            attachment->container_id,
            container_id_size,
            &timeout
        );
        if (res != NANO_OK) {
            // Failed to send container id name.
            write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to send container id");
            return NANO_ERROR;
        }
    }

    return NANO_OK;
}

void
SendKeepAlive(NanoAttachment *attachment)
{
    int keep_alive_socket;
    NanoCommunicationResult res;

    write_dbg(
        attachment,
        attachment->worker_id,
        DBG_LEVEL_DEBUG,
        "Keep alive signal. Family id: %s, UID: %u",
        attachment->container_id,
        attachment->worker_id
    );

    keep_alive_socket = connect_to_keep_alive_socket(attachment);
    if (keep_alive_socket < 0) {
        write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to connect to keep alive socket");
        return;
    }

    write_dbg(
        attachment,
        attachment->worker_id,
        DBG_LEVEL_DEBUG,
        "connected to socket: %d. sending keep alive signals"
    );

    res = send_keep_alive_to_alive_socket(attachment, keep_alive_socket);
    if (res == NANO_ERROR) {
        write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to send keep alive data");
    }

    close(keep_alive_socket);
}

int
IsSessionFinalized(NanoAttachment *attachment, HttpSessionData *session_data)
{
    if (session_data->verdict == TRAFFIC_VERDICT_INSPECT) {
        write_dbg(
            attachment,
            attachment->worker_id,
            DBG_LEVEL_TRACE,
            "Inspecting data for session id: %d",
            session_data->session_id
        );
        return 0;
    }

    write_dbg(
        attachment,
        attachment->worker_id,
        DBG_LEVEL_TRACE,
        "Skipping already inspected for session id: %d",
        session_data->session_id
    );

    return 1;
}

NanoWebResponseType
GetWebResponseType(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
)
{
    if (response->web_response_data == NULL) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_WARNING,
            "Trying to get web response with no response object"
        );
        return NO_WEB_RESPONSE;
    }

    return response->web_response_data->web_response_type;
}

int
IsResponseWithModification(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
)
{
    int res = response->modifications != NULL;
    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_TRACE,
        "Response %s have modifications",
        res ? "does" : "does not"
    );

    return res;
}

NanoResponseModifications
GetResponseModifications(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
)
{
    if (response == NULL) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_WARNING,
            "Trying to get modifications with no response object"
        );
        return (NanoResponseModifications) {
            .modifications = NULL
        };
    }

    return (NanoResponseModifications) {
        .modifications = response->modifications
    };
}

BlockPageData
GetBlockPage(NanoAttachment *attachment, HttpSessionData *session_data, AttachmentVerdictResponse *response)
{
    WebResponseData *web_response_data = response->web_response_data;
    CustomResponseData *custom_response_data;

    if (web_response_data->web_response_type != CUSTOM_WEB_RESPONSE) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_WARNING,
            "Trying to generate custom block page with a non custom response object"
        );

        return (BlockPageData) {
            .response_code = 0,
            .title_prefix = { .len = 0, .data = NULL },
            .title = { .len = 0, .data = NULL },
            .body_prefix = { .len = 0, .data = NULL },
            .body = { .len = 0, .data = NULL },
            .uuid_prefix = { .len = 0, .data = NULL },
            .uuid = { .len = 0, .data = NULL },
            .uuid_suffix = { .len = 0, .data = NULL }
        };
    }

    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_TRACE,
        "Getting custom block page"
    );

    custom_response_data = (CustomResponseData *) web_response_data->data;
    return (BlockPageData) {
            .response_code = custom_response_data->response_code,
            .title_prefix = { .len = strlen(title_prefix), .data = (unsigned char *)title_prefix },
            .title = { .len = strlen((char *)custom_response_data->title), .data = custom_response_data->title },
            .body_prefix = { .len = strlen(body_prefix), .data = (unsigned char *)body_prefix },
            .body = { .len = strlen((char *)custom_response_data->body), .data = custom_response_data->body },
            .uuid_prefix = { .len = strlen(uuid_prefix), .data = (unsigned char *)uuid_prefix },
            .uuid = { .len = strlen((char *)web_response_data->uuid), .data = web_response_data->uuid },
            .uuid_suffix = { .len = strlen(uuid_suffix), .data = (unsigned char *)uuid_suffix }
    };
}


RedirectPageData
GetRedirectPage(NanoAttachment *attachment, HttpSessionData *session_data, AttachmentVerdictResponse *response)
{
    WebResponseData *web_response_data = response->web_response_data;
    RedirectData *redirect_data;

    if (web_response_data->web_response_type != REDIRECT_WEB_RESPONSE) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_WARNING,
            "Trying to generate custom block page with a non redirect response object"
        );

        return (RedirectPageData) {
            .redirect_location = { .len = 0, .data = NULL }
        };
    }

    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_TRACE,
        "Getting redirect data"
    );

    redirect_data = (RedirectData *) web_response_data->data;
    return (RedirectPageData) {
        .redirect_location = {
            .len = strlen((char*)redirect_data->redirect_location),
            .data = redirect_data->redirect_location
        }
    };
}

void
FreeAttachmentResponseContent(
    NanoAttachment *attachment,
    HttpSessionData *session_data,
    AttachmentVerdictResponse *response
)
{
    NanoHttpModificationList *current_modification;
    NanoHttpModificationList *modification_list;

    if (response == NULL) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_WARNING,
            "Attempting to free NULL response"
        );
        return;
    }

    write_dbg(
        attachment,
        session_data->session_id,
        DBG_LEVEL_TRACE,
        "Freeing AttachmentResponse object"
    );
    if (response->web_response_data != NULL) {
        write_dbg(
            attachment,
            session_data->session_id,
            DBG_LEVEL_TRACE,
            "Freeing custom web response data"
        );

        free(response->web_response_data->data);
        free(response->web_response_data);
        response->web_response_data = NULL;
    }

    if (response->modifications != NULL) {
        modification_list = response->modifications;
        while (modification_list) {
            write_dbg(
                attachment,
                session_data->session_id,
                DBG_LEVEL_TRACE,
                "Freeing modifications list"
            );
            current_modification = modification_list;
            modification_list = modification_list->next;
            free(current_modification);
        }
        response->modifications = NULL;
    }

    return;
}
