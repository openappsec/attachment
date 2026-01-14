#include "nano_attachment_sender_async.h"

#include "nano_attachment_common.h"
#include "nano_initializer.h"

NanoCommunicationResult
RegistrationCommSocketAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
RegistrationSocketAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendRequestFilterAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpRequestFilterData *start_data
)
{
    (void)attachment;
    (void)session_data_p;
    (void)start_data;
    return NANO_OK;
}

NanoCommunicationResult
SendMetadataAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpMetaData *metadata
)
{
    (void)attachment;
    (void)session_data_p;
    (void)metadata;
    return NANO_OK;
}

NanoCommunicationResult
SendRequestHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    HttpHeaders *headers
)
{
    (void)attachment;
    (void)session_data_p;
    (void)headers;
    return NANO_OK;
}

NanoCommunicationResult
SendResponseHeadersAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    ResHttpHeaders *headers
)
{
    (void)attachment;
    (void)session_data_p;
    (void)headers;
    return NANO_OK;
}

NanoCommunicationResult
SendRequestBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
)
{
    (void)attachment;
    (void)session_data_p;
    (void)bodies;
    return NANO_OK;
}

NanoCommunicationResult
SendResponseBodyAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p,
    NanoHttpBody *bodies
)
{
    (void)attachment;
    (void)session_data_p;
    (void)bodies;
    return NANO_OK;
}

NanoCommunicationResult
SendRequestEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendResponseEndAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendDelayedVerdictRequestAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}

NanoCommunicationResult
SendMetricToServiceAsyncImpl(
    NanoAttachment *attachment,
    HttpSessionData *session_data_p
)
{
    (void)attachment;
    (void)session_data_p;
    return NANO_OK;
}
