#ifndef __NANO_ATTACHMENT_COMMON_H__
#define __NANO_ATTACHMENT_COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <assert.h>

typedef uint32_t SessionID;
typedef void* DataBuffer;

#define MAX_NGINX_UID_LEN 32
#define MAX_SHARED_MEM_PATH_LEN 128
#define NUM_OF_NGINX_IPC_ELEMENTS 200
#define DEFAULT_KEEP_ALIVE_INTERVAL_MSEC 300000u
#define SHARED_MEM_PATH "/dev/shm/"
#define SHARED_REGISTRATION_SIGNAL_PATH SHARED_MEM_PATH "check-point/cp-nano-attachment-registration"
#define SHARED_KEEP_ALIVE_PATH SHARED_MEM_PATH "check-point/cp-nano-attachment-registration-expiration-socket"
#define SHARED_VERDICT_SIGNAL_PATH SHARED_MEM_PATH "check-point/cp-nano-http-transaction-handler"
#define SHARED_ATTACHMENT_CONF_PATH SHARED_MEM_PATH "cp_nano_http_attachment_conf"
#define DEFAULT_STATIC_RESOURCES_PATH SHARED_MEM_PATH "static_resources"
#define INJECT_POS_IRRELEVANT -1
#define CORRUPTED_SESSION_ID 0
#define METRIC_PERIODIC_TIMEOUT 600
#define MAX_CONTAINER_ID_LEN 12
#define CONTAINER_ID_FILE_PATH "/proc/self/cgroup"
#define RESPONSE_PAGE_PARTS 4
#define UUID_SIZE 64
#define CUSTOM_RESPONSE_TITLE_SIZE 64
#define CUSTOM_RESPONSE_BODY_SIZE 128
#define REDIRECT_RESPONSE_LOCATION_SIZE 512

#ifdef __cplusplus
typedef enum class NanoWebResponseType
#else
typedef enum NanoWebResponseType
#endif
{
    CUSTOM_WEB_RESPONSE,
    REDIRECT_WEB_RESPONSE,

    NO_WEB_RESPONSE
} NanoWebResponseType;

#ifdef __cplusplus
typedef enum class NanoHttpInspectionMode
#else
typedef enum NanoHttpInspectionMode
#endif
{
    NON_BLOCKING_THREAD,
    BLOCKING_THREAD,
    NO_THREAD,

    INSPECTION_MODE_COUNT
} NanoHttpInspectionMode;

#ifdef __cplusplus
typedef enum class NanoCommunicationResult
#else
typedef enum NanoCommunicationResult
#endif
{
    NANO_OK,
    NANO_ERROR,
    NANO_ABORT,
    NANO_AGAIN,
    NANO_HTTP_FORBIDDEN,
    NANO_DECLINED,
    NANO_TIMEOUT
} NanoCommunicationResult;

#ifdef __cplusplus
typedef enum class nano_http_cp_debug_level
#else
typedef enum nano_http_cp_debug_level
#endif
{
    DBG_LEVEL_TRACE,
    DBG_LEVEL_DEBUG,
    DBG_LEVEL_INFO,
    DBG_LEVEL_WARNING,
    DBG_LEVEL_ERROR,
#ifndef __cplusplus
    DBG_LEVEL_ASSERT,
#endif
    DBG_LEVEL_COUNT
} nano_http_cp_debug_level_e;

#ifdef __cplusplus
typedef enum class AttachmentMetricType
#else
typedef enum AttachmentMetricType
#endif
{
    TRANSPARENTS_COUNT,
    TOTAL_TRANSPARENTS_TIME,
    INSPECTION_OPEN_FAILURES_COUNT,
    INSPECTION_CLOSE_FAILURES_COUNT,
    INSPECTION_SUCCESSES_COUNT,
    INJECT_VERDICTS_COUNT,
    DROP_VERDICTS_COUNT,
    ACCEPT_VERDICTS_COUNT,
    IRRELEVANT_VERDICTS_COUNT,
    RECONF_VERDICTS_COUNT,
    INSPECT_VERDICTS_COUNT,
    HOLD_VERDICTS_COUNT,
    AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    THREAD_TIMEOUT,
    REG_THREAD_TIMEOUT,
    REQ_METADATA_THREAD_TIMEOUT,
    REQ_HEADER_THREAD_TIMEOUT,
    REQ_BODY_THREAD_TIMEOUT,
    REQ_END_THREAD_TIMEOUT,
    AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT,
    MAX_REQ_BODY_SIZE_UPON_TIMEOUT,
    MIN_REQ_BODY_SIZE_UPON_TIMEOUT,
    RES_HEADER_THREAD_TIMEOUT,
    RES_BODY_THREAD_TIMEOUT,
    RES_END_THREAD_TIMEOUT,
    HOLD_THREAD_TIMEOUT,
    AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT,
    MAX_RES_BODY_SIZE_UPON_TIMEOUT,
    MIN_RES_BODY_SIZE_UPON_TIMEOUT,
    THREAD_FAILURE,
    REQ_PROCCESSING_TIMEOUT,
    RES_PROCCESSING_TIMEOUT,
    REQ_FAILED_TO_REACH_UPSTREAM,
    REQ_FAILED_COMPRESSION_COUNT,
    RES_FAILED_COMPRESSION_COUNT,
    REQ_FAILED_DECOMPRESSION_COUNT,
    RES_FAILED_DECOMPRESSION_COUNT,
    REQ_SUCCESSFUL_COMPRESSION_COUNT,
    RES_SUCCESSFUL_COMPRESSION_COUNT,
    REQ_SUCCESSFUL_DECOMPRESSION_COUNT,
    RES_SUCCESSFUL_DECOMPRESSION_COUNT,
    CORRUPTED_ZIP_SKIPPED_SESSION_COUNT,
    CPU_USAGE,
    AVERAGE_VM_MEMORY_USAGE,
    AVERAGE_RSS_MEMORY_USAGE,
    MAX_VM_MEMORY_USAGE,
    MAX_RSS_MEMORY_USAGE,
    REQUEST_OVERALL_SIZE_COUNT,
    RESPONSE_OVERALL_SIZE_COUNT,

    METRIC_TYPES_COUNT
} AttachmentMetricType;

#ifdef __cplusplus
typedef enum class AttachmentDataType
#else
typedef enum AttachmentDataType
#endif
{
    REQUEST_START,
    REQUEST_HEADER,
    REQUEST_BODY,
    REQUEST_END,
    RESPONSE_CODE,
    RESPONSE_HEADER,
    RESPONSE_BODY,
    RESPONSE_END,
    CONTENT_LENGTH,
    METRIC_DATA_FROM_PLUGIN,
    REQUEST_DELAYED_VERDICT
} AttachmentDataType;

#ifdef __cplusplus
typedef enum class HttpChunkType
#else
typedef enum HttpChunkType
#endif
{
    HTTP_REQUEST_FILTER,
    HTTP_REQUEST_METADATA,
    HTTP_REQUEST_HEADER,
    HTTP_REQUEST_BODY,
    HTTP_REQUEST_END,
    HTTP_RESPONSE_HEADER,
    HTTP_RESPONSE_BODY,
    HTTP_RESPONSE_END,
    HOLD_DATA
} HttpChunkType;

#ifdef __cplusplus
typedef enum class ServiceVerdict
#else
typedef enum ServiceVerdict
#endif
{
    TRAFFIC_VERDICT_INSPECT,
    TRAFFIC_VERDICT_ACCEPT,
    TRAFFIC_VERDICT_DROP,
    TRAFFIC_VERDICT_INJECT,
    TRAFFIC_VERDICT_IRRELEVANT,
    TRAFFIC_VERDICT_RECONF,
    TRAFFIC_VERDICT_DELAYED
} ServiceVerdict;

#ifdef __cplusplus
typedef enum class AttachmentVerdict
#else
typedef enum AttachmentVerdict
#endif
{
    ATTACHMENT_VERDICT_INSPECT,
    ATTACHMENT_VERDICT_ACCEPT,
    ATTACHMENT_VERDICT_DROP,
    ATTACHMENT_VERDICT_INJECT
} AttachmentVerdict;

#ifdef __cplusplus
typedef enum class HttpModificationType
#else
typedef enum HttpModificationType
#endif
{
    APPEND,
    INJECT,
    REPLACE
} HttpModificationType;

typedef struct __attribute__((__packed__)) HttpInjectData {
    int64_t injection_pos;
    HttpModificationType mod_type;
    uint16_t injection_size;
    uint8_t is_header;
    uint8_t orig_buff_index;
    char data[0];
} HttpInjectData;

typedef struct __attribute__((__packed__)) HttpWebResponseData {
    uint8_t web_response_type;
    uint8_t uuid_size;

    union {
        struct __attribute__((__packed__)) NanoHttpCpCustomWebResponseData {
            uint16_t response_code;
            uint8_t title_size;
            uint8_t body_size;
            char data[0];
        } custom_response_data;

        struct __attribute__((__packed__)) NanoHttpCpRedirectData {
            uint8_t unused_dummy;
            uint8_t add_event_id;
            uint16_t redirect_location_size;
            char redirect_location[0];
        } redirect_data;
    } response_data;
} HttpWebResponseData;

typedef struct {
    size_t              len;
    unsigned char       *data;
} nano_str_t;

typedef struct CustomResponseData {
    uint16_t response_code;
    unsigned char title[CUSTOM_RESPONSE_TITLE_SIZE];
    unsigned char body[CUSTOM_RESPONSE_BODY_SIZE];
} CustomResponseData;

typedef struct RedirectData {
    unsigned char redirect_location[REDIRECT_RESPONSE_LOCATION_SIZE];
} RedirectData;

typedef struct WebResponseData {
    NanoWebResponseType web_response_type;
    unsigned char uuid[UUID_SIZE];
    DataBuffer data;
} WebResponseData;

#ifdef __cplusplus
typedef enum class HttpMetaDataType
#else
typedef enum HttpMetaDataType
#endif
{
    HTTP_PROTOCOL_SIZE,
    HTTP_PROTOCOL_DATA,
    HTTP_METHOD_SIZE,
    HTTP_METHOD_DATA,
    HOST_NAME_SIZE,
    HOST_NAME_DATA,
    LISTENING_ADDR_SIZE,
    LISTENING_ADDR_DATA,
    LISTENING_PORT,
    URI_SIZE,
    URI_DATA,
    CLIENT_ADDR_SIZE,
    CLIENT_ADDR_DATA,
    CLIENT_PORT,
    PARSED_HOST_SIZE,
    PARSED_HOST_DATA,
    PARSED_URI_SIZE,
    PARSED_URI_DATA,

    META_DATA_COUNT
} HttpMetaDataType;

#ifdef __cplusplus
typedef enum class HttpHeaderDataType
#else
typedef enum HttpHeaderDataType
#endif
{
    HEADER_KEY_SIZE,
    HEADER_KEY_DATA,
    HEADER_VAL_SIZE,
    HEADER_VAL_DATA,

    HEADER_DATA_COUNT
} HttpHeaderDataType;

/// @struct NanoHttpModificationList
/// @brief A node that holds all the information regarding modifications.
typedef struct NanoHttpModificationList {
    struct NanoHttpModificationList *next; ///< Next node.
    HttpInjectData modification; ///< Modification data.
    char *modification_buffer; ///< Modification buffer used to store extra needed data.
} NanoHttpModificationList;

/// @struct HttpSessionData
/// @brief Holds all the session's information needed to communicate with the nano service.
/// @details Such as to save verdict and session ID between the request and the response
typedef struct HttpSessionData {
    int                    was_request_fully_inspected; ///< Holds if the request fully inspected.
    ServiceVerdict         verdict; ///< Holds the session's verdict from the Nano Service.
    uint32_t               session_id; ///< Current session's Id.
    unsigned int           remaining_messages_to_reply; ///< Remaining messages left for the agent to respond to.

    // NanoHttpResponseData_t response_data; ///< Holds session's response data.

    double                 req_proccesing_time; ///< Holds session's request processing time.
    double                 res_proccesing_time; ///< Holds session's response processing time.
    uint64_t               processed_req_body_size; ///< Holds session's request body's size.
    uint64_t               processed_res_body_size; ///< Holds session's response body's size'.
} HttpSessionData;

typedef struct HttpMetaData {
    nano_str_t http_protocol;
    nano_str_t method_name;
    nano_str_t host;
    nano_str_t listening_ip;
    uint16_t   listening_port;
    nano_str_t uri;
    nano_str_t client_ip;
    uint16_t   client_port;
    nano_str_t parsed_host;
    nano_str_t parsed_uri;
} HttpMetaData;

typedef struct HttpHeaderData {
    nano_str_t key;
    nano_str_t value;
} HttpHeaderData;

typedef struct HttpHeaders {
    HttpHeaderData *data;
    size_t headers_count;
} HttpHeaders;

typedef struct HttpRequestFilterData {
    HttpMetaData *meta_data;
    HttpHeaders *req_headers;
    bool contains_body;
} HttpRequestFilterData;

typedef struct ResHttpHeaders {
    HttpHeaders *headers;
    uint16_t response_code;
    uint64_t content_length;
} ResHttpHeaders;

typedef struct HttpBody {
    nano_str_t *data;
    size_t bodies_count;
} HttpBody;

typedef struct AttachmentData {
    SessionID session_id;
    HttpChunkType chunk_type;
    HttpSessionData *session_data;
    DataBuffer data;
} AttachmentData;

typedef union __attribute__((__packed__)) HttpModifyData {
    HttpInjectData inject_data[0];
    HttpWebResponseData web_response_data[0];
} HttpModifyData;

typedef struct __attribute__((__packed__)) HttpReplyFromService {
    uint16_t verdict;
    SessionID session_id;
    uint8_t modification_count;
    HttpModifyData modify_data[0];
} HttpReplyFromService;

typedef struct AttachmentVerdictResponse {
    AttachmentVerdict verdict;
    SessionID session_id;
    WebResponseData *web_response_data;
    NanoHttpModificationList *modifications;
} AttachmentVerdictResponse;

typedef struct __attribute__((__packed__)) AttachmentRequest {
    struct __attribute__((__packed__)) connection {
        int sockaddr;
        int local_sockaddr;
    } connection;

    struct __attribute__((__packed__)) http_protocol {
        int len;
        int data;
    } http_protocol;

    struct __attribute__((__packed__)) method {
        int name;
        int data;
    } method;

    struct __attribute__((__packed__)) uri {
        int len;
        int data;
    } uri;

    struct __attribute__((__packed__)) unparsed_uri {
        int len;
        int data;
    } unparsed_uri;
} AttachmentRequest;

typedef struct BlockPageData {
    uint16_t response_code;
    nano_str_t title_prefix;
    nano_str_t title;
    nano_str_t body_prefix;
    nano_str_t body;
    nano_str_t uuid_prefix;
    nano_str_t uuid;
    nano_str_t uuid_suffix;
} BlockPageData;

typedef struct RedirectPageData {
    nano_str_t redirect_location;
} RedirectPageData;

typedef struct NanoResponseModifications {
    NanoHttpModificationList *modifications;
} NanoResponseModifications;

typedef struct __attribute__((__packed__)) NanoHttpMetricData {
    uint16_t data_type;
#ifdef __cplusplus
    uint64_t data[static_cast<int>(AttachmentMetricType::METRIC_TYPES_COUNT)];
#else
    uint64_t data[METRIC_TYPES_COUNT];
#endif
} NanoHttpMetricData;

#endif // __NANO_ATTACHMENT_COMMON_H__
