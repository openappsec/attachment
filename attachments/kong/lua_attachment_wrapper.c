#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>
#include <stdlib.h>
#include "nano_attachment.h"
#include "nano_attachment_common.h"

#define MAX_HEADERS 10000

// Initialize NanoAttachment for worker
static int lua_init_nano_attachment(lua_State *L) {
    int worker_id = luaL_checkinteger(L, 1);
    int num_workers = luaL_checkinteger(L, 2);

    NanoAttachment* attachment = InitNanoAttachment(0, worker_id, num_workers, fileno(stdout));
    if (!attachment) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize NanoAttachment");
        return 2;
    }

    lua_pushlightuserdata(L, attachment);
    return 1;
}

static int lua_get_web_response_type(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*)lua_touserdata(L, 1);
    HttpSessionData* session_data = (HttpSessionData*)lua_touserdata(L, 2);
    AttachmentVerdictResponse* response = (AttachmentVerdictResponse*)lua_touserdata(L, 3);

    if (!attachment || !session_data || !response) {
        return luaL_error(L, "invalid args to get_web_response_type");
    }

    NanoWebResponseType type = GetWebResponseType(attachment, session_data, response);
    lua_pushinteger(L, type);
    return 1;
}


static int lua_get_response_code(lua_State *L) {
    AttachmentVerdictResponse* response = (AttachmentVerdictResponse*)lua_touserdata(L, 1);
    if (!response) {
        return luaL_error(L, "invalid response");
    }

    int code = GetResponseCode(response);
    lua_pushinteger(L, code);
    return 1;
}

static int lua_get_block_page(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*)lua_touserdata(L, 1);
    HttpSessionData* session_data = (HttpSessionData*)lua_touserdata(L, 2);
    AttachmentVerdictResponse* response = (AttachmentVerdictResponse*)lua_touserdata(L, 3);

    if (!attachment || !session_data || !response) {
        return luaL_error(L, "invalid args to get_block_page");
    }

    BlockPageData page = GetBlockPage(attachment, session_data, response);
    size_t size = page.title_prefix.len + page.title.len +
        page.body_prefix.len + page.body.len +
        page.uuid_prefix.len + page.uuid.len + page.uuid_suffix.len;

    char *result = malloc(size + 1);
    if (!result) {
        return luaL_error(L, "memory allocation failed");
    }

    int offset = 0;
    memcpy(result + offset, page.title_prefix.data, page.title_prefix.len); offset += page.title_prefix.len;
    memcpy(result + offset, page.title.data, page.title.len); offset += page.title.len;
    memcpy(result + offset, page.body_prefix.data, page.body_prefix.len); offset += page.body_prefix.len;
    memcpy(result + offset, page.body.data, page.body.len); offset += page.body.len;
    memcpy(result + offset, page.uuid_prefix.data, page.uuid_prefix.len); offset += page.uuid_prefix.len;
    memcpy(result + offset, page.uuid.data, page.uuid.len); offset += page.uuid.len;
    memcpy(result + offset, page.uuid_suffix.data, page.uuid_suffix.len); offset += page.uuid_suffix.len;
    result[size] = '\0';

    lua_pushlstring(L, result, size);
    free(result);
    return 1;
}

static int lua_get_redirect_page(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*)lua_touserdata(L, 1);
    HttpSessionData* session_data = (HttpSessionData*)lua_touserdata(L, 2);
    AttachmentVerdictResponse* response = (AttachmentVerdictResponse*)lua_touserdata(L, 3);

    if (!attachment || !session_data || !response) {
        return luaL_error(L, "invalid args to get_redirect_page");
    }

    RedirectPageData data = GetRedirectPage(attachment, session_data, response);
    lua_pushlstring(L, (const char*)data.redirect_location.data, data.redirect_location.len);
    return 1;
}


// Allocate memory for nano_str_t (long-lived, must be freed later)
static int lua_createNanoStrAlloc(lua_State *L) {
    const char* str = luaL_checkstring(L, 1);
    if (!str) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid string input");
        return 2;
    }

    char* c_str = strdup(str);
    if (!c_str) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to allocate memory for string");
        return 2;
}

    nano_str_t* nanoStr = (nano_str_t*)malloc(sizeof(nano_str_t));
    if (!nanoStr) {
        free(c_str); // Clean up already allocated string
        lua_pushnil(L);
        lua_pushstring(L, "Failed to allocate memory for nano_str_t");
        return 2;
    }

    nanoStr->len = strlen(str);
    nanoStr->data = (unsigned char*)c_str;

    lua_pushlightuserdata(L, nanoStr);
    return 1;
}

// Free nano_str_t (Memory cleanup)
static int lua_freeNanoStr(lua_State *L) {
    nano_str_t* nanoStr = (nano_str_t*)lua_touserdata(L, 1);
    if (nanoStr) {
        free(nanoStr->data);
        free(nanoStr);
    }
    return 0;
}

// Allocate memory for HttpHeaders
// Allocate memory for HttpHeaders
static int lua_allocHttpHeaders(lua_State *L) {
    size_t max_headers = 10000;

    HttpHeaders* headers = (HttpHeaders*)malloc(sizeof(HttpHeaders));
    if (!headers) {
        return luaL_error(L, "Memory allocation failed for HttpHeaders");
    }

    headers->data = (HttpHeaderData*)malloc(max_headers * sizeof(HttpHeaderData));
    if (!headers->data) {
        free(headers);
        return luaL_error(L, "Memory allocation failed for HttpHeaderData");
    }

    headers->headers_count = 0;

    lua_pushlightuserdata(L, headers);
    return 1;
}

// Free HttpHeaders memory
static int lua_freeHttpHeaders(lua_State *L) {
    HttpHeaders* headers = (HttpHeaders*)lua_touserdata(L, 1);
    if (headers) {
        free(headers->data);
        free(headers);
    }
    return 0;
}

// Set the headers_count in HttpHeaders
static int lua_setHeaderCount(lua_State *L) {
    HttpHeaders* headers = (HttpHeaders*)lua_touserdata(L, 1);
    int count = luaL_checkinteger(L, 2);

    if (!headers) {
        return 0;
    }

    headers->headers_count = count;
    return 0;
}

// Helper function to convert Lua string to nano_str_t
static void lua_fill_nano_str(lua_State *L, int index, nano_str_t *nano_str) {
    size_t len;
    const char *str = luaL_checklstring(L, index, &len);

    if (!str) {
        nano_str->data = NULL;
        nano_str->len = 0;
        return;
    }

    // Allocate memory + 1 for null termination
    nano_str->data = (char *)malloc(len + 1);

    if (!nano_str->data) {  // Check if allocation failed
        nano_str->len = 0;
        return;
    }

    memcpy(nano_str->data, str, len);  // Copy exact `len` bytes
    nano_str->data[len] = '\0';  // Manually null-terminate
    nano_str->len = len;
}

static int lua_free_http_metadata(lua_State *L) {
    HttpMetaData *metadata = *(HttpMetaData **)lua_touserdata(L, 1);
    if (!metadata) return 0;

    free(metadata->http_protocol.data);
    free(metadata->method_name.data);
    free(metadata->host.data);
    free(metadata->listening_ip.data);
    free(metadata->uri.data);
    free(metadata->client_ip.data);
    free(metadata->parsed_host.data);
    free(metadata->parsed_uri.data);
    free(metadata);

    return 0;
}

// Set a header element in HttpHeaderData
static int lua_setHeaderElement(lua_State *L) {
    HttpHeaders *headers = (HttpHeaders *)lua_touserdata(L, 1);
    int index = luaL_checkinteger(L, 2);

    if (!headers || index >= MAX_HEADERS) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // Safely allocate and set header key/value
    lua_fill_nano_str(L, 3, &headers->data[index].key);
    lua_fill_nano_str(L, 4, &headers->data[index].value);

    lua_pushboolean(L, 1);
    return 1;
}

// Initialize session
static int lua_init_session(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    SessionID session_id = luaL_checkinteger(L, 2);

    if (!attachment) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid nano_attachment");
        return 2;
    }

    HttpSessionData* session_data = InitSessionData(attachment, session_id);
    if (!session_data) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize session data");
        return 2;
    }

    lua_pushlightuserdata(L, session_data);
    return 1;
}

// Finalize session
static int lua_fini_session(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    HttpSessionData* session_data = lua_touserdata(L, 2);

    if (!attachment || !session_data) {
        lua_pushnil(L);
        lua_pushstring(L, "Error: Invalid attachment or session_data");
        return 2;
    }

    FiniSessionData(attachment, session_data);
    lua_pushboolean(L, 1);
    return 1;
}

// Check if session is finalized
static int lua_is_session_finalized(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    HttpSessionData* session_data = (HttpSessionData*) lua_touserdata(L, 2);

    if (!attachment || !session_data) {
        lua_pushboolean(L, 0);
        return 1;
    }

    int result = IsSessionFinalized(attachment, session_data);
    lua_pushboolean(L, result);
    return 1;
}

// Function to extract request metadata and create HttpMetaData struct
static int lua_create_http_metadata(lua_State *L) {
    HttpMetaData *metadata = (HttpMetaData *)malloc(sizeof(HttpMetaData));
    if (!metadata) {
        return luaL_error(L, "Memory allocation failed");
    }

    lua_fill_nano_str(L, 1, &metadata->http_protocol);
    lua_fill_nano_str(L, 2, &metadata->method_name);
    lua_fill_nano_str(L, 3, &metadata->host);
    lua_fill_nano_str(L, 4, &metadata->listening_ip);
    metadata->listening_port = (uint16_t)luaL_checkinteger(L, 5);
    lua_fill_nano_str(L, 6, &metadata->uri);
    lua_fill_nano_str(L, 7, &metadata->client_ip);
    metadata->client_port = (uint16_t)luaL_checkinteger(L, 8);
    lua_fill_nano_str(L, 9, &metadata->parsed_host);
    lua_fill_nano_str(L, 10, &metadata->parsed_uri);

    // Store pointer in Lua
    lua_pushlightuserdata(L, metadata);
    return 1;  // Return userdata
}

// Send data to NanoAttachment
static int lua_send_data(lua_State *L) {
    // Retrieve function arguments from Lua
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    SessionID session_id = luaL_checkinteger(L, 2);
    HttpSessionData *session_data = (HttpSessionData*) lua_touserdata(L, 3);
    HttpChunkType chunk_type = luaL_checkinteger(L, 4);
    HttpMetaData* meta_data = (HttpMetaData*) lua_touserdata(L, 5);
    HttpHeaders* req_headers = (HttpHeaders*) lua_touserdata(L, 6);
    int contains_body = luaL_checkinteger(L, 7);  // Convert Lua boolean to C int
    //int contains_body = 0;

    // Validate inputs
    if (!attachment || !session_data || !meta_data || !req_headers) {
        lua_pushstring(L, "Error: received NULL data in lua_send_data");
        return lua_error(L);
    }

    // Allocate memory for HttpRequestFilterData
    HttpRequestFilterData *filter_data = (HttpRequestFilterData *)malloc(sizeof(HttpRequestFilterData));
    if (!filter_data) {
        return luaL_error(L, "Memory allocation failed for HttpRequestFilterData");
    }

    // Populate HttpRequestFilterData struct
    filter_data->meta_data = meta_data;
    filter_data->req_headers = req_headers;
    filter_data->contains_body = contains_body;

    // Create attachment data
    AttachmentData attachment_data;
    attachment_data.session_id = session_id;
    attachment_data.session_data = session_data;
    attachment_data.chunk_type = chunk_type;
    attachment_data.data = (void*)filter_data;

    AttachmentVerdictResponse* res_ptr = malloc(sizeof(AttachmentVerdictResponse));
    *res_ptr = SendDataNanoAttachment(attachment, &attachment_data);

    // Free allocated memory
    free(filter_data);

    lua_pushinteger(L, res_ptr->verdict);
    lua_pushlightuserdata(L, res_ptr);
    return 2;
}

static int lua_send_body(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    SessionID session_id = luaL_checkinteger(L, 2);
    HttpSessionData *session_data = (HttpSessionData*) lua_touserdata(L, 3);
    size_t body_len;
    const char *body_chunk = luaL_checklstring(L, 4, &body_len);
    HttpChunkType chunk_type = luaL_checkinteger(L, 5);

    if (!attachment || !session_data || !body_chunk) {
        lua_pushstring(L, "Error: Invalid attachment or session_data");
        return lua_error(L);
    }

    // For small bodies, send as a single chunk
    if (body_len <= 8 * 1024) {
        HttpBody http_chunks;
        http_chunks.bodies_count = 1;
        
        nano_str_t chunk;
        chunk.data = (unsigned char*)body_chunk;
        chunk.len = body_len;
        http_chunks.data = &chunk;

        AttachmentData attachment_data;
        attachment_data.session_id = session_id;
        attachment_data.session_data = session_data;
        attachment_data.chunk_type = chunk_type;
        attachment_data.data = &http_chunks;

        AttachmentVerdictResponse* res_ptr = malloc(sizeof(AttachmentVerdictResponse));
        *res_ptr = SendDataNanoAttachment(attachment, &attachment_data);
        
        // Push verdict
        lua_pushinteger(L, res_ptr->verdict);
        lua_pushlightuserdata(L, res_ptr);
        
        // Push modifications if they exist
        if (res_ptr->modifications) {
            lua_pushlightuserdata(L, res_ptr->modifications);
        } else {
            lua_pushnil(L);
        }
        
        return 3;
    }

    // Calculate number of chunks (8KB each, like Envoy)
    const size_t CHUNK_SIZE = 8 * 1024;
    size_t num_chunks = ((body_len - 1) / CHUNK_SIZE) + 1;

    // Limit number of chunks like Envoy
    if (num_chunks > 10000) {
        num_chunks = 10000;
    }

    // Create HttpBody structure
    HttpBody http_chunks;
    http_chunks.bodies_count = num_chunks;

    // Allocate memory for chunks array
    http_chunks.data = (nano_str_t*)malloc(num_chunks * sizeof(nano_str_t));
    if (!http_chunks.data) {
        lua_pushstring(L, "Error: Failed to allocate memory for chunks");
        return lua_error(L);
    }

    // Prepare chunks using pointer arithmetic like Envoy
    for (size_t i = 0; i < num_chunks; i++) {
        nano_str_t* chunk_ptr = (nano_str_t*)((char*)http_chunks.data + (i * sizeof(nano_str_t)));
        size_t chunk_start = i * CHUNK_SIZE;
        size_t chunk_len = (i == num_chunks - 1) ? (body_len - chunk_start) : CHUNK_SIZE;
        
        chunk_ptr->data = (unsigned char*)(body_chunk + chunk_start);
        chunk_ptr->len = chunk_len;
    }

    // Prepare attachment data
    AttachmentData attachment_data;
    attachment_data.session_id = session_id;
    attachment_data.session_data = session_data;
    attachment_data.chunk_type = chunk_type;
    attachment_data.data = &http_chunks;

    // Send all chunks at once
    AttachmentVerdictResponse* res_ptr = malloc(sizeof(AttachmentVerdictResponse));
    *res_ptr = SendDataNanoAttachment(attachment, &attachment_data);

    // Free allocated memory
    free(http_chunks.data);

    // Push verdict
    lua_pushinteger(L, res_ptr->verdict);
    lua_pushlightuserdata(L, res_ptr);

    // Push modifications if they exist
    if (res_ptr->modifications) {
        lua_pushlightuserdata(L, res_ptr->modifications);
    } else {
        lua_pushnil(L);
    }
    
    return 3;
}

static int lua_end_inspection(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    SessionID session_id = luaL_checkinteger(L, 2);
    HttpSessionData* session_data = (HttpSessionData*) lua_touserdata(L, 3);
    HttpChunkType chunk_type = luaL_checkinteger(L, 4);

    if (!attachment || !session_data) {
        lua_pushstring(L, "Error: Invalid attachment or session_data");
        return lua_error(L);
    }

    AttachmentData attachment_data;
    attachment_data.session_id = session_id;
    attachment_data.session_data = session_data;
    attachment_data.chunk_type = chunk_type;
    attachment_data.data = NULL;

    // Send NULL to indicate end of data
    AttachmentVerdictResponse* res_ptr = malloc(sizeof(AttachmentVerdictResponse));
    *res_ptr = SendDataNanoAttachment(attachment, &attachment_data);

    lua_pushinteger(L, res_ptr->verdict);
    lua_pushlightuserdata(L, res_ptr);

    return 2;
}

// Send response headers to NanoAttachment
static int lua_send_response_headers(lua_State *L) {
    NanoAttachment* attachment = (NanoAttachment*) lua_touserdata(L, 1);
    SessionID session_id = luaL_checkinteger(L, 2);
    HttpSessionData *session_data = (HttpSessionData*) lua_touserdata(L, 3);
    HttpHeaders *headers = (HttpHeaders*) lua_touserdata(L, 4);
    int status_code = luaL_checkinteger(L, 5);
    uint64_t content_length = luaL_checkinteger(L, 6);

    if (!attachment || !session_data || !headers) {
        lua_pushstring(L, "Error: Invalid attachment, session_data, or headers");
        return lua_error(L);
    }

    // Create ResHttpHeaders structure exactly as in filter.go
    ResHttpHeaders res_headers;
    res_headers.headers = headers;
    res_headers.response_code = status_code;
    res_headers.content_length = content_length;

    AttachmentData attachment_data;
    attachment_data.session_id = session_id;
    attachment_data.session_data = session_data;
    attachment_data.chunk_type = HTTP_RESPONSE_HEADER;
    attachment_data.data = &res_headers;

    AttachmentVerdictResponse* res_ptr = malloc(sizeof(AttachmentVerdictResponse));
    *res_ptr = SendDataNanoAttachment(attachment, &attachment_data);
    lua_pushinteger(L, res_ptr->verdict);
    lua_pushlightuserdata(L, res_ptr);
    return 2;
}

// Register functions in Lua
static const struct luaL_Reg nano_attachment_lib[] = {
    {"init_nano_attachment", lua_init_nano_attachment},
    {"get_web_response_type", lua_get_web_response_type},
    {"get_response_code", lua_get_response_code},
    {"get_block_page", lua_get_block_page},
    {"get_redirect_page", lua_get_redirect_page},
    {"createNanoStrAlloc", lua_createNanoStrAlloc},
    {"freeNanoStr", lua_freeNanoStr},
    {"setHeaderElement", lua_setHeaderElement},
    {"send_data", lua_send_data},
    {"send_response_headers", lua_send_response_headers},
    {"fini_session", lua_fini_session},
    {"is_session_finalized", lua_is_session_finalized},
    {"init_session", lua_init_session},
    {"allocHttpHeaders", lua_allocHttpHeaders},
    {"freeHttpHeaders", lua_freeHttpHeaders},
    {"setHeaderCount", lua_setHeaderCount},
    {"create_http_metadata", lua_create_http_metadata},
    {"send_body", lua_send_body},
    {"end_inspection", lua_end_inspection},
    {NULL, NULL}
};

// Load library
int luaopen_lua_attachment_wrapper(lua_State *L) {
    luaL_newlib(L, nano_attachment_lib);
    return 1;
}
