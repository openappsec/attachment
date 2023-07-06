// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ngx_cp_static_content.h"

#include <ngx_hash.h>

#include "ngx_cp_utils.h"
#include "ngx_cp_custom_response.h"

ngx_hash_t                static_resources_hash_table; ///< Holds all the static resources data.
ngx_int_t                 is_static_resources_table_initialized_var = 0; ///< A flag if static resources hash table was initialized.

static const ngx_int_t    not_a_static_resource = NOT_A_STATIC_RESOURCE; ///< Not a static resource variable.
static const unsigned int static_resource_res_headers_allow_ranges = 1; ///< Static resource result allow ranges.
static const unsigned int static_resource_res_headers_keepalive = 1; ///< Static resource result headers keep alive configuration.
static const ngx_int_t    static_resource_res_headers_response_code = NGX_HTTP_OK; ///< Static resource good result response.
static const ngx_int_t    default_max_hash_table_size = 512; ///< Maximum hash table size configuration.
static const ngx_int_t    default_hash_table_bucket_size = 64;
static const ngx_int_t    default_part_items_num = 100; ///< Default number of elements to be allocated for a static resources list during static resources initialization.
static const ngx_int_t    initial_hash_table_data_value = 1; ///< Initial value of initiated table data.

static ngx_hash_init_t    static_resources_hash_initializer; ///< NGINX Hash initialization settings.

///
/// @brief Get the static resources into the static_resources and return the number of resources.
/// @details Given a memory poll and static sources list. Attempts to open the static resource directory.
/// for each static data in the directory, allocate a new element in the static_resources list and load the
/// data into the new element.
/// @param[in, out] static_resources NGINX list of the static allocated resources.
/// @param[in, out] memory_pool NGINX pool used to allocate data into.
/// @return ngx_int_t - The number of allocated static resources.
///
static ngx_uint_t
get_static_resources(ngx_list_t *static_resources, ngx_pool_t *memory_pool)
{
    size_t num_static_resources = 0;
    struct dirent *current_entry = NULL;
    ngx_str_t *current_resource = NULL;
    const char *static_resources_path = get_static_resources_path();

    DIR *static_resources_directory = opendir(static_resources_path);
    if (static_resources_directory == NULL) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to open the static resources directory. Path: %s, error: %s",
            static_resources_path,
            strerror(errno)
        );
        return -1;
    }

    write_dbg(
        DBG_LEVEL_TRACE,
        "Successfully opened the static resources' directory: %s",
        static_resources_path
    );
    while ((current_entry = readdir (static_resources_directory)) != NULL) {
        // Iterates over the files in the static resources directory.
        // Allocates a new element to the list and initialize it given the resources data.
        if (strcmp(current_entry->d_name, ".") == 0 || strcmp(current_entry->d_name, "..") == 0) continue;

        current_resource = ngx_list_push(static_resources);
        if (current_resource == NULL) {
            write_dbg(
                DBG_LEVEL_ERROR,
                "Failed to allocate memory for a static resource path. Path: %s",
                static_resources_path
            );
            return -1;
        }
        write_dbg(DBG_LEVEL_TRACE, "Found static resource: %s", current_entry->d_name);

        // Load the read data from the file onto the current resource element.
        current_resource->len = strlen(current_entry->d_name);
        current_resource->data = ngx_palloc(memory_pool, current_resource->len + 1);
        ngx_memcpy(current_resource->data, current_entry->d_name, current_resource->len);
        current_resource->data[current_resource->len] = '\0';
        num_static_resources++;
    }
    closedir(static_resources_directory);

    return num_static_resources;
}

///
/// @brief Initiates static resources hash table with the provided data in static_resources.
/// @details Takes the provided variables and initiates the static hash table that
/// is used throughout the attachment.
/// @param[in, out] static_resources NGINX list - data to be initiated 
/// @param[in] num_static_resources The number of provided resources in static_resources.
/// @param[in, out] memory_pool NGINX pool used to allocate data into.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
init_static_web_resources_hash_table(
    ngx_list_t *static_resources,
    const size_t num_static_resources,
    ngx_pool_t *memory_pool
)
{
    ngx_int_t init_hash_table_result;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Received %u static web resources. Initializing the static resources table.",
        num_static_resources
    );
    
    // initiate the static hash table with the provided data in static_resources.
    init_hash_table_result = init_hash_table(
        memory_pool,
        &static_resources_hash_initializer,
        &static_resources_hash_table,
        "static resources",
        default_max_hash_table_size,
        default_hash_table_bucket_size,
        static_resources,
        &initial_hash_table_data_value,
        sizeof(initial_hash_table_data_value)
    );
    if (init_hash_table_result != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to initialize static resources table");
        free_list_from_pool(memory_pool, static_resources);
        return NGX_ERROR;
    }

    is_static_resources_table_initialized_var = 1;
    write_dbg(DBG_LEVEL_TRACE, "Successfully initialized the static resources table");

    return NGX_OK;
}

ngx_int_t
init_static_resources(ngx_pool_t *memory_pool)
{
    size_t num_static_resources;
    ngx_list_t *static_resources = ngx_list_create(memory_pool, default_part_items_num, sizeof(ngx_str_t));
    if (static_resources == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate the list of static resource paths");
        return NGX_ERROR;
    }

    // Read the static data saved into static_resources.
    num_static_resources = get_static_resources(static_resources, memory_pool);
    if (num_static_resources == (size_t)-1) {
        free_list_from_pool(memory_pool, static_resources);
        return NGX_ERROR;
    }
    if (num_static_resources == 0) {
        free_list_from_pool(memory_pool, static_resources);
        return NGX_OK;
    }

    // Initiate the static_resources_hash_table with static_resources data. 
    if (init_static_web_resources_hash_table(static_resources, num_static_resources, memory_pool) != NGX_OK) {
        free_list_from_pool(memory_pool, static_resources);
        return NGX_ERROR;
    }

    free_list_from_pool(memory_pool, static_resources);
    return NGX_OK;
}

ngx_int_t
is_static_resources_table_initialized(void)
{
    return is_static_resources_table_initialized_var;
}

///
/// @brief 
/// @param[in] null_terminated_uri Null terminated uri that holds the resource name.
/// @param[in, out] static_resource_name A variable to save data and len of the extracted resource name.
/// @returns ngx_int_t
///         - #1 Successed in getting a static resource name.
///         - #0 Failed to get static resource name.
///
ngx_int_t
get_static_resource_name(const ngx_str_t *null_terminated_uri, ngx_str_t *static_resource_name)
{
    size_t uri_prefix_length;
    u_char *last_uri_separator;

    // Skip past last "/"
    last_uri_separator = reverse_strnchr(null_terminated_uri->data, '/', null_terminated_uri->len);
    if (last_uri_separator == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Invalid URI in HTTP request, URI: %s", null_terminated_uri->data);
        return 0;
    }

    uri_prefix_length = last_uri_separator - null_terminated_uri->data + 1;
    static_resource_name->data = last_uri_separator + 1;
    static_resource_name->len = null_terminated_uri->len - uri_prefix_length;

    return 1;
}

///
/// @brief Validates that the provided static resource name is a valid.
/// @details The function checks if the static resources table has been properly intiliazed.
/// If it has, it initates a hash key and searchs for it in the static resources hash table.
/// If it finds it, returns 1, in any other case returns 0.
/// @param[in, out] static_resource_name NGINX string - resource name to be checked to be valid.
/// @returns ngx_int_t
///         - #1 Successed in getting a static resource.
///         - #0 Failed to get static resource.
///
static ngx_int_t
is_static_resource_request(ngx_str_t *static_resource_name)
{
    char *data;
    ngx_uint_t key;

    if (!is_static_resources_table_initialized()) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Cannot determine whether request is for a static resource: static resources' table is not initialized"
        );
        return 0;
    }

    write_dbg(
        DBG_LEVEL_TRACE,
        "Checking whether requested resource %s (name length: %u) is a static resource",
        static_resource_name->data, static_resource_name->len
    );

    key = ngx_hash_key(static_resource_name->data, static_resource_name->len);
    data = ngx_hash_find(&static_resources_hash_table, key, static_resource_name->data, static_resource_name->len);
    if (data == NULL) {
        write_dbg(DBG_LEVEL_TRACE, "Requested resource %s is not a static resource", static_resource_name->data);
        return 0;
    }

    return 1;
}

static void
set_location_conf_root(
    ngx_http_core_loc_conf_t *location_conf,
    const ngx_str_t *root_name,
    ngx_array_t *root_lengths,
    ngx_array_t *root_values
)
{
    location_conf->root.len = root_name->len;
    location_conf->root.data = root_name->data;
    location_conf->root_lengths = root_lengths;
    location_conf->root_values = root_values;
}

///
/// @brief Sends a static content response header.
/// @param[in, out] request
/// @param[in] static_resource_size
/// @param[in] static_resource_last_modified_time
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
send_static_content_response_headers(
    ngx_http_request_t *request,
    const off_t static_resource_size,
    const time_t static_resource_last_modified_time
)
{
    ngx_int_t send_headers_res = ngx_http_cp_response_headers_sender(
        request,
        static_resource_res_headers_response_code,
        static_resource_size,
        static_resource_last_modified_time,
        static_resource_res_headers_allow_ranges,
        static_resource_res_headers_keepalive
    );
    if (send_headers_res != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to send headers for static content response");
        return NGX_ERROR;
    }

    return NGX_OK;
}

///
/// @brief Open a cached file at the location configuration.
/// @param[in] location_conf Location configuration regarding the file to be handled.
/// @param[in, out] open_files_cache A cache of opened files.
/// @param[in, out] file_path File path to the file to be read.
/// @param[in, out] open_file_info Information regarding the file to be read.
/// @param[in, out] memory_pool NGINX pool.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
open_cached_file(
    ngx_http_core_loc_conf_t *location_conf,
    ngx_open_file_cache_t *open_files_cache,
    ngx_str_t *file_path,
    ngx_open_file_info_t *open_file_info,
    ngx_pool_t *memory_pool
)
{
    open_file_info->read_ahead = location_conf->read_ahead;
    open_file_info->directio = location_conf->directio;
    open_file_info->valid = location_conf->open_file_cache_valid;
    open_file_info->min_uses = location_conf->open_file_cache_min_uses;
    open_file_info->errors = location_conf->open_file_cache_errors;
    open_file_info->events = location_conf->open_file_cache_events;

    return ngx_open_cached_file(open_files_cache, file_path, open_file_info, memory_pool);
}

///
/// @brief Sends the static resource.
/// @param[in, out] request NGINX request static resource request to be sent.
/// @param[in, out] static_resource_name A path to the static resource.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t
send_static_resource(ngx_http_request_t *request, ngx_str_t *static_resource_name)
{
    const char *static_resources_root_path = get_static_resources_path();

    ngx_int_t open_file_res;
    ngx_int_t send_headers_res;
    ngx_open_file_info_t open_file_info;
    ngx_str_t static_resource_path;
    ngx_http_core_loc_conf_t *core_module_loc_conf = ngx_http_get_module_loc_conf(request, ngx_http_core_module);

    ngx_str_t old_root = core_module_loc_conf->root;
    ngx_array_t *old_root_lengths = core_module_loc_conf->root_lengths;
    ngx_array_t *old_root_values = core_module_loc_conf->root_values;
    ngx_str_t old_uri = request->uri;

    ngx_str_t new_root = { strlen(static_resources_root_path), (u_char *)static_resources_root_path };
    set_location_conf_root(core_module_loc_conf, &new_root, NULL, NULL);
    request->uri = *static_resource_name;

    // Map static_resource_path URI to file path.
    if (ngx_http_map_uri_to_path(request, &static_resource_path, &new_root.len, 0) == NULL) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to map static resource's URI to file path. URI: %.*s",
            request->uri.len,
            request->uri.data
        );
        return NGX_ERROR;
    }
    static_resource_path.len = new_root.len + static_resource_name->len;

    ngx_memzero(&open_file_info, sizeof(ngx_open_file_info_t));

    // Open static resource's file.
    open_file_res = open_cached_file(
        core_module_loc_conf,
        core_module_loc_conf->open_file_cache,
        &static_resource_path,
        &open_file_info,
        request->pool
    );
    if (open_file_res != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to open static resource's file. File path: %.*s",
            static_resource_path.len,
            static_resource_path.data
        );
        return NGX_ERROR;
    }

    // Send static content response headers.
    send_headers_res = send_static_content_response_headers(request, open_file_info.size, open_file_info.mtime);
    if (send_headers_res != NGX_OK) return send_headers_res;
    if (request != request->main && open_file_info.size == 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Tried to send empty file, sent only headers");
        return NGX_OK;
    }

    set_location_conf_root(core_module_loc_conf, &old_root, old_root_lengths, old_root_values);
    request->uri = old_uri;

    return ngx_http_cp_file_response_sender(
        request,
        &static_resource_path,
        &open_file_info,
        request == request->main,
        request->connection->log,
        request->pool
    );
}

///
/// @brief
/// @param[in, out] request NGINX request.
/// @param[in, out] null_terminated_uri Null terminated Uri.
/// @param[in, out] static_resource_name Static resource name.
/// @param[in] handle_static_resource_result  Results in handling the static resource request.
///
void
finalize_static_resource_response(
    ngx_http_request_t *request,
    ngx_str_t *null_terminated_uri,
    ngx_str_t *static_resource_name,
    const ngx_int_t handle_static_resource_result
)
{
    ngx_int_t finalize_request_response_code;

    // Frees null_terminated_uri data.
    if (null_terminated_uri->data != NULL) {
        ngx_pfree(request->pool, null_terminated_uri->data);
        null_terminated_uri->data = NULL;
    }

    if (handle_static_resource_result == not_a_static_resource) {
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Request is not for a static resource. Request's URI: %.*s",
            request->uri.len,
            request->uri.data
        );
        return;
    }

    // Debug printing of request result response.
    switch (handle_static_resource_result) {
        case NGX_OK:
        case NGX_DONE: {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Successfully sent requested static resource: %.*s",
                static_resource_name->len,
                static_resource_name->data
            );
            break;
        }
        case NGX_AGAIN: {
            write_dbg(
                DBG_LEVEL_DEBUG,
                "Failed to finish sending requested static resource, retrying. Static resource: %.*s",
                static_resource_name->len,
                static_resource_name->data
            );
            break;
        }
        default: {
            write_dbg(
                DBG_LEVEL_WARNING, "Failed to send requested static resource: %.*s",
                static_resource_name->len,
                static_resource_name->data
            );
            break;
        }
    }

    // Finalize response of the static response request.
    if (
        handle_static_resource_result == NGX_OK ||
        handle_static_resource_result == NGX_DONE ||
        handle_static_resource_result == NGX_AGAIN
    ) {
        finalize_request_response_code = handle_static_resource_result;
    } else {
        finalize_request_response_code = NGX_HTTP_FORBIDDEN;
    }
    ngx_http_finalize_request(request, finalize_request_response_code);
}

ngx_int_t
handle_static_resource_request(uint32_t session_id, ngx_http_cp_verdict_e *verdict, ngx_http_request_t *request)
{
    ngx_str_t null_terminated_uri;
    ngx_str_t static_resource_name;
    ngx_int_t send_static_resource_res;

    write_dbg(
        DBG_LEVEL_TRACE,
        "Trying to serve requested resource as static content. URI: %.*s",
        request->uri.len,
        request->uri.data
    );

    if (duplicate_ngx_string(&null_terminated_uri, &request->uri, request->pool) != NGX_OK) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to create a null terminated duplicate of URI. URI: %.*s",
            request->uri.len,
            request->uri.data
        );
        finalize_static_resource_response(request, &null_terminated_uri, &static_resource_name, NGX_ERROR);
        return NGX_ERROR;
    }

    // Get static resource name in static_resource_name.
    if (!get_static_resource_name(&null_terminated_uri, &static_resource_name)) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to create a null terminated duplicate of URI. URI: %.*s",
            request->uri.len,
            request->uri.data
        );
        finalize_static_resource_response(request, &null_terminated_uri, &static_resource_name, NGX_ERROR);
        return NGX_ERROR;
    }

    // Validates that static_resource_name is a valid request.
    if (!is_static_resource_request(&static_resource_name)) {
        finalize_static_resource_response(
            request,
            &null_terminated_uri,
            &static_resource_name,
            not_a_static_resource
        );
        return not_a_static_resource;
    }

    *verdict = TRAFFIC_VERDICT_IRRELEVANT;
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Request is for a static resource, inspection is not needed (session ID = %d)",
        session_id
    );

    // Sends the static request.
    send_static_resource_res = send_static_resource(request, &static_resource_name);
    finalize_static_resource_response(request, &null_terminated_uri, &static_resource_name, send_static_resource_res);

    return NGX_DONE;
}
