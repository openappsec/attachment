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

/// @file ngx_cp_utils.h
#ifndef __NGX_CP_UTILS_H__
#define __NGX_CP_UTILS_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/time.h>
#include <assert.h>

#include "nginx_attachment_common.h"

#ifndef __FILENAME__
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define write_dbg(_dbg_level, fmt, ...)                                                         \
    {                                                                                          \
        write_dbg_impl(_dbg_level, __func__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__);      \
        if ((_dbg_level) == DBG_LEVEL_ASSERT) assert(0);                                       \
    }

#define write_dbg_if_needed(_dbg_level, fmt, ...)                                                     \
    {                                                                                                 \
		if ((dbg_is_needed) == 0) {                                                                   \
			write_dbg_impl(DBG_LEVEL_TRACE, __func__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__);    \
		} else {                                                                                      \
			write_dbg_impl(_dbg_level, __func__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__);         \
		}                                                                                             \
        if ((_dbg_level) == DBG_LEVEL_ASSERT) assert(0);                                              \
    }

extern ngx_int_t fail_mode_verdict;
extern ngx_int_t fail_mode_hold_verdict;
extern ngx_int_t dbg_is_needed;
extern ngx_int_t num_of_connection_attempts;
extern ngx_uint_t content_length_would_change;
extern ngx_uint_t fail_open_timeout;
extern ngx_uint_t fail_open_hold_timeout;
extern ngx_uint_t req_max_proccessing_ms_time;
extern ngx_uint_t res_max_proccessing_ms_time;
extern ngx_uint_t registration_thread_timeout_msec;
extern ngx_uint_t req_header_thread_timeout_msec;
extern ngx_uint_t req_body_thread_timeout_msec;
extern ngx_uint_t res_header_thread_timeout_msec;
extern ngx_uint_t res_body_thread_timeout_msec;
extern ngx_uint_t waiting_for_verdict_thread_timeout_msec;
extern ngx_http_inspection_mode_e inspection_mode;
extern ngx_uint_t num_of_nginx_ipc_elements;

///
/// @struct ngx_http_cp_list_iterator
/// @brief NGINX list iterator's data.
///
typedef struct {
    ngx_list_part_t *current_part; ///< Iterator's current node.
    size_t current_part_element_index; ///< Current part index.
    size_t current_list_element_index; ///< Current list index.
    size_t list_element_size; ///< The total size of the list that the iterator belongs to.
} ngx_http_cp_list_iterator;

///
/// @struct ngx_http_cp_sessions_per_minute_limit
/// @brief Holds sessions per minute related limitations.
///
typedef struct {
    /// After more than a minute has passed, we reset all session monitoring data.
    /// sessions_per_second array helps keeping track with sessions that need to be closed.
    unsigned int sessions_per_second[60];
    unsigned int last_minute_sessions_sum; ///< Sum of all the last minutes sessions' sum.
    unsigned int last_session_time; ///< The length of the latest session.
} ngx_http_cp_sessions_per_minute_limit;

///
/// @brief Set debug context.
/// @param[in, out] client_ip Client IP to set in the debug.
/// @param[in, out] listening_ip Listening IP to set in the debug.
/// @param[in, out] uri_prefix Uri prefix to set in the debug.
/// @param[in, out] hostname Hostname to set in the debug.
/// @param[in, out] method Method to set in the debug.
/// @param[in] listening_port Listening port to set in the debug.
///
void set_dbg_by_ctx(
    char *client_ip,
    char *listening_ip,
    char *uri_prefix,
    char *hostname,
    char *method,
    unsigned int listening_port);

///
/// @brief Reset debug context.
///
void reset_dbg_ctx();

///
/// @brief Initiate list iterator of the provided list.
/// @param[in, out] list to get the iterator of.
/// @param[in, out] iterator the iterator to be initiated
///
void init_list_iterator(ngx_list_t *list, ngx_http_cp_list_iterator *iterator);

///
/// @brief Get list element
/// @param[in, out] iterator the iterator to be initiated.
/// @param[in] index.
/// @returns void*
///         - #A pointer to the element.
///         - #NULL if failed to get or reached the end of the list.
///
void *get_list_element(ngx_http_cp_list_iterator *iterator, const size_t index);

///
/// @brief Free a list from NGINX pool.
/// @param[in, out] memory_pool NGINX pool.
/// @param[in, out] list A pointer to a list to free.
/// @returns void*
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t free_list_from_pool(ngx_pool_t *memory_pool, ngx_list_t *list);

///
/// @brief Initiate a provided hash table with the provided values.
/// @param[in, out] memory_pool NGINX pool.
/// @param[in, out] hash_table_initializer NGINX hash initializator.
/// @param[in, out] hash_table Hash table to init.
/// @param[in] hash_table_name Hash table name.
/// @param[in] max_size Maximum size to set the hash table.
/// @param[in] bucket_size Bucket size to set in the hash table.
/// @param[in, out] keys Keys initiate and put into the hash_table.
/// @param[in, out] initial_value Initial hash value.
/// @param[in, out] initial_value_size Initial hash value's size.
/// @return ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t init_hash_table(
    ngx_pool_t *memory_pool,
    ngx_hash_init_t *hash_table_initializer,
    ngx_hash_t *hash_table,
    char *hash_table_name,
    ngx_uint_t max_size,
    ngx_uint_t bucket_size,
    ngx_list_t *keys,
    const void *initial_value,
    const size_t initial_value_size
);

///
/// @brief Copy the src buffer to the dest.
/// @param[in, out] dest NGINX chain to be copied into.
/// @param[in] src NGINX chain to come from.
///
void copy_chain_buffers(ngx_chain_t *dest, ngx_chain_t *src);

///
/// @brief Adds a new chain element before current list element.
/// @param[in, out] current_elem NGINX chain to be copied into.
/// @param[in] new_elem NGINX chain to come from.
///
void prepend_chain_elem(ngx_chain_t *current_elem, ngx_chain_t *new_elem);

///
/// @brief Adds a new chain element after current list element.
/// @param[in, out] current_elem NGINX chain to be copied into.
/// @param[in] new_elem NGINX chain to come from.
///
void append_chain_elem(ngx_chain_t *current_elem, ngx_chain_t *new_elem);

///
/// @brief Split chain element.
/// @param[in, out] elem NGINX chain to be split.
/// @param[in, out] split_index Index to split from.
/// @param[in, out] pool NGINX pool.
/// @returns ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t split_chain_elem(ngx_chain_t *elem, uint16_t split_index, ngx_pool_t *pool);

///
/// @brief Create chain element
/// @param[in, out] elem NGINX chain to be split.
/// @param[in, out] split_index Index to split from.
/// @param[in, out] pool NGINX pool.
/// @returns ngx_chain_t
///         - #A valid pointer to a ngx_chain_t.
///         - #NULL if failed to create a chain element.
///
ngx_chain_t * create_chain_elem(uint32_t data_size, char *data, ngx_pool_t *pool);

///
/// @brief Free a NGINX chain.
/// @param[in, out] pool NGINX pool that free the resources into.
/// @param[in, out] chain NGINX chain to free.
/// @returns ngx_chain_t
///
void free_chain(ngx_pool_t *pool, ngx_chain_t *chain);

///
/// @brief Get currently set response uuid.
/// @returns char * of set web_response_uuid variable.
///
const char *get_web_response_uuid(void);

///y
/// @brief Get currently set response code.
/// @returns Returns the size of web_response_uuid variable.
///
ngx_uint_t get_web_response_uuid_size(void);

///
/// @brief Sets a custom response page by modifying web_response_title/body/uuid variables.
/// @param[in] title Sets the web response title.
/// @param[in] message Sets the response body.
/// @param[in] uuid Sets the uuid of the custom response.
/// @param[in, out] response_code Sets the response code of the custom response.
///
void set_custom_response(const ngx_str_t *title, const ngx_str_t *message, const ngx_str_t *uuid, ngx_uint_t response_code);

///
/// @brief Sets a redirect response by modifying redirect triggers, redirect_location and web_response_uuid.
/// @param[in] location Redirect location to set to.
/// @param[in] uuid Redirection's response uuid to set.
/// @param[in, out] add_event_id_to_header Event ID to add to the response header.
///
void set_redirect_response(const ngx_str_t *location, const ngx_str_t *uuid, uint add_event_id_to_header);

///
/// @brief Get the redirect location.
/// @returns redirect_location variable.
///
u_char *get_redirect_location();

///
/// @brief Get the redirect location.
/// @returns redirect_location_size variable.
///
ngx_uint_t get_redirect_location_size();

///
/// @brief Get the redirect location.
/// @returns add_event_id variable.
///
ngx_uint_t get_add_event_id();

///
/// @brief Returns if timeout has been reached.
/// @param[in, out] timeout NGINX pool that free the resources into.
/// @returns Returns 1 it timeout reached, otherwise 0.
///
int is_timeout_reached(struct timeval *timeout);

///
/// @brief Get delta current time + delta_time_in_sec value in seconds.
/// @param[in] delta_time_in_sec Delta time to return
/// @returns timeval struct with tv_sec value of += delta_time_in_sec.
///
struct timeval get_timeout_val_sec(const int delta_time_in_sec);

///
/// @brief Get delta current time + delta_time_in_usec value in seconds.
/// @param[in] delta_time_in_usec Delta time to return
/// @returns timeval struct with tv_sec value of += delta_time_in_usec.
///
struct timeval get_timeout_val_usec(const int delta_time_in_usec);

///
/// @brief Get delta current time + delta_time_in_msec value in msec.
/// @param[in] delta_time_in_msec Delta time to return
/// @returns timeval struct with tv_sec, tv_usec set accordingly
///
struct timeval get_timeout_val_msec(const int delta_time_in_msec);

///
/// @brief Get the currently set response page.
/// @param[in, out] request NGINX request, used to get the NGINX pool to allocate buffer needed for out_chain.
/// @param[in, out] out_chain NGINX chain that the response page data will be written to.
/// @returns ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR_ERR.
///
ngx_int_t get_response_page(ngx_http_request_t *request, ngx_chain_t (*out_chain)[7]);

///
/// @brief Get currently set response page length.
/// @returns ngx_uint_t length of the response page.
///
ngx_uint_t get_response_page_length(void);

///
/// @brief Get currently set response code.
/// @returns ngx_uint_t web_triggers_response_code variable.
///
ngx_uint_t get_response_code(void);

///
/// @brief Get currently set static resource path.
/// @returns char * get static_resources_path variable.
///
const char * get_static_resources_path(void);

///
/// @brief Get currently set memory_pool.
/// @returns ngx_pool_t * get memory_pool.
///
ngx_pool_t *get_memory_pool(void);

///
/// @brief Set memory_pool.
/// @param[in, out] new_memory_pool A new NGINX pool to be set.
///
void set_memory_pool(ngx_pool_t *new_memory_pool);

///
/// @brief Get number of digits of the provided num variable.
/// @param[in] num The number variable to get the number of digits from.
/// @returns Returns the number of digits.
///
unsigned int get_number_of_digits(int num);

///
/// @brief Get sessions per minute limit verdict.
/// @returns ngx_http_cp_verdict_e sessions_per_minute_limit_verdict variable.
///
ngx_http_cp_verdict_e get_sessions_per_minute_limit_verdict(void);

///
/// @brief Get maximum sessions per minute.
/// @returns unsigned int max_sessions_per_minute variable.
///
unsigned int get_max_sessions_per_minute(void);

///
/// @brief Get periodic session limit info..
/// @returns ngx_http_cp_sessions_per_minute_limit * Session per minute limit info.
///
ngx_http_cp_sessions_per_minute_limit *get_periodic_sessions_limit_info(void);

///
/// @brief Writing into debug implementation.
/// @param[in] _dbg_level Debug level to write into.
/// @param[in] func Function name from which the write debug was called from.
/// @param[in] file File from which the debug function was called from.
/// @param[in] line_num Line number of the write debug was called on.
/// @param[in] fmt Debug formatter.
/// @param[in] ... Extra values to write into the debug using the formatter.
///
void ngx_cdecl write_dbg_impl(int _dbg_level, const char *func, const char *file, int line_num, const char *fmt, ...);

///
/// @brief Sets a new debug level.
/// @param[in] _dbg_level New debug level to be set.
///
void set_cp_ngx_attachment_debug_level(int _dbg_level);

///
/// @brief Sets a new session ID.
/// @param[in] _dbg_level New session ID to be set.
///
void set_current_session_id(uint32_t cur_session_id);

///
/// @brief Checks if inspection required for a provided source IP.
/// @param[in] src_ip Provided source IP to be checked.
/// @returns 1 if inspection required, otherwise 0.
///
int is_inspection_required_for_source(const char *src_ip);

///
/// @brief Initiates general configuration with the provided file path.
/// @param[in] conf_path Configuration path to a file of general configuration to initiate.
/// @returns ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t init_general_config(const char *conf_path);

///
/// @brief Resets attachment configuration and loads them again from the file path in SHARED_ATTACMENT_CONF_PATH.
/// @returns ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t reset_attachment_config(void);

///
/// @brief Resets attachment configuration and loads them again from the file path in SHARED_ATTACMENT_CONF_PATH.
/// @param[in] null_terminated_string null terminated string that the original string will be copied into.
/// @param[in] original_string String to be copied into the null_terminated_string.
/// @param[in] memory_pool NGINX pool for allocation the needed buffer for null_terminated_string.
/// @returns ngx_int_t
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t duplicate_ngx_string(ngx_str_t *null_terminated_string, ngx_str_t *original_string, ngx_pool_t *memory_pool);

///
/// @brief Reverse implementation to strnchr - finding a character in a length limited string from the end.
/// @param[in] string
/// @param[in] char_to_find
/// @param[in] string_length
/// @returns u_char* pointer to the first u_char that was found.
///
u_char *reverse_strnchr(u_char *string, const u_char char_to_find, const size_t string_length);

///
/// @brief Get keep alive internal milliseconds.
/// @returns ngx_msec_t keep_alive_interval_msec variable.
///
ngx_msec_t get_keep_alive_interval_msec(void);

///
/// @brief Update CPU's max, average metrics and time usage metric.
///
void set_metric_cpu_usage(void);

///
/// @brief Update memory's max, average metrics and time usage metric.
///
void set_metric_memory_usage(void);

#endif // __NGX_CP_UTILS_H__
