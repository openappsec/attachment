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

/// @file ngx_cp_utils.c
#include "ngx_cp_utils.h"

#include <ngx_core.h>
#include <ngx_log.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_http.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <math.h>

#include "nginx_attachment_util.h"
#include "ngx_cp_initializer.h"
#include "nginx_attachment_common.h"
#include "ngx_cp_metric.h"

#define USERCHECK_TITLE_START "<!-- CHECK_POINT_USERCHECK_TITLE_PLACEHOLDER-->"
#define USERCHECK_BODY_START "<!-- CHECK_POINT_USERCHECK_BODY_PLACEHOLDER-->"
#define USERCHECK_UUID_START "<!-- CHECK_POINT_USERCHECK_UUID_PLACEHOLDER-->"
#define MAX_STATIC_RESOURCES_PATH_LENGTH 256

static ngx_int_t is_configuration_updated = NGX_ERROR;

static ngx_uint_t web_triggers_response_code = NGX_HTTP_FORBIDDEN;

#define RESPONSE_PAGE_PARTS 4
static ngx_str_t web_response_page_parts[RESPONSE_PAGE_PARTS];

static ngx_uint_t web_response_title_size = 0;
static char web_response_title[64]; ///< Web response title static buffer.

static ngx_uint_t web_response_body_size = 0;
static char web_response_body[256]; ///< Web response body static buffer.

static ngx_uint_t web_response_uuid_size = 0;
static char web_response_uuid[64]; ///< Web response body uuid buffer.

static ngx_uint_t add_event_id = 0;
static ngx_uint_t redirect_location_size = 0; ///< Redirect location size.
static u_char redirect_location[512]; ///< Redirect location buffer.

static const ngx_uint_t max_static_resources_path_length = MAX_STATIC_RESOURCES_PATH_LENGTH;
static char static_resources_path[MAX_STATIC_RESOURCES_PATH_LENGTH];

static ngx_pool_t *memory_pool = NULL;

// no need to add a semicolon since it is already part of the included content
static const char web_response_page_format[] =
#include "ngx_cp_http_usercheck.h"


static int is_ctx_match = 1;
static int dbg_level = DBG_LEVEL_INFO; ///< Default debug level.
static uint32_t cur_session_id = 0; ///< Current session ID.

static uint pid = 0;

ngx_http_cp_sessions_per_minute_limit sessions_per_minute_limit_info = {
    .sessions_per_second = {0},
    .last_minute_sessions_sum = 0,
    .last_session_time = 0,
};

ngx_uint_t  current_config_version = 0;

ngx_int_t fail_mode_verdict = NGX_OK; ///< Fail open verdict incase of a timeout.
ngx_int_t fail_mode_hold_verdict = NGX_OK; ///< Fail open verdict incase of a timeout when waiting for wait verdict.
ngx_int_t dbg_is_needed = 0; ///< Debug flag.
ngx_int_t num_of_connection_attempts = 0; ///< Maximum number of attempted connections.
ngx_uint_t fail_open_timeout = 50; ///< Fail open timeout in milliseconds.
ngx_uint_t fail_open_hold_timeout = 150; ///< Fail open wait timeout in milliseconds.
ngx_http_cp_verdict_e sessions_per_minute_limit_verdict = TRAFFIC_VERDICT_ACCEPT;
ngx_uint_t max_sessions_per_minute = 0; ///< Masimum session per minute.
ngx_uint_t req_max_proccessing_ms_time = 3000; ///< Total Request processing timeout in milliseconds.
ngx_uint_t res_max_proccessing_ms_time = 3000; ///< Total Response processing timeout in milliseconds.
ngx_uint_t registration_thread_timeout_msec = 100; ///< Registration timeout in milliseconds.
ngx_uint_t req_header_thread_timeout_msec = 100; ///< Request header processing timeout in milliseconds.
ngx_uint_t req_body_thread_timeout_msec = 150; ///< Request body processing timeout in milliseconds.
ngx_uint_t res_header_thread_timeout_msec = 100; ///< Response header processing timeout in milliseconds.
ngx_uint_t res_body_thread_timeout_msec = 150; ///< Response body processing timeout in milliseconds.
ngx_uint_t waiting_for_verdict_thread_timeout_msec = 150; ///< Wait thread processing timeout in milliseconds.
ngx_http_inspection_mode_e inspection_mode = NON_BLOCKING_THREAD; ///< Default inspection mode.
ngx_uint_t num_of_nginx_ipc_elements = 200; ///< Number of NGINX IPC elements.
ngx_msec_t keep_alive_interval_msec = DEFAULT_KEEP_ALIVE_INTERVAL_MSEC;

static struct timeval
getCurrTimeFast()
{
    struct timeval curr_time;
    struct timespec curr_time_mono;


    clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_time_mono);

    curr_time.tv_sec = curr_time_mono.tv_sec;
    curr_time.tv_usec = curr_time_mono.tv_nsec/1000.0;
    return curr_time;
}

void
init_list_iterator(ngx_list_t *list, ngx_http_cp_list_iterator *iterator)
{
    if (list == NULL) {
        write_dbg(DBG_LEVEL_ASSERT, "Failed to initialize list iterator: NULL list pointer");
        return;
    }
    if (iterator == NULL) {
        write_dbg(DBG_LEVEL_ASSERT, "Failed to initialize list iterator: NULL iterator pointer");
        return;
    }

    iterator->current_part = &list->part;
    iterator->current_part_element_index = 0;
    iterator->current_list_element_index = 0;
    iterator->list_element_size = list->size;
}

void *
get_list_element(ngx_http_cp_list_iterator *iterator, const size_t index)
{
    while (iterator->current_list_element_index < index) {
        if (iterator->current_part_element_index >= iterator->current_part->nelts) {
            if (iterator->current_part->next == NULL) break;

            iterator->current_part = iterator->current_part->next;
            iterator->current_part_element_index = 0;
        }

        iterator->current_part_element_index++;
        iterator->current_list_element_index++;
    }

    if (iterator->current_part->next == NULL && iterator->current_list_element_index < index) return NULL;

    return (char *)(iterator->current_part)->elts + iterator->list_element_size * iterator->current_part_element_index;
}

ngx_int_t
free_list_from_pool(ngx_pool_t *memory_pool, ngx_list_t *list)
{
    int was_free_successful = 1;
    size_t curr_list_part_elem_idx;
    int freed_current = 0;
    void *data;
    ngx_list_part_t *part, *next_part;
    size_t num_part_elements;

    if (list == NULL) return NGX_OK;

    part = &list->part;
    if (part == NULL) {
        // Free list's head.
        ngx_pfree(memory_pool, list);
        return NGX_OK;
    }
    data = part->elts;

    num_part_elements = part->nelts;
    next_part = part->next;

    for (curr_list_part_elem_idx = 0 ;; curr_list_part_elem_idx++) {
        if (curr_list_part_elem_idx >= num_part_elements) {
            // Free all the elements.
            if (part->next == NULL) {
                break;
            }

            part = next_part;
            data = part->elts;
            num_part_elements = part->nelts;

            curr_list_part_elem_idx = 0;
            freed_current = 0;
        }
        if (!freed_current) {
            was_free_successful &= ngx_pfree(memory_pool, data) == NGX_OK;
            was_free_successful &= ngx_pfree(memory_pool, part) == NGX_OK;
            freed_current = 1;
        }
    }
    was_free_successful &= ngx_pfree(memory_pool, list) == NGX_OK;

    return was_free_successful ? NGX_OK : NGX_ERROR;
}

///
/// @brief Initiate hash key array.
/// @param[in, out] memory_pool NGINX pool to allocate all the necessary data.
/// @param[in, out] hash_key_array Hash key array to allocate and initiate.
/// @param[in, out] key_list List of keys to add to the initialized hash table.
/// @param[in] initial_data_value_ptr Initial data value pointer.
/// @param[in] initial_data_size Initial data size that will be increased if necessary.
/// @returns ngx_int_t 
///         - #NGX_OK.
///         - #NGX_ERROR.
///
ngx_int_t
init_hash_key_array(
    ngx_pool_t *memory_pool,
    ngx_hash_keys_arrays_t *hash_key_array,
    ngx_list_t *key_list,
    const void *initial_data_value_ptr,
    const size_t initial_data_size
)
{
    ngx_int_t add_key_result;
    size_t idx;
    ngx_list_part_t *list_part = NULL;
    ngx_str_t *current_part_elements = NULL;
    // Allocates initial_data_value_copy and copies intial data size.
    void *initial_data_value_copy = ngx_pnalloc(memory_pool, initial_data_size);

    memcpy(initial_data_value_copy, initial_data_value_ptr, initial_data_size);

    hash_key_array->pool = memory_pool;
    hash_key_array->temp_pool = memory_pool;
    ngx_hash_keys_array_init(hash_key_array, NGX_HASH_SMALL);

    // Go over the keys and insert them into the hash table.
    list_part = &key_list->part;
    current_part_elements = list_part->elts;
    for (idx = 0; ; idx++) {
        if (idx >= list_part->nelts) {
            if (list_part->next == NULL) {
                break;
            }
            list_part = list_part->next;
            current_part_elements = list_part->elts;
            idx = 0;
        }
        write_dbg(
            DBG_LEVEL_TRACE,
            "Adding key No. %u (name: %s, length: %u) to the list of hash table keys",
            idx,
            current_part_elements[idx].data,
            current_part_elements[idx].len
        );
        add_key_result = ngx_hash_add_key(
            hash_key_array,
            &current_part_elements[idx],
            initial_data_value_copy,
            NGX_HASH_READONLY_KEY
        );
        if (add_key_result != NGX_OK) {
            write_dbg(
                DBG_LEVEL_WARNING,
                "Failed to add the key %s to the list of hash table keys",
                current_part_elements[idx].data
            );
            return NGX_ERROR;
        }
        write_dbg(
            DBG_LEVEL_TRACE,
            "Successfully added the key %s to the list of hash table keys",
            current_part_elements[idx].data
        );
    }

    return NGX_OK;
}

ngx_int_t
init_hash_table(
    ngx_pool_t *memory_pool,
    ngx_hash_init_t *hash_table_initializer,
    ngx_hash_t *hash_table,
    char *hash_table_name,
    ngx_uint_t max_size,
    ngx_uint_t bucket_size,
    ngx_list_t *keys,
    const void *initial_value,
    const size_t initial_value_size
)
{
    ngx_hash_keys_arrays_t hash_keys_array;
    // Initiate hash table keys.
    if (init_hash_key_array(memory_pool, &hash_keys_array, keys, initial_value, initial_value_size) != NGX_OK) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to initialize the keys of the hash table \"%s\"", hash_table_name);
        return NGX_ERROR;
    }

    hash_table_initializer->hash = hash_table;
    hash_table_initializer->key = ngx_hash_key;
    hash_table_initializer->max_size = max_size;
    hash_table_initializer->bucket_size = bucket_size;
    hash_table_initializer->name = hash_table_name;
    hash_table_initializer->pool = memory_pool;
    hash_table_initializer->temp_pool = memory_pool;

    // Initiate the hash table with the keys.
    ngx_int_t res = ngx_hash_init(hash_table_initializer, hash_keys_array.keys.elts, hash_keys_array.keys.nelts);
    if (res != 0 || hash_table_initializer->hash == NULL) return NGX_ERROR;

    return NGX_OK;
}

void
copy_chain_buffers(ngx_chain_t *dest, ngx_chain_t *src)
{
    ngx_chain_t *curr_src = src;
    ngx_chain_t *curr_dst = dest;
    while (curr_src != NULL && curr_dst != NULL) {
        ngx_memcpy(curr_dst->buf, curr_src->buf, sizeof(ngx_buf_t));
        curr_src = curr_src->next;
        curr_dst = curr_dst->next;
    }
}

void
prepend_chain_elem(ngx_chain_t *current_elem, ngx_chain_t *new_elem)
{
    write_dbg(DBG_LEVEL_DEBUG, "Adding new chain element before current list element");
    ngx_buf_t *temp_buffer = current_elem->buf;

    current_elem->buf = new_elem->buf;
    new_elem->buf = temp_buffer;

    new_elem->next = current_elem->next;
    current_elem->next = new_elem;
}

void
append_chain_elem(ngx_chain_t *current_elem, ngx_chain_t *new_elem)
{
    write_dbg(DBG_LEVEL_DEBUG, "Adding new chain element after current list element");
    new_elem->next = current_elem->next;
    new_elem->buf->last_buf = current_elem->buf->last_buf;
    new_elem->buf->last_in_chain = current_elem->buf->last_in_chain;
    current_elem->next = new_elem;
    current_elem->buf->last_buf = 0;
    current_elem->buf->last_in_chain = 0;
}

ngx_int_t
split_chain_elem(ngx_chain_t *elem, uint16_t split_index, ngx_pool_t *pool)
{
    ngx_chain_t *new_chain;
    ngx_buf_t *new_buf;
    uint16_t original_element_size = elem->buf->last - elem->buf->pos;

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Splitting buffer chain element. Split index: %d, original element size: %d",
        split_index,
        original_element_size
    );

    if (split_index <= 0 || split_index > original_element_size) {
        write_dbg(DBG_LEVEL_ASSERT, "Cannot split chain element on illegal index: %d", split_index);
        return NGX_ERROR;
    }

    new_buf = ngx_calloc_buf(pool);
    if (new_buf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate new buffer element");
        return NGX_ERROR;
    }

    new_chain = ngx_alloc_chain_link(pool);
    if (new_chain == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate new chain element");
        ngx_pfree(pool, new_buf);
        return NGX_ERROR;
    }

    new_buf->start = elem->buf->pos + split_index - 1;
    new_buf->pos = new_buf->start;
    new_buf->end = elem->buf->end;
    new_buf->last = elem->buf->last;
    new_buf->memory = 1;
    elem->buf->end = elem->buf->pos + split_index - 1;
    elem->buf->last = elem->buf->end;

    new_chain->buf = new_buf;
    append_chain_elem(elem, new_chain);

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Successfully split chain element. First half element size: %d, second half element size: %d",
        elem->buf->last - elem->buf->pos,
        new_chain->buf->last - new_chain->buf->pos
    );

    return NGX_OK;
}

///
/// @brief Allocates and creates a new NGINX chain element.
/// @param[in] data_size Size of the data to be put in NGINX chain.
/// @param[in, out] data Data to put into the newly allocates NGINX chain.
/// @param[in, out] pool NGINX pool to allocate buffers from.
/// @returns 
///
ngx_chain_t *
create_chain_elem(uint32_t data_size, char *data, ngx_pool_t *pool)
{
    ngx_buf_t *new_buf;
    ngx_chain_t *new_chain;

    new_buf = ngx_calloc_buf(pool);
    if (new_buf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate new buffer element");
        return NULL;
    }

    new_chain = ngx_alloc_chain_link(pool);
    if (new_chain == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate new chain element");
        ngx_pfree(pool, new_buf);
        return NULL;
    }

    // Sets the new chain values.
    new_buf->start = (u_char *)data;
    new_buf->pos = new_buf->start;
    new_buf->last = new_buf->pos + data_size;
    new_buf->end = new_buf->last;
    new_buf->memory = 1;

    new_chain->buf = new_buf;
    new_chain->next = NULL;

    write_dbg(
        DBG_LEVEL_DEBUG,
        "Successfully created chain element. Element data: \"%s\", element data size: %d",
        new_chain->buf->pos == NULL ? (u_char *)"" : new_chain->buf->pos,
        new_chain->buf->last - new_chain->buf->pos
    );

    return new_chain;
}

void
free_chain(ngx_pool_t *pool, ngx_chain_t *chain)
{
    ngx_chain_t *next_chain;

    while (chain) {
        ngx_pfree(pool, chain->buf->start);
        ngx_pfree(pool, chain->buf);

        next_chain = chain->next;
        ngx_pfree(pool, chain);
        chain = next_chain;
    }
}

int
is_timeout_reached(struct timeval *timeout)
{
    struct timeval curr_time;

    curr_time = getCurrTimeFast();
    return (timercmp(timeout, &curr_time, <));
}

struct timeval
get_timeout_val_sec(const int delta_time_in_sec)
{
    struct timeval time;

    time = getCurrTimeFast();
    time.tv_sec += delta_time_in_sec;
    return time;
}

struct timeval
get_timeout_val_usec(const int delta_time_in_usec)
{
    struct timeval time;

    time = getCurrTimeFast();
    time.tv_usec += delta_time_in_usec;
    return time;
}

struct timeval
get_timeout_val_msec(const int delta_time_in_msec)
{
    struct timeval time;

    time = getCurrTimeFast();
    time.tv_sec += delta_time_in_msec / 1000;
    time.tv_usec += (delta_time_in_msec % 1000) * 1000;
    return time;
}

void
set_custom_response(const ngx_str_t *title, const ngx_str_t *body, const ngx_str_t *uuid, ngx_uint_t response_code)
{
    write_dbg(
        DBG_LEVEL_TRACE,
        "Setting Custom response page:\nresponse_code = %d, title size = %d, body size = %d, uuid = %s, uuid size = %d",
        response_code,
        title->len,
        body->len,
        uuid->data,
        uuid->len
    );

    web_triggers_response_code = response_code;

    web_response_title_size = title->len;
    web_response_body_size = body->len;
    web_response_uuid_size = uuid->len;

    if (web_response_title_size == 0 || web_response_body_size == 0) return;
    // Copies the provided variables into their respective response variables.
    memcpy(web_response_title, title->data, web_response_title_size);
    memcpy(web_response_body, body->data, web_response_body_size);
    memcpy(web_response_uuid, "Incident Id: ", strlen("Incident Id: "));
    memcpy(web_response_uuid + strlen("Incident Id: "), uuid->data, web_response_uuid_size);
}

void
set_redirect_response(const ngx_str_t *location, const ngx_str_t *uuid, uint add_event_id_to_header)
{
    write_dbg(DBG_LEVEL_TRACE, "Setting Redirect response");

    web_triggers_response_code = NGX_HTTP_TEMPORARY_REDIRECT;

    add_event_id = add_event_id_to_header;
    // Sets the redirection location data and the web response uuid.
    redirect_location_size = location->len;
    memcpy(redirect_location, location->data, redirect_location_size);
    memcpy(web_response_uuid, uuid->data, web_response_uuid_size);
}

u_char *
get_redirect_location()
{
    return redirect_location;
}

ngx_uint_t
get_redirect_location_size()
{
    return redirect_location_size;
}

ngx_uint_t
get_add_event_id()
{
    return add_event_id;
}

void
set_response_page_chain_elem(ngx_buf_t **part, ngx_str_t *content, ngx_chain_t *cur_chain, ngx_chain_t **next_chain)
{
    (*part)->pos = content->data;
    (*part)->last = (*part)->pos + content->len;
    (*part)->memory = 1;
    (*part)->last_buf = *next_chain == NULL ? 1 : 0;
    (*part)->last_in_chain = *next_chain == NULL ? 1 : 0;

    cur_chain->buf = *part;
    cur_chain->next = *next_chain;
}

ngx_int_t
get_response_page(ngx_http_request_t *request, ngx_chain_t (*out_chain)[7])
{
    ngx_int_t idx;
    ngx_chain_t *tmp_next;
    ngx_buf_t *buf[7]; // Title prefix -> Title -> Body prefix -> Body -> UUID prefix -> UUID -> UUID suffix
    ngx_str_t title  = { web_response_title_size, (u_char *)web_response_title };
    ngx_str_t body = { web_response_body_size, (u_char *)web_response_body };
    ngx_str_t uuid = { web_response_uuid_size, (u_char *)web_response_uuid };

    if (web_response_title_size == 0 || web_response_body_size == 0) return NGX_ERROR_ERR;

    for (idx = 0; idx < 7; idx++) {
        buf[idx] = ngx_calloc_buf(request->pool);
        if (buf[idx] == NULL) {
            for (; idx >= 0; idx--) {
                ngx_pfree(request->pool, buf[idx]);
            }
            return NGX_ERROR_ERR;
        }
    }

    tmp_next = *out_chain + 1;
    set_response_page_chain_elem(buf, web_response_page_parts, *out_chain, &tmp_next);

    tmp_next = *out_chain + 2;
    set_response_page_chain_elem(buf + 1, &title, *out_chain + 1, &tmp_next);

    tmp_next = *out_chain + 3;
    set_response_page_chain_elem(buf + 2, web_response_page_parts + 1, *out_chain + 2, &tmp_next);

    tmp_next = *out_chain + 4;
    set_response_page_chain_elem(buf + 3, &body, *out_chain + 3, &tmp_next);

    tmp_next = *out_chain + 5;
    set_response_page_chain_elem(buf + 4, web_response_page_parts + 2, *out_chain + 4, &tmp_next);

    tmp_next = *out_chain + 6;
    set_response_page_chain_elem(buf + 5, &uuid, *out_chain + 5, &tmp_next);

    tmp_next = NULL;
    set_response_page_chain_elem(buf + 6, web_response_page_parts + 3, *out_chain + 6, &tmp_next);

    return NGX_OK;
}

ngx_uint_t
get_response_page_length(void)
{
    ngx_uint_t idx;
    ngx_uint_t total_length = 0;

    if (web_response_title_size == 0 || web_response_body_size == 0) return 0;

    for (idx = 0; idx < RESPONSE_PAGE_PARTS; idx++) {
        total_length += web_response_page_parts[idx].len;
    }

    total_length += web_response_title_size;
    total_length += web_response_body_size;
    total_length += web_response_uuid_size;

    return total_length;
}

ngx_uint_t
get_response_code(void)
{
    return web_triggers_response_code;
}

const char *
get_web_response_uuid(void)
{
    return web_response_uuid + strlen("Incident Id: ");
}

ngx_uint_t
get_web_response_uuid_size(void)
{
    return web_response_uuid_size - strlen("Incident Id: ");
}

const char *
get_static_resources_path(void)
{
    return static_resources_path;
}

ngx_pool_t *
get_memory_pool(void)
{
    return memory_pool;
}

void
set_memory_pool(ngx_pool_t *new_memory_pool)
{
    memory_pool = new_memory_pool;
}

unsigned int
get_number_of_digits(int num)
{
    unsigned int num_of_digits = 0;

    do {
        num /= 10;
        num_of_digits++;
    } while (num != 0);

    return num_of_digits;
}

ngx_http_cp_verdict_e
get_sessions_per_minute_limit_verdict()
{
    return sessions_per_minute_limit_verdict;
}

unsigned int
get_max_sessions_per_minute()
{
    return max_sessions_per_minute;
}

ngx_http_cp_sessions_per_minute_limit *
get_periodic_sessions_limit_info()
{
    if (sessions_per_minute_limit_info.last_session_time == 0) {
        sessions_per_minute_limit_info.last_session_time = (unsigned int)(time(NULL));
        sessions_per_minute_limit_verdict = isFailOpenOnSessionLimit() ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
        max_sessions_per_minute = getMaxSessionsPerMinute();
    }
    return &sessions_per_minute_limit_info;
}

void
set_cp_ngx_attachment_debug_level(int _dbg_level)
{
    dbg_level = _dbg_level;
}

void
set_current_session_id(uint32_t _cur_session_id)
{
    cur_session_id = _cur_session_id;
}

void ngx_cdecl
write_dbg_impl(int _dbg_level, const char *func, const char *file, int line_num, const char *fmt, ...)
{
    if (_dbg_level < dbg_level || !is_ctx_match) return;

    char debug_str[NGX_MAX_ERROR_STR] = {0};
    char session_id_str[32] = {0};
    va_list args;
    time_t ttime;
    int millisec;
    struct timeval tv;
    char time_stamp[64];
    char str_uid[140];

    time(&ttime);
    tv = getCurrTimeFast();
    millisec = lrint(tv.tv_usec/1000.0);
    if (millisec>=1000) {
        // Allow for rounding up to nearest second
        millisec -=1000;
        tv.tv_sec++;
    }
    strftime(time_stamp, sizeof(time_stamp), "%FT%T", localtime(&ttime));

    if (!pid) pid = getpid();

    if (cur_session_id > 0) {
        snprintf(session_id_str, sizeof(session_id_str) - 1, "<session id %u> ", cur_session_id);
    }
    // Prints the debug given all the data and a formatter.
    snprintf(
        str_uid,
        sizeof(str_uid) - 1,
        "|%s.%03d: %s@%s:%d [uid %s | pid %u] %s| ",
        time_stamp,
        millisec,
        func,
        file,
        line_num,
        get_unique_id(),
        pid,
        session_id_str
    );

    va_start(args, fmt);
    vsnprintf(debug_str, sizeof(debug_str) - 1, fmt, args);

    va_end(args);
    dprintf(ngx_stderr, "%s%s\n", str_uid, debug_str);
}

///
/// @brief Initialize a web response data using the set global variables.
///
static void
initialize_web_response_data()
{
    char *title_pos = NULL;
    char *body_pos = NULL;
    char *uuid_pos = NULL;

    // Sets Check Point's attack detection string.
    static char default_title[] = "Attack blocked by web application protection";
    static char default_body[] = "Check Point's <b>Application Security</b> has detected an attack and blocked it.";
    static char default_uuid[] = "";

    title_pos = strstr(web_response_page_format, USERCHECK_TITLE_START);
    body_pos = strstr(web_response_page_format, USERCHECK_BODY_START);
    uuid_pos = strstr(web_response_page_format, USERCHECK_UUID_START);

    // Sets web response format and then pages.
    web_response_page_parts[0].data = (u_char *)web_response_page_format;
    web_response_page_parts[0].len = strlen(web_response_page_format) - strlen(title_pos);

    // Sets default title.
    web_response_title_size = strlen(default_title);
    memcpy(web_response_title, default_title, web_response_title_size);

    web_response_page_parts[1].data = (u_char *)title_pos + strlen(USERCHECK_TITLE_START);
    web_response_page_parts[1].len = strlen((char *)web_response_page_parts[1].data) - strlen(body_pos);

    // Sets default body.
    web_response_body_size = strlen(default_body);
    memcpy(web_response_body, default_body, web_response_body_size);

    web_response_page_parts[2].data = (u_char *)body_pos + strlen(USERCHECK_BODY_START);
    web_response_page_parts[2].len = strlen((char *)web_response_page_parts[2].data) - strlen(uuid_pos);

    // Sets default uuid.
    web_response_uuid_size = strlen(default_uuid);
    memcpy(web_response_uuid, default_uuid, web_response_uuid_size);

    web_response_page_parts[3].data = (u_char *)uuid_pos + strlen(USERCHECK_UUID_START);
    web_response_page_parts[3].len = strlen((char *)web_response_page_parts[3].data);
}

int
is_inspection_required_for_source(const char *src_ip)
{
    if (!isIPAddress(src_ip)) {
        write_dbg(DBG_LEVEL_WARNING, "Input %s is not an IP adress", src_ip);
        return -1;
    }

    write_dbg(DBG_LEVEL_DEBUG, "Is relevant: %s", src_ip);

    return !isSkipSource(src_ip);
}

///
/// @brief Sets a new static resources path.
/// @param[in] new_path A new path to be set as the static resources path.
///
void
set_static_resources_path(const char *new_path)
{
    ngx_uint_t new_path_len = strnlen(new_path, max_static_resources_path_length - 2);
    ngx_int_t is_path_terminated_with_slash = new_path[new_path_len - 1] == '/';
    ngx_memzero(static_resources_path, sizeof(static_resources_path));
    snprintf(
        static_resources_path,
        is_path_terminated_with_slash ? new_path_len + 1 : new_path_len + 2,
        is_path_terminated_with_slash ? "%s" : "%s/",
        new_path
    );

    write_dbg(DBG_LEVEL_DEBUG, "Set static resources path to: %s", static_resources_path);
}

void
set_dbg_by_ctx(
    char *client_ip,
    char *listening_ip,
    char *uri_prefix,
    char *hostname,
    char *method,
    unsigned int listening_port)
{
    int curr_match_result;
    write_dbg(
        DBG_LEVEL_TRACE,
        "Context for debug of the current request: %s -> %s:%d, URI: %s, hostname: %s, method: %s",
        client_ip,
        listening_ip,
        listening_port,
        uri_prefix,
        hostname,
        method
    );
    curr_match_result = isDebugContext(client_ip, listening_ip, listening_port, method, hostname, uri_prefix);

    write_dbg(DBG_LEVEL_TRACE, "Current debug context match result: %s", curr_match_result ? "match" : "no match");
    is_ctx_match = curr_match_result;
}

void
reset_dbg_ctx()
{
    is_ctx_match = 1;
}

ngx_int_t
init_general_config(const char *conf_path)
{
    int new_dbg_level = DBG_LEVEL_COUNT;

    if (access(conf_path, F_OK) != 0) return NGX_ERROR;

    if (is_configuration_updated == NGX_OK) return NGX_OK;

    // Initiate attachment using the file in the provided conf_path.
    if (!initAttachmentConfig(conf_path)) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to load the configuration");
        return NGX_ERROR;
    }

    new_dbg_level = getDbgLevel();

    if (new_dbg_level >= DBG_LEVEL_COUNT) {
        write_dbg(DBG_LEVEL_WARNING, "Illegal debug level received: %d", new_dbg_level);
        is_configuration_updated = NGX_ERROR;
        return NGX_ERROR;
    }
    write_dbg(DBG_LEVEL_DEBUG, "Setting debug level to: %d", new_dbg_level);
    // Setting a new debug level.
    set_cp_ngx_attachment_debug_level(new_dbg_level);

    if (web_response_title_size == 0 || web_response_body_size == 0) {
        write_dbg(DBG_LEVEL_DEBUG, "Setting web trigger response page");
        initialize_web_response_data();
    }

    // Setting fail open/close.
    fail_mode_verdict = isFailOpenMode() == 1 ? NGX_OK : NGX_ERROR;
    fail_open_timeout = getFailOpenTimeout();

    // Setting fail wait open/close
    fail_mode_hold_verdict = isFailOpenHoldMode() == 1 ? NGX_OK : NGX_ERROR;
    fail_open_hold_timeout = getFailOpenHoldTimeout();

    // Setting attachment's variables.
    sessions_per_minute_limit_verdict = isFailOpenOnSessionLimit() ? TRAFFIC_VERDICT_ACCEPT : TRAFFIC_VERDICT_DROP;
    max_sessions_per_minute = getMaxSessionsPerMinute();
    inspection_mode = getInspectionMode();
    req_max_proccessing_ms_time = getReqProccessingTimeout();
    res_max_proccessing_ms_time = getResProccessingTimeout();
    registration_thread_timeout_msec = getRegistrationThreadTimeout();
    req_header_thread_timeout_msec = getReqHeaderThreadTimeout();
    req_body_thread_timeout_msec = getReqBodyThreadTimeout();
    res_header_thread_timeout_msec = getResHeaderThreadTimeout();
    res_body_thread_timeout_msec = getResBodyThreadTimeout();
    waiting_for_verdict_thread_timeout_msec = getWaitingForVerdictThreadTimeout();

    num_of_nginx_ipc_elements = getNumOfNginxIpcElements();
    keep_alive_interval_msec = (ngx_msec_t) getKeepAliveIntervalMsec();

    set_static_resources_path(getStaticResourcesPath());
    is_configuration_updated = NGX_OK;

    write_dbg(
        DBG_LEVEL_INFO,
        "Successfully loaded configuration. "
        "inspection mode: %d, "
        "debug level: %d, "
        "failure mode: %s, "
        "fail mode timeout: %u msec, "
        "failure wait mode: %s, "
        "fail mode wait timeout: %u msec, "
        "sessions per minute limit verdict: %s, "
        "max sessions per minute: %u, "
        "req max processing time: %u msec, "
        "res max processing time: %u msec, "
        "registration thread timeout: %u msec, "
        "req header thread timeout: %u msec, "
        "req body thread timeout: %u msec, "
        "res header thread timeout: %u msec, "
        "res body thread timeout: %u msec, "
        "wait thread timeout: %u msec, "
        "static resources path: %s, "
        "num of nginx ipc elements: %u, "
        "keep alive interval msec: %u msec",
        inspection_mode,
        new_dbg_level,
        (fail_mode_verdict == NGX_OK ? "fail-open" : "fail-close"),
        fail_open_timeout,
        (fail_mode_hold_verdict == NGX_OK ? "fail-open" : "fail-close"),
        fail_open_hold_timeout,
        sessions_per_minute_limit_verdict == TRAFFIC_VERDICT_ACCEPT ? "Accpet" : "Drop",
        max_sessions_per_minute,
        req_max_proccessing_ms_time,
        res_max_proccessing_ms_time,
        registration_thread_timeout_msec,
        req_header_thread_timeout_msec,
        req_body_thread_timeout_msec,
        res_header_thread_timeout_msec,
        res_body_thread_timeout_msec,
        waiting_for_verdict_thread_timeout_msec,
        getStaticResourcesPath(),
        num_of_nginx_ipc_elements,
        keep_alive_interval_msec
    );


    return NGX_OK;
}

ngx_int_t
reset_attachment_config()
{
    write_dbg(DBG_LEVEL_INFO, "Resetting attachment configuration");

    is_configuration_updated = NGX_ERROR;
    current_config_version++;
    return init_general_config(SHARED_ATTACHMENT_CONF_PATH);
}

ngx_int_t
duplicate_ngx_string(ngx_str_t *null_terminated_string, ngx_str_t *original_string, ngx_pool_t *memory_pool)
{
    null_terminated_string->len = original_string->len;
    null_terminated_string->data = ngx_pcalloc(memory_pool, null_terminated_string->len + 1);
    if (null_terminated_string->data == NULL) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to allocate memory for a copy of the string %.*s",
            original_string->len,
            original_string->data
        );
        return NGX_ERROR;
    }
    ngx_snprintf(null_terminated_string->data, null_terminated_string->len + 1, "%V", original_string);

    return NGX_OK;
}

u_char *
reverse_strnchr(u_char *string, const u_char char_to_find, const size_t string_length)
{
    u_char *curr_char;
    for (curr_char = string + string_length - 1; curr_char >= string; curr_char--) {
        if (*curr_char == char_to_find) return curr_char;
    }

    return NULL;
}

ngx_msec_t
get_keep_alive_interval_msec(void)
{
    return keep_alive_interval_msec;
}

///
/// @brief Get the CPU usage time.
/// @param[in, out]  total_usage_time timeval struct that's the total cpu usage's time will be saved into.
///
void
get_total_cpu_usage_time(struct timeval *total_usage_time)
{
    static struct timeval last_user_usage_time = {0, 0};
    static struct timeval last_kernel_usage_time = {0, 0};

    struct timeval diff_user_time = {0, 0};
    struct timeval diff_kernel_time = {0, 0};
    struct rusage usage;

    getrusage(RUSAGE_SELF, &usage);
    timersub(&usage.ru_utime, &last_user_usage_time, &diff_user_time);
    timersub(&usage.ru_stime, &last_kernel_usage_time, &diff_kernel_time);
    timeradd(&diff_user_time, &diff_kernel_time, total_usage_time);
    last_kernel_usage_time = usage.ru_stime;
    last_user_usage_time = usage.ru_utime;
}

void
set_metric_cpu_usage(void)
{
    static struct timeval prev_time = {0, 0};
    static const unsigned int usecs_in_sec = 1000000;

    struct timeval curr_time;
    struct timeval diff_time = {0, 0};
    struct timeval total_usage_time = {0, 0};
    double total_cpu_usage_fraction = 0;
    uint64_t cpu_usage_percent = 0;

    curr_time = getCurrTimeFast();

    timersub(&curr_time, &prev_time, &diff_time);
    get_total_cpu_usage_time(&total_usage_time);
    total_cpu_usage_fraction = (double)(total_usage_time.tv_sec * usecs_in_sec + total_usage_time.tv_usec) /
        (diff_time.tv_sec * usecs_in_sec + diff_time.tv_usec);
    prev_time = curr_time;

    cpu_usage_percent = total_cpu_usage_fraction * 100;
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Updating CPU max and average metrics. Current value: %u%%. The fraction of CPU time value %f.",
        cpu_usage_percent,
        total_cpu_usage_fraction
    );
    updateMetricField(CPU_USAGE, cpu_usage_percent);
}

void
set_metric_memory_usage(void)
{
    static const int max_line_length = 32;

    unsigned int vm_size = 0;
    unsigned int rss_size = 0;
    char buff[max_line_length];

    FILE *mem_status = fopen("/proc/self/status", "r");
    if (mem_status == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to open the status file. File: /proc/self/status");
        return;
    }
    while (fgets(buff, max_line_length, mem_status)) {
        if (strstr(buff, "VmSize") != NULL) {
            sscanf(buff, "VmSize: %u kB", &vm_size);
        }
        if (strstr(buff, "VmRSS") != NULL) {
            sscanf(buff, "VmRSS: %u kB", &rss_size);
        }
    }
    if (fclose(mem_status) != 0) {
        write_dbg(DBG_LEVEL_WARNING, "Failed closing the status file. File: /proc/self/status");
    }
    write_dbg(
        DBG_LEVEL_DEBUG,
        "Updating memory max and average metrics. Current values: VM %u kB, RSS: %u kB.",
        vm_size,
        rss_size
    );
    updateMetricField(AVERAGE_VM_MEMORY_USAGE, vm_size);
    updateMetricField(AVERAGE_RSS_MEMORY_USAGE, rss_size);
    updateMetricField(MAX_VM_MEMORY_USAGE, vm_size);
    updateMetricField(MAX_RSS_MEMORY_USAGE, rss_size);
}
