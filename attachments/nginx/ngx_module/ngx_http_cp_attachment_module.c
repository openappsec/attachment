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

/// @file ngx_http_cp_attachment_module.c
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_files.h>

#include "ngx_cp_hooks.h"
#include "ngx_cp_utils.h"
#include "ngx_cp_initializer.h"
#include "ngx_http_cp_attachment_module.h"
#include "nginx_attachment_common.h"

extern ngx_uint_t current_config_version; ///< NGINX configuration version.
typedef struct {
    ngx_flag_t enable; ///< Flags if the configuration enabled.
    ngx_int_t num_of_workers; ///< Number of workers.
    ngx_uint_t current_loc_config_version; ///< NGINX configuration version.
} ngx_cp_attachment_conf_t;

///
/// @brief Creates NGINX cp attachment configuration.
/// @param[in, out] conf NGINX configuration.
/// @return 
///         - #ngx_cp_attachment_conf_t if successed to create conf.
///         - #NULL if failed to create conf.
///
static void * ngx_cp_attachment_create_conf(ngx_conf_t *conf);

///
/// @brief Sets attachment's module configuration in NGINX configuration chain.
/// @param[in, out] configure NGINX configuration.
/// @param[in] curr ngx_cp_attachment_conf_t Pointer to the configuration.
/// @param[in] next ngx_cp_attachment_conf_t Pointer to the configuration.
/// @return NGX_CONF_OK.
///
static char * ngx_cp_attachment_merge_conf(ngx_conf_t *conf, void *curr, void *next);

///
/// @brief Sets numbers of workers configuration.
/// @param[in, out] cf NGINX configuration.
/// @param[in, out] cmd NGINX command.
/// @param[in, out] conf NGINX CP configuration.
/// @return NGX_CONF_OK
///
static char * ngx_cp_attachment_set_num_workers_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

///
/// @brief Inits NGINX CP attachment.
/// @param[in] conf NGINX configuration.
/// @returns ngx_int_t
///         - #NGX_OK
///         - #NGX_ERROR
///
static ngx_int_t ngx_cp_attachment_init(ngx_conf_t *conf);

///
/// @brief Creates NGINX cp attachment configuration.
/// @param[in, out] cf NGINX configuration.
/// @return ngx_cp_attachment_conf_t
///         - #ngx_cp_attachment_conf_t pointer if successed.
///         - #NULL if failed.
///
static void * ngx_cp_attachment_create_main_conf(ngx_conf_t *cf);

///
/// @brief Inits a NGINX CP worker.
/// @param[in] cycle NGINX cycle.
/// @returns NGX_OK.
///
static ngx_int_t ngx_cp_attachment_init_worker(ngx_cycle_t *cycle);

///
/// @brief Finis a NGINX CP worker.
/// @param[in] cycle NGINX cycle.
///
static void ngx_cp_attachment_fini_worker(ngx_cycle_t *cycle);

ngx_http_output_header_filter_pt ngx_http_next_response_header_filter; ///< NGINX response header filter.
ngx_http_request_body_filter_pt ngx_http_next_request_body_filter; ///< NGINX request body filter.
ngx_http_output_body_filter_pt ngx_http_next_response_body_filter; ///< NGINX output body filter.

struct sockaddr_un attachment_server; ///< NGINX CP attachments server socket.

static ngx_event_t ngx_keep_alive_event;
static ngx_int_t is_timer_active = 0;
static ngx_connection_t  dumb_connection;
static ngx_msec_t keep_alive_interval_msec = 0;
static ngx_msec_t timer_interval_msec = 10000;

/// NGINX CP attachment command array.
static ngx_command_t ngx_cp_attachment_commands[] = {
    {
        ngx_string("cp-nano-nginx-attachment"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_cp_attachment_conf_t, enable),
        NULL
    },
    {
        ngx_string("cp_worker_processes"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_cp_attachment_set_num_workers_conf,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_cp_attachment_conf_t, num_of_workers),
        NULL
    },
    ngx_null_command
};

/// NGINX CP attachment module context.
static ngx_http_module_t ngx_cp_attachment_module_ctx = {
    NULL,
    ngx_cp_attachment_init,
    ngx_cp_attachment_create_main_conf,
    NULL,
    NULL,
    NULL,
    ngx_cp_attachment_create_conf,
    ngx_cp_attachment_merge_conf
};

/// NGINX attachment module.
ngx_module_t ngx_http_cp_attachment_module = {
    NGX_MODULE_V1,                    ///< NGINX CP module version.
    &ngx_cp_attachment_module_ctx,    ///< module context.
    ngx_cp_attachment_commands,       ///< module directives.
    NGX_HTTP_MODULE,                  ///< module type.
    NULL,
    NULL,
    ngx_cp_attachment_init_worker,    ///< init process.
    NULL,
    NULL,
    ngx_cp_attachment_fini_worker,    ///< exit process.
    NULL,
    NGX_MODULE_V1_PADDING
};

int workers_amount_to_send = 0;

static void *
ngx_cp_attachment_create_main_conf(ngx_conf_t *cf)
{
    ngx_cp_attachment_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_cp_attachment_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_cp_attachment_set_num_workers_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void) cmd;
    ngx_str_t        *value;
    ngx_cp_attachment_conf_t  *ccf;
    ccf = (ngx_cp_attachment_conf_t *)conf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "auto") == 0) {
        ccf->num_of_workers = ngx_ncpu;
        return NGX_CONF_OK;
    }

    ccf->num_of_workers = ngx_atoi(value[1].data, value[1].len);

    if (ccf->num_of_workers == NGX_ERROR) {
        ccf->num_of_workers = 0;
        return "invalid value";
    }

    return NGX_CONF_OK;
}

static void *
ngx_cp_attachment_create_conf(ngx_conf_t *conf)
{
    ngx_cp_attachment_conf_t  *module_conf;

    if (conf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to create attachment module configuration: input argument is NULL");
        return NULL;
    }

    module_conf = ngx_pcalloc(conf->pool, sizeof(ngx_cp_attachment_conf_t));
    if (module_conf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to allocate attachment module configuration");
        return NULL;
    }

    module_conf->enable = NGX_CONF_UNSET;
    module_conf->num_of_workers = 0;
    module_conf->current_loc_config_version =  current_config_version;
    write_dbg(DBG_LEVEL_TRACE, "Successfully created attachment module configuration");
    return module_conf;
}


ngx_uint_t
get_num_of_workers(ngx_http_request_t *request)
{
    if (workers_amount_to_send > 0) return workers_amount_to_send;

    ngx_cp_attachment_conf_t *conf = ngx_http_get_module_main_conf(request, ngx_http_cp_attachment_module);
    if (conf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to fetch the local NGINX attachment state");
        return 0;
    }
    write_dbg(DBG_LEVEL_INFO, "num_of_workers=%d", conf->num_of_workers);

    workers_amount_to_send = conf->num_of_workers;
    return conf->num_of_workers;
}

ngx_int_t
is_ngx_cp_attachment_disabled(ngx_http_request_t *request)
{
    ngx_cp_attachment_conf_t *conf = ngx_http_get_module_loc_conf(request, ngx_http_cp_attachment_module);
    if (conf == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to fetch the local NGINX attachment state");
        return NGX_CONF_UNSET;
    }
    if (conf->current_loc_config_version != current_config_version) {
        conf->current_loc_config_version =  current_config_version;
        write_dbg(DBG_LEVEL_INFO, "Reconfiguring the local NGINX attachment state");
    }
    write_dbg(DBG_LEVEL_TRACE, "NGINX attachment state: %s", conf->enable ? "enabled" : "disabled");
    return !conf->enable;
}

void
ngx_cp_set_module_loc_conf(ngx_http_request_t *request, ngx_flag_t new_state)
{
    ngx_cp_attachment_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(request, ngx_http_cp_attachment_module);
    conf->enable = new_state;
    write_dbg(DBG_LEVEL_INFO, "Configuration set to be %s", conf->enable ? "enabled" : "disabled");
}

static char *
ngx_cp_attachment_merge_conf(ngx_conf_t *configure, void *curr, void *next)
{
    (void)configure;
    ngx_cp_attachment_conf_t *prev = curr;
    ngx_cp_attachment_conf_t *conf = next;

    ngx_conf_merge_value(conf->enable, prev->enable, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->num_of_workers, prev->num_of_workers, ngx_ncpu);

    write_dbg(DBG_LEVEL_TRACE, "Successfully set attachment module configuration in nginx configuration chain");
    return NGX_CONF_OK;
}

///
/// @brief Sends keep alive to the nano agent.
/// @param[in] event NGINX event.
///
static void
ngx_send_keep_alive(ngx_event_t *event)
{
    char *family_name = NULL;
    uint8_t family_name_size = 0;
    uint8_t worker_id = 0;
    int keep_alive_socket = -1;
    struct timeval timeout = get_timeout_val_sec(1);
    int res = 0;
    int connected = 0;
    static ngx_msec_t keep_alive_wait_period = 0;

    if (ngx_exiting) {
        is_timer_active = 0;
        write_dbg(DBG_LEVEL_INFO, "exiting without re-sched of ngx_send_keep_alive . ngx_exiting=%d", ngx_exiting);
        return;
    }

    keep_alive_interval_msec = get_keep_alive_interval_msec();
    if (keep_alive_interval_msec <= 0) {
        // Received invalid interval size, using default.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Received invalid interval size, using default value instead. Received value: %d, Default value: %u",
            keep_alive_interval_msec,
            DEFAULT_KEEP_ALIVE_INTERVAL_MSEC
        );
        keep_alive_interval_msec = DEFAULT_KEEP_ALIVE_INTERVAL_MSEC;
    }

    keep_alive_wait_period += timer_interval_msec;
    if (keep_alive_wait_period < keep_alive_interval_msec) {
        // Wait alive period is still within interval size.
        goto keep_alive_handler_out;
    }

    get_docker_id(&family_name);
    family_name_size = strlen(family_name);
    write_dbg(DBG_LEVEL_DEBUG, "Keep alive signal. Family id: %s, UID: %u", family_name, worker_id);

    if (keep_alive_socket > 0) {
        close(keep_alive_socket);
        keep_alive_socket = -1;
    }

    // Attempting to create a socket.
    keep_alive_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (keep_alive_socket < 0) {
        // Failed to create a socket.
        write_dbg(
            DBG_LEVEL_WARNING,
            "Could not create socket due to error. Socket number: %d, error: %s, errno: %d",
            keep_alive_socket,
            strerror(errno),
            errno
        );
        goto keep_alive_handler_out;
    }
    attachment_server.sun_family = AF_UNIX;
    strncpy(attachment_server.sun_path, SHARED_KEEP_ALIVE_PATH, sizeof(attachment_server.sun_path) - 1);

    // Attempting to connect to the nano service.
    connected = connect(keep_alive_socket, (struct sockaddr *)&attachment_server, sizeof(struct sockaddr_un));
    if (connected == -1) {
        // Failed to connect to the nano service.
        write_dbg(
            DBG_LEVEL_DEBUG,
            "Could not connect to nano service. Path: %s, Error: %s, Errno: %d",
            attachment_server.sun_path,
            strerror(errno),
            errno
        );
        goto keep_alive_handler_out;
    }
    write_dbg(DBG_LEVEL_DEBUG, "connected to socket: %d. sending keep alive signals");

    // Exchanging worker id with the nano service.
    res = exchange_communication_data_with_service(
        keep_alive_socket,
        &worker_id,
        sizeof(worker_id),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        // Failed to send worker id
        write_dbg_if_needed(DBG_LEVEL_WARNING, "Failed to send worker id");
        goto keep_alive_handler_out;
    }

    // Exchanging family name size with the nano service.
    res = exchange_communication_data_with_service(
        keep_alive_socket,
        &family_name_size,
        sizeof(family_name_size),
        WRITE_TO_SOCKET,
        &timeout
    );
    if (res <= 0) {
        // Failed to send family name size.
        write_dbg_if_needed(DBG_LEVEL_WARNING, "Failed to send family name size");
        goto keep_alive_handler_out;
    }

    if (family_name_size > 0) {
        // Exchanging family name with the nano service.
        res = exchange_communication_data_with_service(
            keep_alive_socket,
            family_name,
            family_name_size,
            WRITE_TO_SOCKET,
            &timeout
        );
        if (res <= 0) {
            // Failed to send family name.
            write_dbg_if_needed(DBG_LEVEL_WARNING, "Failed to send family name");
            goto keep_alive_handler_out;
        }
    }
    keep_alive_wait_period = 0;

keep_alive_handler_out:
    // Sends another signal.
    write_dbg(DBG_LEVEL_DEBUG, "send signal again in %u sec", (timer_interval_msec / 1000));
    ngx_add_timer(event, timer_interval_msec);
    if (keep_alive_socket > 0) {
        close(keep_alive_socket);
        keep_alive_socket = -1;
    }
}

static ngx_int_t
ngx_cp_attachment_init_worker(ngx_cycle_t *cycle)
{
    ngx_core_conf_t *core_main_conf;
    ngx_cp_attachment_conf_t *attachment_conf;

    write_dbg(DBG_LEVEL_INFO, "entering init worker. ngx_exiting=%d", ngx_exiting);

    attachment_conf = (ngx_cp_attachment_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_cp_attachment_module);
    if (attachment_conf && attachment_conf->num_of_workers) workers_amount_to_send = attachment_conf->num_of_workers;
    if (!workers_amount_to_send) {
        core_main_conf = (ngx_core_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_core_module);
        workers_amount_to_send = core_main_conf->worker_processes;
    }
    // Worker number 0 will always exist.
    // Therefore the single instance of the timer will be created and destroyed by it.
    if (ngx_worker == 0) {
        write_dbg(DBG_LEVEL_INFO, "Configured workers amount: %d", workers_amount_to_send);
        ngx_keep_alive_event.handler = ngx_send_keep_alive;
        ngx_keep_alive_event.log = cycle->log;
        ngx_keep_alive_event.data = &dumb_connection;
        dumb_connection.fd = (ngx_socket_t) -1;
        keep_alive_interval_msec = get_keep_alive_interval_msec();
        if (keep_alive_interval_msec == 0) {
            write_dbg(DBG_LEVEL_WARNING, "Invalid interval size: %u, set to default value: %d ", keep_alive_interval_msec, DEFAULT_KEEP_ALIVE_INTERVAL_MSEC);
            keep_alive_interval_msec = DEFAULT_KEEP_ALIVE_INTERVAL_MSEC;
        }

        ngx_add_timer(&ngx_keep_alive_event, timer_interval_msec);
        is_timer_active = 1;
        write_dbg(
            DBG_LEVEL_INFO,
            "Timer successfully added. Keep alive interval: %d, timer interval: %d",
            keep_alive_interval_msec,
            timer_interval_msec
        );
    }
    return NGX_OK;
}

static void
ngx_cp_attachment_fini_worker(ngx_cycle_t *cycle)
{
    write_dbg(DBG_LEVEL_INFO, "entering fini worker. is_timer_active=%d, ngx_exiting=%d", is_timer_active, ngx_exiting);

    // only worker number 0 (always exists since it is worker number 1 is allowed to create
    // the single instance of the timer and destroy it)
    if (ngx_worker != 0) return;

    (void)cycle;
    if (is_timer_active) ngx_del_timer(&ngx_keep_alive_event);
    write_dbg(DBG_LEVEL_INFO, "Timer successfully deleted");
    is_timer_active = 0;
}

static ngx_int_t
ngx_cp_attachment_init(ngx_conf_t *conf)
{
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *http_core_main_conf;
    write_dbg(DBG_LEVEL_TRACE, "Setting the memory pool used in the current context");
    if (conf->pool == NULL) {
        write_dbg(
            DBG_LEVEL_WARNING,
            "Failed to set memory pool in the current context, "
            "no memory pool has been allocated for the current configuration"
        );
        return NGX_ERROR;
    }
    set_memory_pool(conf->pool);
    write_dbg(
        DBG_LEVEL_TRACE,
        "Successfully set the memory pool in the current context. Setting attachment module's hooks."
    );

    http_core_main_conf = ngx_http_conf_get_module_main_conf(conf, ngx_http_core_module);
    handler = ngx_array_push(&http_core_main_conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (handler == NULL) {
        write_dbg(DBG_LEVEL_WARNING, "Failed to set HTTP request headers' handler");
        return NGX_ERROR;
    }
    *handler = ngx_http_cp_req_header_handler;

    ngx_http_next_response_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cp_res_header_filter;

    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_cp_req_body_filter;

    ngx_http_next_response_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cp_res_body_filter;

    write_dbg(DBG_LEVEL_TRACE, "Successfully set attachment module's hooks");

    return NGX_OK;
}
