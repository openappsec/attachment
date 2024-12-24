#include "nano_configuration.h"

#include "nano_attachment_common.h"
#include "nano_utils.h"
#include "nano_attachment_util.h"

#include <unistd.h>
#include <sys/types.h>

NanoCommunicationResult
init_attachment_config(NanoAttachment *attachment, const char *conf_path)
{
    int new_dbg_level = DBG_LEVEL_COUNT;

    if (access(conf_path, F_OK) != 0) return NANO_ERROR;

    if (attachment->is_configuration_updated == NANO_OK) return NANO_OK;

    // Initiate attachment using the file in the provided conf_path.
    if (!initAttachmentConfig(conf_path)) {
        write_dbg(attachment, attachment->worker_id, DBG_LEVEL_WARNING, "Failed to load the configuration");
        return NANO_ERROR;
    }

    new_dbg_level = getDbgLevel();

    if (new_dbg_level >= DBG_LEVEL_COUNT) {
        write_dbg(
            attachment,
            attachment->worker_id,
            DBG_LEVEL_WARNING,
            "Illegal debug level received: %d",
            new_dbg_level
        );
        attachment->is_configuration_updated = NANO_ERROR;
        return NANO_ERROR;
    }
    write_dbg(attachment, attachment->worker_id, DBG_LEVEL_DEBUG, "Setting debug level to: %d", new_dbg_level);
    // Setting a new debug level.
    attachment->dbg_level = new_dbg_level;

    // Setting fail open/close.
    attachment->fail_mode_verdict = isFailOpenMode() == 1 ? NANO_OK : NANO_ERROR;
    attachment->fail_open_timeout = getFailOpenTimeout();

    // Setting fail delayed open/close
    attachment->fail_mode_delayed_verdict = isFailOpenHoldMode() == 1 ? NANO_OK : NANO_ERROR;
    attachment->fail_open_delayed_timeout = getFailOpenHoldTimeout();

    // Setting attachment's variables.
    attachment->sessions_per_minute_limit_verdict =
        isFailOpenOnSessionLimit() ? ATTACHMENT_VERDICT_ACCEPT : ATTACHMENT_VERDICT_DROP;
    attachment->max_sessions_per_minute = getMaxSessionsPerMinute();
    attachment->inspection_mode = getInspectionMode();
    if (attachment->inspection_mode >= INSPECTION_MODE_COUNT) {
        write_dbg(
            attachment,
            attachment->worker_id,
            DBG_LEVEL_WARNING,
            "Illegal inspection mode received: %d",
            attachment->inspection_mode
        );
        attachment->is_configuration_updated = NANO_ERROR;
        return NANO_ERROR;
    }

    attachment->req_max_proccessing_ms_time = getReqProccessingTimeout();
    attachment->res_max_proccessing_ms_time = getResProccessingTimeout();
    attachment->registration_thread_timeout_msec = getRegistrationThreadTimeout();
    attachment->req_header_thread_timeout_msec = getReqHeaderThreadTimeout();
    attachment->req_body_thread_timeout_msec = getReqBodyThreadTimeout();
    attachment->res_header_thread_timeout_msec = getResHeaderThreadTimeout();
    attachment->res_body_thread_timeout_msec = getResBodyThreadTimeout();
    attachment->waiting_for_verdict_thread_timeout_msec = getWaitingForVerdictThreadTimeout();

    attachment->num_of_nano_ipc_elements = getNumOfNginxIpcElements();
    attachment->keep_alive_interval_msec = getKeepAliveIntervalMsec();

    // set_static_resources_path(getStaticResourcesPath());
    attachment->is_configuration_updated = NANO_OK;

    attachment->logging_data->dbg_level = attachment->dbg_level;
    attachment->logging_data->worker_id = attachment->worker_id;
    attachment->logging_data->fd = attachment->logging_fd;

    write_dbg(
        attachment,
        attachment->worker_id,
        DBG_LEVEL_INFO,
        "Successfully loaded configuration. "
        "inspection mode: %d, "
        "debug level: %d, "
        "failure mode: %s, "
        "fail mode timeout: %u msec, "
        "failure delayed mode: %s, "
        "fail mode delayed timeout: %u msec, "
        "sessions per minute limit verdict: %s, "
        "max sessions per minute: %u, "
        "req max processing time: %u msec, "
        "res max processing time: %u msec, "
        "registration thread timeout: %u msec, "
        "req start thread timeout: %u msec, "
        "req header thread timeout: %u msec, "
        "req body thread timeout: %u msec, "
        "res header thread timeout: %u msec, "
        "res body thread timeout: %u msec, "
        "delayed thread timeout: %u msec, "
        "static resources path: %s, "
        "num of nginx ipc elements: %u, "
        "keep alive interval msec: %u msec",
        attachment->inspection_mode,
        attachment->dbg_level,
        (attachment->fail_mode_verdict == NANO_OK ? "fail-open" : "fail-close"),
        attachment->fail_open_timeout,
        (attachment->fail_mode_delayed_verdict == NANO_OK ? "fail-open" : "fail-close"),
        attachment->fail_open_delayed_timeout,
        attachment->sessions_per_minute_limit_verdict == ATTACHMENT_VERDICT_ACCEPT ? "Accept" : "Drop",
        attachment->max_sessions_per_minute,
        attachment->req_max_proccessing_ms_time,
        attachment->res_max_proccessing_ms_time,
        attachment->registration_thread_timeout_msec,
        attachment->req_start_thread_timeout_msec,
        attachment->req_header_thread_timeout_msec,
        attachment->req_body_thread_timeout_msec,
        attachment->res_header_thread_timeout_msec,
        attachment->res_body_thread_timeout_msec,
        attachment->waiting_for_verdict_thread_timeout_msec,
        getStaticResourcesPath(),
        attachment->num_of_nano_ipc_elements,
        attachment->keep_alive_interval_msec
    );

    return NANO_OK;
}

NanoCommunicationResult
reset_attachment_config(NanoAttachment *attachment)
{
    write_dbg(attachment, attachment->worker_id, DBG_LEVEL_INFO, "Resetting attachment configuration");

    attachment->is_configuration_updated = NANO_ERROR;
    attachment->current_config_version++;
    return init_attachment_config(attachment, SHARED_ATTACHMENT_CONF_PATH);
}
