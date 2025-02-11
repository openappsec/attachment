#include "nano_attachment_thread.h"

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "nano_attachment_sender.h"
#include "nano_attachment_sender_thread.h"
#include "nano_utils.h"
#include "nano_attachment_metric.h"

///
/// @brief Calculate the processing time of a transaction and update the session data accordingly.
///
/// @param session_data_p Pointer to the HttpSessionData struct containing session data.
/// @param thread_time_begin Pointer to the timespec struct representing the start time of the transaction.
/// @param transaction_type The type of transaction (REQUEST or RESPONSE).
///
static void
CalcProcessingTime(
    HttpSessionData *session_data_p,
    struct timespec *thread_time_begin,
    TransactionType transaction_type
)
{
    struct timespec thread_time_end;

    if (transaction_type == START || transaction_type == METRICS) return;

    clock_gettime(CLOCK_REALTIME, &thread_time_end);

    double begin_usec = (thread_time_begin->tv_sec * 1000 * 1000) + (thread_time_begin->tv_nsec / 1000);
    double end_usec = (thread_time_end.tv_sec * 1000 * 1000) + (thread_time_end.tv_nsec / 1000);
    double elapsed = end_usec - begin_usec;
    if (transaction_type == REQUEST) {
        session_data_p->req_proccesing_time += elapsed;
    } else {
        session_data_p->res_proccesing_time += elapsed;
    }
}

///
/// @brief runs the provided routine with the arguments in a non thread and without a timeout.
/// @param[in, out] attachment A pointer to the NanoAttachment struct.
/// @param[in] session_id The session ID.
/// @param[in, out] thread_func A pointer to the provided routine to run in a thread.
/// @param[in, out] arg Routine's arguments.
/// @param[in, out] func_name Called thread timeout.
/// @returns 1
///
int
NanoRunInWithoutThreadTimeout(
    NanoAttachment *attachment,
    SessionID session_id,
    CpThreadRoutine thread_func,
    void *arg,
    char *func_name
)
{
    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Executing cb in blocking mode, fn=%s",
        func_name
    );

    thread_func(arg);

    return 1;
}

int
NanoRunInThreadTimeout(
    NanoAttachment *attachment,
    AttachmentData *data,
    CpThreadRoutine thread_func,
    void *arg,
    int timeout_msecs,
    char *func_name,
    TransactionType transaction_type
)
{
    int status = 0;
    int ret = 0;
    void *res = NULL;
    pthread_t thread;
    struct timespec ts;
    struct timespec thread_time_begin;
    uint32_t session_id;
    HttpEventThreadCtx *ctx = (HttpEventThreadCtx *)arg;

    session_id = (data == NULL) ? attachment->worker_id : data->session_data->session_id;
    init_thread_ctx(ctx, attachment, data);

    if (attachment->inspection_mode == NO_THREAD) {
        return NanoRunInWithoutThreadTimeout(attachment, session_id, thread_func, arg, func_name);
    }

    if (clock_gettime(CLOCK_REALTIME, &thread_time_begin) == -1) {
        updateMetricField(attachment, THREAD_FAILURE, 1);
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_ERROR,
            "clock_gettime(CLOCK_REALTIME) failed. Status: %s",
            strerror(errno)
        );
        return 0;
    }

    /// Runs the routine in a dedicated thread.
    write_dbg(
        attachment,
        session_id,
        DBG_LEVEL_TRACE,
        "Executing cb in dedicated thread, fn=%s",
        func_name
    );

    if (pthread_create(&thread, NULL, thread_func, arg) != 0) {
        updateMetricField(attachment, THREAD_FAILURE, 1);
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_TRACE,
            "pthread_create failed with errno=%d, fn=%s",
            errno,
            func_name
        );
        return 0;
    }

    if (attachment->inspection_mode == BLOCKING_THREAD) {
        // Runs the function in a blocking thread.
        status = pthread_join(thread, &res);
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_TRACE,
            "pthread_join returned from blocking call. status=%d, fn=%s",
            status,
            func_name
        );
        return status == 0;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        updateMetricField(attachment, THREAD_FAILURE, 1);
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_ERROR,
            "clock_gettime(CLOCK_REALTIME) failed. Status: %s",
            strerror(errno)
        );
        return 0;
    }

    // Convert milliseconds to timespec
    ts.tv_sec += timeout_msecs / 1000;
    ts.tv_nsec += (timeout_msecs % 1000) * 1000 * 1000;
    if (ts.tv_nsec > 1000 * 1000 * 1000) {
        ts.tv_nsec -= 1000 * 1000 * 1000;
        ++ts.tv_sec;
    }

    long long tv_nsec = ts.tv_nsec + (timeout_msecs % 1000) * 1000000;

    ts.tv_sec += timeout_msecs / 1000 + tv_nsec / 1000000000;
    ts.tv_nsec = tv_nsec % 1000000000;

    status = pthread_timedjoin_np(thread, NULL, &ts);

    if (status != 0) {
        write_dbg(
            attachment,
            session_id,
            status == ETIMEDOUT ? DBG_LEVEL_DEBUG : DBG_LEVEL_WARNING,
            "pthread_timejoin_np returns with %d (%s), fn=%s",
            status,
            strerror(status),
            func_name
        );

        ret = pthread_cancel(thread);
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_DEBUG,
            "pthread_cancel returns with ret=%d, fn=%s",
            ret,
            func_name
        );

        ret = pthread_join(thread, &res);
        if (ret != 0) {
            updateMetricField(attachment, THREAD_FAILURE, 1);
            write_dbg(
                attachment,
                session_id,
                DBG_LEVEL_WARNING,
                "pthread_join failed while fail open is enabled. RET=%d, fn=%s",
                ret,
                func_name
            );
            return ret != 0;
        }

        updateMetricField(attachment, res == PTHREAD_CANCELED ? THREAD_TIMEOUT : THREAD_FAILURE, 1);
        if (res == PTHREAD_CANCELED) {
            write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "thread was canceled, fn=%s", func_name);
        }

        write_dbg(attachment, session_id, DBG_LEVEL_DEBUG, "pthread_join returns with ret=%d", ret);
    } else {
        write_dbg(
            attachment,
            session_id,
            DBG_LEVEL_TRACE,
            "Successfully executed thread. fn=%s",
            func_name
        );
    }

    if (data != NULL) {
        CalcProcessingTime(data->session_data, &thread_time_begin, transaction_type);
    }
    return status == 0;
}
