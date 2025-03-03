/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "smart_manager.h"
#include "utils.h"

/**
 * A polling monitor instance.
 */
typedef struct polling_monitor_t
{
    /** The backend interface to monitor on */
    mmsm_backend_intf_t *intf;

    /** The callback to fire when data is available */
    mmsm_data_callback_fn_t callback;

    /** The context to provide back to the user */
    void *context;

    /** The command to periodically send */
    mmsm_data_item_t *command;

    /** How often to send the command, in milliseconds */
    uint32_t frequency_ms;

    /** The next time that sending the command is due */
    struct timespec next_time;

    /** The next instance in the list */
    struct polling_monitor_t *next;
} polling_monitor_t;


/**
 * An async monitor instance.
 */
typedef struct async_monitor_t
{
    /** The backend interface to monitor on */
    mmsm_backend_intf_t *intf;

    /** The callback to fire when data is available */
    mmsm_data_callback_fn_t callback;

    /** The command to periodically send */
    mmsm_data_item_t *command;

    /** The context to provide back to the user */
    void *context;

    /** The pattern to monitor for */
    char pattern[1024];

    /** The next instance in the list */
    struct async_monitor_t *next;
} async_monitor_t;


/**
 * A list of all interfaces that have async operations.
 */
typedef struct async_intf_def_t
{
    /** This is a list of async operations on the following interface. */
    mmsm_backend_intf_t *this_interface;

    /** The thread that will run this list. */
    pthread_t async_monitor_thread;

    /** The head of the list of asynch operations on this interface. */
    struct async_monitor_t *head;

    /** The next interface on which there are async ops. */
    struct async_intf_def_t *next;

} async_intf_def_t;

/** The head of the list of interfaces on which there are async monitors. */
static async_intf_def_t *async_interface_list = NULL;

/** The mutex for communication to the async thread */
static pthread_mutex_t async_mutex = PTHREAD_MUTEX_INITIALIZER;

/** The pthread_t instance for the polling thread */
static pthread_t polling_monitor_thread;

/** The mutex for communication to the polling thread */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/** The condition to notify changes to the polling thread */
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/** Whether or not the system is running */
static bool is_running = false;

/** The polling monitor list */
static polling_monitor_t *polling_monitor_list = NULL;

/**
 * Adds the given number of milliseconds to the timespec value.
 */
static void
timespec_add_ms(struct timespec *ts, uint32_t milliseconds)
{
    ts->tv_sec += milliseconds / 1000ul;
    ts->tv_nsec += (milliseconds % 1000ul) * 1000000ul;
    ts->tv_sec += ts->tv_nsec / 1000000000ull;
    ts->tv_nsec = ts->tv_nsec % 1000000000ull;
}


/**
 * Returns true if lhs is at an earlier point in time than rhs
 */
static bool
timespec_is_less_than(const struct timespec *lhs, const struct timespec *rhs)
{
    if (lhs->tv_sec == rhs->tv_sec)
        return lhs->tv_nsec < rhs->tv_nsec;
    return lhs->tv_sec < rhs->tv_sec;
}


static mmsm_data_item_t *
mmsm_internal_request(mmsm_backend_intf_t *intf,
                      mmsm_data_item_t *command)
{
    mmsm_data_item_t *rsp = NULL;

    if (intf->req_blocking)
    {
        mmsm_error_code err = intf->req_blocking(intf, command, &rsp);
        if (err != mmsm_success)
        {
            mmsm_data_item_free(rsp);
            LOG_ERROR("req_blocking failed: %d\n", err);
            return NULL;
        }
    }
    else if (intf->req_async)
    {
        /* Not implemented yet */
        return NULL;
    }

    return rsp;
}


/**
 * Runs an async monitor.
 *
 * The thread monitors the polling_monitor_list linked list, waiting for any of
 * them to expire. When one expires, it sends the request as a blocking request
 * and fires the provided callback.
 *
 * Both of those actions block the polling monitor thread and so user code that
 * blocks the callback while waiting for another callback to arrive will
 * deadlock!
 *
 * Mutexes are not held during the callback so the user can send requests in a
 * callback.
 */
static void *
async_monitor_thread_fn(void *arg)
{
    async_intf_def_t *current_list = (async_intf_def_t *)arg;

    MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);

    /* coverity[missing_lock:SUPPRESS] */
    while (is_running && current_list->head)
    {
        async_monitor_t *iter;
        mmsm_data_item_t *result = NULL;

        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        current_list->this_interface->req_async(current_list->this_interface,
                                                &result);

        if (!result)
        {
            MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);
            continue;
        }

        for (iter = current_list->head;
             iter;
             iter = iter->next)
        {
            if (mmsm_find_key(result, &iter->command->mmsm_key)
                && iter->callback)
            {
                iter->callback(iter->context, iter->intf, result);
            }
        }
        MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);

        mmsm_data_item_free(result);

    }
    MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);

    return NULL;
}


/**
 * Runs the polling monitor.
 *
 * The thread monitors the polling_monitor_list linked list, waiting for any of
 * them to expire. When one expires, it sends the request as a blocking request
 * and fires the provided callback.
 *
 * Both of those actions block the polling monitor thread and so user code that
 * blocks the callback while waiting for another callback to arrive will
 * deadlock!
 *
 * Mutexes are not held during the callback so the user can send requests in a
 * callback.
 */
static void *
polling_monitor_thread_fn(void *arg)
{
    UNUSED(arg);

    MMSM_ASSERT(pthread_mutex_lock(&mutex) == 0);

    /* coverity[missing_lock:SUPPRESS] */
    while (is_running)
    {
        polling_monitor_t *iter;
        struct timespec now;
        struct timespec *next_expires = NULL;
        bool fired_one = false;

        clock_gettime(CLOCK_REALTIME, &now);

        for (iter = polling_monitor_list;
             iter;
             iter = iter->next)
        {
            if (next_expires == NULL ||
                timespec_is_less_than(&iter->next_time, next_expires))
            {
                next_expires = &iter->next_time;
            }

            if (timespec_is_less_than(&iter->next_time, &now))
            {
                mmsm_data_item_t *result;

                fired_one = true;
                iter->next_time = now;
                timespec_add_ms(&iter->next_time, iter->frequency_ms);

                MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
                result = mmsm_internal_request(iter->intf, iter->command);
                iter->callback(iter->context, iter->intf, result);
                MMSM_ASSERT(pthread_mutex_lock(&mutex) == 0);

                mmsm_data_item_free(result);

                break;
            }
        }

        if (fired_one)
            continue;

        /* Wait for next monitor to expire, or the condition to fire */
        if (next_expires)
        {
            int ret = pthread_cond_timedwait(&cond, &mutex, next_expires);
            MMSM_ASSERT(ret == 0 || ret == ETIMEDOUT);
        }
        else
        {
            MMSM_ASSERT(pthread_cond_wait(&cond, &mutex) == 0);
        }
    }
    MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);

    return NULL;
}


mmsm_data_item_t *
mmsm_request(mmsm_backend_intf_t *intf, ...)
{
    mmsm_data_item_t *rsp = NULL;
    va_list args;
    mmsm_data_item_t *command;

    va_start(args, intf);
    MMSM_ASSERT(intf->process_request_args);
    command = intf->process_request_args(intf, args);
    if (command)
        rsp = mmsm_internal_request(intf, command);

    va_end(args);

    mmsm_data_item_free(command);

    return rsp;
}


mmsm_error_code
mmsm_monitor_polling(mmsm_backend_intf_t *intf,
                     uint32_t frequency_ms,
                     mmsm_data_callback_fn_t callback,
                     void *context,
                     ...)
{
    polling_monitor_t *monitor;
    va_list args;

    MMSM_ASSERT(pthread_mutex_lock(&mutex) == 0);

    monitor = malloc(sizeof(*monitor));
    if (!monitor)
    {
        MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
        return mmsm_unknown_error;
    }

    va_start(args, context);
    monitor->command = intf->process_request_args(intf, args);
    va_end(args);

    if (!monitor->command)
    {
        mmsm_data_item_free(monitor->command);
        free(monitor);
        MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
        return mmsm_unknown_error;
    }

    monitor->intf = intf;
    monitor->callback = callback;
    monitor->context = context;

    monitor->frequency_ms = frequency_ms;
    monitor->next_time.tv_sec = 0;

    monitor->next = polling_monitor_list;
    polling_monitor_list = monitor;

    MMSM_ASSERT(pthread_cond_signal(&cond) == 0);
    MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);

    return mmsm_success;
}


static void
ail_init(async_intf_def_t *this_ail, mmsm_backend_intf_t *intf)
{
    this_ail->this_interface = intf;
    this_ail->head = NULL;
    this_ail->next = NULL;
}


mmsm_error_code
mmsm_monitor_pattern(mmsm_backend_intf_t *intf,
                     const char *pattern,
                     mmsm_data_callback_fn_t callback,
                     void *context,
                     ...)
{
    async_monitor_t *monitor;
    va_list args;
    async_intf_def_t *current_list;

    MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);
    current_list = async_interface_list;
    if (!async_interface_list)
    {
        /*
         * If this is the first async monitor that we are adding then we create
         * the first async_interface_list entry.
         */
        async_interface_list = calloc(1, sizeof(*async_interface_list));
        if (!async_interface_list)
        {
            MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
            return mmsm_unknown_error;
        }

        ail_init(async_interface_list, intf);
        current_list = async_interface_list;
    }
    else
    {
        /* If we already have an async_interface_list then we need to search it
         * to see if we already have an entry in there for the intf on which we
         * want to create this async monitor. We only need to create a new entry
         * on the async_interface_list if this is the first async monitor on the
         * intf.
         */
        while (current_list->this_interface != intf)
        {
            if (current_list->next == NULL)
            {
                current_list->next = calloc(1, sizeof *async_interface_list);
                if (!current_list->next)
                {
                    MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
                    return mmsm_unknown_error;
                }
                ail_init(current_list->next, intf);
                current_list = current_list->next;
                break;
            }
            current_list = current_list->next;
        }
    }

    monitor = malloc(sizeof(*monitor));
    if (!monitor)
    {
        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        return mmsm_unknown_error;
    }

    va_start(args, context);
    monitor->command = intf->process_request_args(intf, args);
    va_end(args);

    if (!monitor->command)
    {
        mmsm_data_item_free(monitor->command);
        free(monitor);
        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        return mmsm_unknown_error;
    }


    monitor->intf = intf;
    monitor->callback = callback;
    monitor->context = context;

    strncpy(monitor->pattern, pattern, sizeof(monitor->pattern));
    monitor->pattern[sizeof(monitor->pattern) - 1] = '\0';
    monitor->next = current_list->head;
    current_list->head = monitor;

    MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);

    return mmsm_success;
}


mmsm_error_code
mmsm_start(void)
{
    MMSM_ASSERT(pthread_mutex_lock(&mutex) == 0);
    MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);

    if (is_running)
    {
        MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        return mmsm_unknown_error;
    }

    is_running = true;

    MMSM_ASSERT(pthread_create(&polling_monitor_thread,
                               NULL,
                               polling_monitor_thread_fn,
                               NULL) == 0);

    async_intf_def_t *current_list = async_interface_list;

    while (current_list)
    {
        MMSM_ASSERT(pthread_create(&current_list->async_monitor_thread,
                                   NULL,
                                   async_monitor_thread_fn,
                                   current_list) == 0);
        current_list = current_list->next;
    }
    MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
    MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);

    return mmsm_success;
}


mmsm_error_code
mmsm_stop(void)
{
    MMSM_ASSERT(pthread_mutex_lock(&mutex) == 0);
    MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);

    if (!is_running)
    {
        MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        return mmsm_unknown_error;
    }

    is_running = false;

    MMSM_ASSERT(pthread_cond_signal(&cond) == 0);
    MMSM_ASSERT(pthread_mutex_unlock(&mutex) == 0);
    MMSM_ASSERT(pthread_join(polling_monitor_thread, NULL) == 0);

    struct async_intf_def_t *iter = async_interface_list;
    while (iter)
    {
        MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);
        MMSM_ASSERT(pthread_join(iter->async_monitor_thread, NULL) == 0);
        MMSM_ASSERT(pthread_mutex_lock(&async_mutex) == 0);

        iter = iter->next;
    }
    MMSM_ASSERT(pthread_mutex_unlock(&async_mutex) == 0);

    return mmsm_success;
}
