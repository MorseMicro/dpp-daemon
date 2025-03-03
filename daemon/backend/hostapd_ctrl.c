/*
 * Copyright 2022-2024 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <pthread.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>

#include <wpa_ctrl.h>

#include "backend.h"

#include "utils.h"
#include "helpers.h"
#include "logging.h"
#include "datalog.h"
#include "mmsm_data.h"


typedef struct backend_hostapd_ctrl_t
{
    /** The interface */
    mmsm_backend_intf_t intf;

    /** The path to the control socket */
    char control_sock[1024];

    /** The data log file handler */
    FILE *datalog;

    /** The wpa_ctrl structure that is used in the pattern monitor */
    struct wpa_ctrl *monitor_wpa_ctrl;
} backend_hostapd_ctrl_t;


/** Mutex to wrap wpa_ctrl_open, which relies on static memory */
pthread_mutex_t wpa_ctrl_open_mutex = PTHREAD_MUTEX_INITIALIZER;


static mmsm_error_code
backend_hostapd_ctrl_command(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t *command,
                             mmsm_data_item_t **result);

static mmsm_error_code
backend_hostapd_ctrl_monitor(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t **result);

/**
 * Reads the command information requested byt the user and formats it
 * into something that will be accepted by the backend.
 *
 * See the backend specific variants of this for details on the command
 * formatting.
 *
 * @param intf The backend interface to be invoked
 * @param args A va list of args that, in this case is a C string.
 *
 * @returns a data item that continas the processed args
 */
static mmsm_data_item_t *
backend_hostapd_process_request_args(mmsm_backend_intf_t *intf,
                                     va_list args);



static const mmsm_backend_intf_t intf = {
    .req_blocking = backend_hostapd_ctrl_command,
    .req_async = backend_hostapd_ctrl_monitor,
    .process_request_args = backend_hostapd_process_request_args,
};


static int
parse_item(char *line, mmsm_data_item_t *item)
{
    char *save_ptr = NULL;
    char *token;

    token = strtok_r(line, "= ", &save_ptr);
    if (token)
    {
        if (*token == '<')
        {
            while (*token != '>')
            {
                token++;
            }
            token++;
        }
        item->mmsm_key.type = MMSM_KEY_TYPE_STRING;
        item->mmsm_key.d.string = strdup(token);
        token = strtok_r(NULL, "=", &save_ptr);
        if (token)
        {
            item->mmsm_value = (uint8_t *)strdup(token);
            item->mmsm_value_len = strlen(token) + 1;
        }
        return 0;
    }
    return 1;
}


static mmsm_data_item_t *
parse_output(char *buf)
{
    char *save_ptr = NULL;
    char *token;
    mmsm_data_item_t *previous = NULL, *head = NULL;

    token = strtok_r(buf, "\n", &save_ptr);
    while (token != NULL)
    {
        if (!previous)
        {
            previous = calloc(1, sizeof(*previous));
            head = previous;
        }
        else
        {
            previous->mmsm_next = calloc(1, sizeof(*previous));
            previous = previous->mmsm_next;
        }
        if (previous == NULL)
        {
            mmsm_data_item_free(head);
            return NULL;
        }
        previous->mmsm_next = NULL;

        if (parse_item(token, previous))
        {
            mmsm_data_item_free(head);
            return NULL;
        }
        token = strtok_r(NULL, "\n", &save_ptr);
    }

    return head;
}


static mmsm_error_code
backend_hostapd_ctrl_monitor(mmsm_backend_intf_t *handle,
                             struct mmsm_data_item_t **result)
{
    int ret;
    backend_hostapd_ctrl_t *hostapd = get_container_from_intf(hostapd, handle);
    char out_buf[2048];
    size_t out_buf_len = sizeof(out_buf) - 1;

    if (hostapd->monitor_wpa_ctrl == NULL)
    {
        MMSM_ASSERT(pthread_mutex_lock(&wpa_ctrl_open_mutex) == 0);
        hostapd->monitor_wpa_ctrl = wpa_ctrl_open(hostapd->control_sock);
        MMSM_ASSERT(pthread_mutex_unlock(&wpa_ctrl_open_mutex) == 0);

        if (hostapd->monitor_wpa_ctrl == NULL)
        {
            LOG_ERROR("Failed to open control interface\n");
            return mmsm_unknown_error;
        }
        else
        {
            wpa_ctrl_attach(hostapd->monitor_wpa_ctrl);
        }
    }
    struct timeval tv;
    int res;
    int sock = wpa_ctrl_get_fd(hostapd->monitor_wpa_ctrl);
    fd_set rfds;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    res = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (res < 0)
        return mmsm_unknown_error;
    ret = wpa_ctrl_recv(hostapd->monitor_wpa_ctrl, out_buf, &out_buf_len);
    if(ret == 0)
    {
        out_buf[out_buf_len] = 0;
        LOG_VERBOSE("RX: \n");
        LOG_DATA(LOG_LEVEL_VERBOSE, (uint8_t *)out_buf, out_buf_len);
        *result = parse_output(out_buf);
    }

    return ret == 0 ? mmsm_success : mmsm_unknown_error;
}


static mmsm_error_code
backend_hostapd_ctrl_command(mmsm_backend_intf_t *handle,
                             mmsm_data_item_t *command,
                             mmsm_data_item_t **result)
{
    int ret;
    backend_hostapd_ctrl_t *hostapd = get_container_from_intf(hostapd, handle);
    char out_buf[2048];
    size_t out_buf_len = sizeof(out_buf) - 1;
    struct wpa_ctrl *wpa_ctrl = NULL;

    datalog_write_string(hostapd->datalog, "Tx %s\n", command->mmsm_value);

    MMSM_ASSERT(pthread_mutex_lock(&wpa_ctrl_open_mutex) == 0);
    wpa_ctrl = wpa_ctrl_open(hostapd->control_sock);
    MMSM_ASSERT(pthread_mutex_unlock(&wpa_ctrl_open_mutex) == 0);
    if (wpa_ctrl == NULL)
    {
        LOG_ERROR("Failed to open control interface\n");
        return mmsm_unknown_error;
    }

    ret = wpa_ctrl_request(wpa_ctrl, (char *)command->mmsm_value,
                           strlen((char *)command->mmsm_value),
                           out_buf, &out_buf_len, NULL);
    out_buf[out_buf_len] = 0;

    LOG_VERBOSE("RX:\n%s\n", out_buf);
    datalog_write_string(hostapd->datalog, "Rx\n%s\n", out_buf);

    *result = parse_output(out_buf);

    wpa_ctrl_close(wpa_ctrl);

    return ret == 0 ? mmsm_success : mmsm_unknown_error;
}


static mmsm_data_item_t *
backend_hostapd_process_request_args(mmsm_backend_intf_t *intf,
                                     va_list args)
{
    mmsm_data_item_t *arg = calloc(1, sizeof(*arg));

    arg->mmsm_value = (uint8_t *)strdup(va_arg(args, char *));
    arg->mmsm_key.type = MMSM_KEY_TYPE_STRING;
    arg->mmsm_key.d.string = strdup((char *)arg->mmsm_value);
    arg->mmsm_value_len = strlen((char *)arg->mmsm_value) + 1;
    return arg;
}


mmsm_backend_intf_t *
mmsm_backend_hostapd_ctrl_create(const char *control_sock)
{
    backend_hostapd_ctrl_t *module;

    LOG_INFO("Instantiating hostapd control backend\n");

    module = calloc(1, sizeof(*module));
    if (!module)
        return NULL;

    if (strlen(control_sock) > sizeof(module->control_sock) - 1)
    {
        free(module);
        return NULL;
    }

    strncpy(module->control_sock, control_sock, sizeof(module->control_sock));
    module->control_sock[sizeof(module->control_sock) - 1] = '\0';
    module->intf = intf;
    module->datalog = datalog_create("hostapd");

    return &module->intf;
}


void
mmsm_backend_hostapd_ctrl_destroy(mmsm_backend_intf_t *handle)
{
    backend_hostapd_ctrl_t *hostapd = get_container_from_intf(hostapd, handle);
    datalog_close(hostapd->datalog);
    hostapd->datalog = NULL;
    if (hostapd->monitor_wpa_ctrl)
    {
        wpa_ctrl_detach(hostapd->monitor_wpa_ctrl);
        wpa_ctrl_close(hostapd->monitor_wpa_ctrl);
    }
    free(hostapd);
}
