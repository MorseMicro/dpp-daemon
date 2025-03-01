/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <time.h>

#include "backend.h"
#include "utils.h"
#include "mmsm_data.h"
#include "helpers.h"
#include "datalog.h"


typedef struct backend_nl80211_t
{
    /** The interface */
    mmsm_backend_intf_t intf;

    /** The data log file handler */
    FILE *datalog;

    /** The nl socket structure that is used in the pattern monitor */
    struct nl_sock *sock;

} backend_nl80211_t;


typedef struct nl80211_params_t
{
    backend_nl80211_t *backend;
    mmsm_data_item_t **result;
} nl80211_params_t;


static mmsm_error_code
backend_nl80211_ctrl_monitor(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t **result);


static mmsm_error_code
backend_nl80211_sync_command(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t *command,
                             mmsm_data_item_t **result);


static mmsm_data_item_t *
backend_nl80211_process_request_args(mmsm_backend_intf_t *intf,
                                     va_list args);


static mmsm_error_code
backend_nl80211_stop(mmsm_backend_intf_t *intf);


static mmsm_backend_intf_t nl80211_intf =
{
    .req_blocking = backend_nl80211_sync_command,
    .req_async = backend_nl80211_ctrl_monitor,
    .process_request_args = backend_nl80211_process_request_args,
    .stop = backend_nl80211_stop,
};


static mmsm_error_code backend_nl80211_stop(mmsm_backend_intf_t *intf)
{
    return mmsm_success;
}


/**
 * Creates and connects an nl80211 socket, and provides the ID.
 */
static struct nl_sock *
backend_nl80211_socket_connect(int *id)
{
    struct nl_sock *sock;

    sock = nl_socket_alloc();
    if (!sock)
    {
        LOG_ERROR("Failed to allocate netlink socket.\n");
        return NULL;
    }
    nl_socket_set_buffer_size(sock, 8192, 8192);

    if (genl_connect(sock))
    {
        LOG_ERROR("Failed to connect to netlink socket.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return NULL;
    }

    *id = genl_ctrl_resolve(sock, "nl80211");
    if (*id < 0)
    {
        LOG_ERROR("Nl80211 interface not found.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return NULL;
    }

    return sock;
}


static bool
attr_looks_nested(struct nlattr *iter, int attr_len)
{
    while (nla_ok(iter, attr_len))
    {
        iter = nla_next(iter, &attr_len);
    }

    return attr_len == 0;
}


/**
 * Navigates the provided attribute data, filling mmsm_data_item_t structure
 */
static mmsm_data_item_t *
navigate_attrs(struct nlattr *attr_data, int attr_len)
{
    struct nlattr *nla;
    int remaining;
    mmsm_data_item_t *iter = NULL, *head = NULL;

    nla_for_each_attr(nla,
                      attr_data,
                      attr_len,
                      remaining)
    {
        int attr = nla_type(nla);
        int length = nla_len(nla);
        uint8_t *data = (uint8_t *)nla_data(nla);

        if (iter != NULL)
        {
            iter->mmsm_next = calloc(1, sizeof(*iter->mmsm_next));
            iter = iter->mmsm_next;
        }
        else
        {
            head = calloc(1, sizeof(*iter->mmsm_next));
            iter = head;
        }

        iter->mmsm_key.type = MMSM_KEY_TYPE_U32;
        iter->mmsm_key.d.u32 = attr;
        iter->mmsm_value_len = length;
        iter->mmsm_value = calloc(1, length);
        memcpy(iter->mmsm_value, data, length);

        if (attr_looks_nested((struct nlattr *)data, length))
        {
            iter->mmsm_sub_values = navigate_attrs((struct nlattr *)data,
                                                   length);
        }
    }

    return head;
}


static int
sync_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nla;
    int len;
    nl80211_params_t *params = (nl80211_params_t *)arg;

    LOG_VERBOSE("RX: \n");
    LOG_DATA(LOG_LEVEL_VERBOSE,
             (uint8_t *)nlmsg_hdr(msg),
             nlmsg_get_max_size(msg));
    datalog_write_string(params->backend->datalog, "Rx\n");
    datalog_write_data(params->backend->datalog,
        (uint8_t *)nlmsg_hdr(msg), nlmsg_get_max_size(msg));

    mmsm_data_item_t **result = params->result;
    mmsm_data_item_t *iter = NULL;
    mmsm_data_item_t *entry = calloc(1, sizeof(*entry));

    nla = genlmsg_attrdata(gnlh, 0);
    len = genlmsg_attrlen(gnlh, 0);

    entry->mmsm_sub_values = navigate_attrs(nla, len);

    if (*result == NULL)
    {
        *result = entry;
    }
    else
    {
        iter = *result;
        while (iter->mmsm_next)
        {
            iter = iter->mmsm_next;
        }
        iter->mmsm_next = entry;
    }

    return NL_SKIP;
}


static int
sync_finish_handler(struct nl_msg *msg, void *arg) {
    bool *done = arg;
    *done = true;

    return NL_SKIP;
}


static int
nlCallback(struct nl_msg* msg, void* arg)
{
    struct nlattr *nla;
    int len;
    nl80211_params_t *params = (nl80211_params_t *)arg;

    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(ret_hdr);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    LOG_VERBOSE("RX: \n");
    LOG_DATA(LOG_LEVEL_VERBOSE,
             (uint8_t *)nlmsg_hdr(msg),
             nlmsg_get_max_size(msg));

    datalog_write_string(params->backend->datalog, "Rx\n");
    datalog_write_data(params->backend->datalog,
        (uint8_t *)nlmsg_hdr(msg), nlmsg_get_max_size(msg));

    mmsm_data_item_t **result = params->result;
    mmsm_data_item_t *iter = NULL;
    mmsm_data_item_t *entry = calloc(1, sizeof(*entry));

    if (!entry)
        return NL_STOP;

    nla = genlmsg_attrdata(gnlh, 0);
    len = genlmsg_attrlen(gnlh, 0);

    entry->mmsm_sub_values = navigate_attrs(nla, len);

    if (*result == NULL)
    {
        *result = entry;
    }
    else
    {
        iter = *result;
        while (iter->mmsm_next)
        {
            iter = iter->mmsm_next;
        }
        iter->mmsm_next = entry;
    }

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);


    entry->mmsm_key.d.u32 = gnlh->cmd;
    entry->mmsm_key.type = MMSM_KEY_TYPE_U32;

    return 0;
}


static mmsm_error_code
backend_nl80211_ctrl_monitor(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t **result)
{
    mmsm_error_code err = mmsm_success;
    backend_nl80211_t *nl80211 =
            get_container_from_intf(nl80211, intf);
    nl80211_params_t params = {
        .backend = nl80211,
        .result = result
    };
    int sk_fd;
    fd_set rfds;
    int ret;

    if (nl80211->sock == NULL)
    {
        nl80211->sock = nl_socket_alloc();
        if (!nl80211->sock)
        {
            LOG_ERROR("Failed to open nl80211 interface\n");
            err = mmsm_unknown_error;
            goto done;
        }
        ret = genl_connect(nl80211->sock);
        if (ret < 0)
        {
            LOG_ERROR("no connect\n");
            goto done;
        }

        ret = genl_ctrl_resolve(nl80211->sock, "nl80211");
        ret = genl_ctrl_resolve_grp(nl80211->sock, "nl80211", "mlme");
        if (ret < 0)
        {
            LOG_ERROR("MLME group not found\n");
            goto done;
        }
        ret = nl_socket_add_membership(nl80211->sock, ret);
        if (ret < 0)
        {
            LOG_ERROR("MLME group not found\n");
            goto done;
        }

        nl_socket_disable_seq_check(nl80211->sock);

        ret = nl_socket_modify_cb(nl80211->sock, NL_CB_VALID,
                                  NL_CB_CUSTOM, nlCallback, &params);
        if (ret < 0)
        {
            LOG_ERROR("Unable to register callback\n");
            goto done;
        }
    }
    struct timeval tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);

    sk_fd = nl_socket_get_fd(nl80211->sock);
    FD_SET(sk_fd, &rfds);
    ret = select(sk_fd + 1, &rfds, NULL, NULL, &tv);
    if (ret == 0)
    {
        goto done;
    }

    ret = nl_recvmsgs_default(nl80211->sock);
    if (ret < 0) {
        LOG_ERROR("Error receiving message\n");
    }

done:

    return err;
}


static mmsm_error_code
backend_nl80211_sync_command(mmsm_backend_intf_t *intf,
                             mmsm_data_item_t *command,
                             mmsm_data_item_t **result)
{
    struct nl_sock *sock = NULL;
    struct nl_cb *nlcb = NULL;
    bool done = false;
    mmsm_error_code err = mmsm_success;
    int id;
    mmsm_data_item_t *cur;
    backend_nl80211_t *nl80211 =
            get_container_from_intf(nl80211, intf);
    nl80211_params_t params = {
        .backend = nl80211,
        .result = result
    };

    struct nl_msg* msg = nlmsg_alloc();
    if (!msg)
    {
        LOG_ERROR("Failed to allocate netlink message.\n");
        return mmsm_unknown_error;
    }

    sock = backend_nl80211_socket_connect(&id);
    if (!sock)
    {
        LOG_ERROR("Failed to open nl80211 interface\n");
        err = mmsm_unknown_error;
        goto done;
    }

    cur = command;
    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                id,
                0,
                NLM_F_DUMP,
                cur->mmsm_key.d.u32,
                0);

    while (cur->mmsm_next)
    {
        cur = cur->mmsm_next;
        nla_put(msg, cur->mmsm_key.d.u32, cur->mmsm_value_len, cur->mmsm_value);
    }

    nlcb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!nlcb)
    {
        LOG_ERROR("Failed to allocate callback\n");
        err = mmsm_unknown_error;
        goto done;
    }

    datalog_write_string(nl80211->datalog, "Tx\n");
    datalog_write_data(nl80211->datalog,
        (uint8_t *)nlmsg_hdr(msg),
        nlmsg_datalen(nlmsg_hdr(msg)) +  NLMSG_HDRLEN);

    nl_send_auto(sock, msg);

    nl_cb_set(nlcb, NL_CB_VALID , NL_CB_CUSTOM, sync_callback, &params);
    nl_cb_set(nlcb, NL_CB_FINISH, NL_CB_CUSTOM, sync_finish_handler, &done);

    while (!done)
        nl_recvmsgs(sock, nlcb);

    err = mmsm_success;

done:
    if (nlcb)
        nl_cb_put(nlcb);

    if (msg)
        nlmsg_free(msg);

    if (sock)
    {
        nl_close(sock);
        nl_socket_free(sock);
    }

    return err;
}


#define PACK_VA_ARG(dest, type)                             \
    do {                                                    \
        type value = (type)va_arg(args, int);               \
        (dest)->mmsm_value = calloc(1, sizeof(type));       \
        memcpy((dest)->mmsm_value, &(value), sizeof(type)); \
        (dest)->mmsm_value_len = sizeof(type);              \
    } while (0)


static mmsm_data_item_t *
backend_nl80211_process_request_args(mmsm_backend_intf_t *intf,
                                     va_list args)
{
    mmsm_data_item_t *arg, *cur;
    int attr_id;
    int type;

    arg = calloc(1, sizeof(mmsm_data_item_t));
    cur = arg;
    cur->mmsm_key.type = MMSM_KEY_TYPE_U32;
    cur->mmsm_key.d.u32 = va_arg(args, uint32_t);

    attr_id = va_arg(args, int);
    while (attr_id != -1)
    {
        cur->mmsm_next = calloc(1, sizeof(mmsm_data_item_t));
        cur = cur->mmsm_next;

        cur->mmsm_key.type = MMSM_KEY_TYPE_U32;
        cur->mmsm_key.d.u32 = attr_id;

        type = va_arg(args, int);
        switch (type)
        {
            case NLA_U8:
                PACK_VA_ARG(cur, uint8_t);
                break;

            case NLA_U16:
                PACK_VA_ARG(cur, uint16_t);
                break;

            case NLA_U32:
                PACK_VA_ARG(cur, uint32_t);
                break;

            case NLA_U64:
                PACK_VA_ARG(cur, uint64_t);
                break;

            case NLA_STRING:
                cur->mmsm_value = (uint8_t *)strdup(va_arg(args, char *));
                cur->mmsm_value_len = strlen((char *)cur->mmsm_value);
                break;

            case NLA_FLAG:
            default:
                printf("Arg type %d not supported\n", type);
                mmsm_data_item_free(arg);
                return NULL;
        }

        attr_id = va_arg(args, int);
    }
    return arg;
}


mmsm_backend_intf_t *
mmsm_backend_nl80211_create(void)
{
    backend_nl80211_t *module;
    LOG_INFO("Instantiating NL80211 backend\n");

    module = calloc(1, sizeof(*module));
    if (!module)
        return NULL;

    module->intf = nl80211_intf;
    module->datalog = datalog_create("nl80211");

    return &module->intf;
}


void
mmsm_backend_nl80211_destroy(mmsm_backend_intf_t *handle)
{
    backend_nl80211_t *nl80211 = get_container_from_intf(nl80211, handle);
    datalog_close(nl80211->datalog);
    nl80211->datalog = NULL;
    if (nl80211->sock)
    {
        nl_socket_free(nl80211->sock);
    }
    free(nl80211);

}
