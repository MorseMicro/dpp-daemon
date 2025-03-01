/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include "dpp_mdns.h"
#include <avahi-core/core.h>
#include <avahi-core/log.h>
#include <avahi-core/publish.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>

/** The pthread_t instance for polling mDNS requests */
pthread_t polling_mdns_thread;

static AvahiSEntryGroup *group = NULL;
static AvahiSimplePoll *simple_poll = NULL;
static char *name = NULL;
static uint16_t portno = 0;
static char *service_name = NULL;

static void create_dpp_services(AvahiServer *server);

static void
cleanup()
{
    if (simple_poll)
    {
        avahi_simple_poll_free(simple_poll);
        simple_poll = NULL;
    }

    if (service_name)
    {
        free(service_name);
        service_name = NULL;
    }

    if (name)
    {
        avahi_free(name);
        name = NULL;
    }
}

static void
dpp_entry_group_callback(AvahiServer *server,
                         AvahiSEntryGroup *entry_group,
                         AvahiEntryGroupState entry_state,
                         void *userdata)
{
    (void)userdata;
    switch (entry_state)
    {
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
        {
            LOG_INFO("Service '%s' successfully established.\n", name);
            break;
        }

        case AVAHI_ENTRY_GROUP_COLLISION:
        {
            char *alt_name;
            alt_name = avahi_alternative_service_name(name);
            LOG_WARN("Renaming to '%s' due to service name collision\n", alt_name);

            avahi_free(name);
            name = alt_name;
            create_dpp_services(server);
            break;
        }

        case AVAHI_ENTRY_GROUP_FAILURE:
        {
            LOG_ERROR("Entry group failure: %s\n",
                      avahi_strerror(avahi_server_errno(server)));

            /* Some kind of failure happened while we were registering our services */
            avahi_simple_poll_quit(simple_poll);
            cleanup();
            exit(-1);
            break;
        }
        default:
        {
            break;
        }
    }
}

/* change me */
static void
create_dpp_services(AvahiServer *server)
{
    int ret;

    /* If this is the first time we're called, let's create a new entry group */
    if (!group)
    {
        group = avahi_s_entry_group_new(server, dpp_entry_group_callback, NULL);
        if (!group)
        {
            LOG_ERROR("avahi_entry_group_new() failed: %s\n",
                      avahi_strerror(avahi_server_errno(server)));
            goto fail;
        }
    }

    ret = avahi_server_add_service(server, group, AVAHI_IF_UNSPEC,
                                   AVAHI_PROTO_UNSPEC, 0, name,
                                   "_dpp._tcp", NULL, NULL,
                                   portno, NULL);

    if (ret < 0)
    {
        LOG_ERROR("Failed to add _dpp._tcp service: %s\n", avahi_strerror(ret));
        goto fail;
    }

    /* Add an additional _bootstrapping._sub._dpp._tcp subtype */
    ret = avahi_server_add_service_subtype(server, group, AVAHI_IF_UNSPEC,
                                           AVAHI_PROTO_UNSPEC, 0, name,
                                           "_dpp._tcp", NULL,
                                           "_bootstrapping._sub._dpp._tcp");
    if (ret < 0)
    {
        LOG_ERROR("Could not add _bootstrapping._sub._dpp._tcp subtype: %s\n",
                  avahi_strerror(ret));
        goto fail;
    }

    /* Tell the server to register the service */
    ret = avahi_s_entry_group_commit(group);
    if (ret < 0)
    {
        LOG_ERROR("Failed to commit entry_group: %s\n", avahi_strerror(ret));
        goto fail;
    }

    return;

fail:
    avahi_simple_poll_quit(simple_poll);
    cleanup();
    exit(-1);
}

static void
dpp_server_callback(AvahiServer *server,
                    AvahiServerState state,
                    void * userdata)
{
    (void)userdata;
    assert(server != NULL);

    /* Called whenever the server state changes */
    switch (state) {

        case AVAHI_SERVER_RUNNING:
        {
            if (!group)
            {
                create_dpp_services(server);
            }

            break;
        }

        case AVAHI_SERVER_COLLISION:
        {
            char *altname;
            int ret;

            /* A host name collision happened. Let's pick a new name for the
             * server */
            altname = avahi_alternative_host_name(avahi_server_get_host_name(server));
            LOG_WARN("Host name collision, retrying with '%s'\n", altname);
            ret = avahi_server_set_host_name(server, altname);
            avahi_free(altname);

            if (ret < 0)
            {
                LOG_ERROR("Failed to set new host name: %s\n",
                          avahi_strerror(ret));
                avahi_simple_poll_quit(simple_poll);
                cleanup();
                exit(-1);
            }
        }
        /* fallthrough */
        case AVAHI_SERVER_REGISTERING:
        {
            if (group)
            {
                avahi_s_entry_group_reset(group);
            }

            break;
        }
        case AVAHI_SERVER_FAILURE:
        {
            /* Terminate on failure */
            LOG_ERROR("mDNS Server failure: %s\n",
                      avahi_strerror(avahi_server_errno(server)));
            avahi_simple_poll_quit(simple_poll);
            cleanup();
            exit(-1);
            break;
        }
        default:
        {
            break;
        }
    }
}

static void *
dpp_polling_mdns_thread_fn(void *arg)
{
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    return 0;
}

static void
log_function_local(AvahiLogLevel level, const char *msg)
{
    switch (level)
    {
    case AVAHI_LOG_ERROR:
        LOG_ERROR("%s\n", msg);
        break;
    case AVAHI_LOG_WARN:
        LOG_WARN("%s\n", msg);
        break;
    case AVAHI_LOG_NOTICE:
        /* fallthrough */
    case AVAHI_LOG_INFO:
        LOG_INFO("%s\n", msg);
        break;
    case AVAHI_LOG_DEBUG:
        LOG_DEBUG("%s\n", msg);
        break;
    default:
        LOG_ERROR("%s\n", msg);
    }
}

bool
dpp_mdns_start(const char* _service_name, uint16_t _portno)
{
    AvahiServerConfig config;
    AvahiServer *server = NULL;
    int error;

    service_name = strdup(_service_name);
    portno = _portno;

    simple_poll = avahi_simple_poll_new();
    if (!simple_poll)
    {
        LOG_ERROR("Failed to create simple poll object for mDNS\n");
        goto fail;
    }

    name = avahi_strdup(service_name);

    /* Use local print function */
    avahi_set_log_function(log_function_local);

    /* Let's set the host name for this server. */
    avahi_server_config_init(&config);
    config.publish_workstation = 0;

    server = avahi_server_new(avahi_simple_poll_get(simple_poll),
                              &config,
                              dpp_server_callback,
                              NULL,
                              &error);

    avahi_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    if (!server)
    {
        LOG_ERROR("Failed to create server: %s\n", avahi_strerror(error));
        goto fail;
    }

    if (pthread_create(&polling_mdns_thread,
                       NULL,
                       dpp_polling_mdns_thread_fn,
                       NULL))
    {
        LOG_ERROR("Could not start mDNS thread");
        goto fail;
    }
    return true;

fail:
    /* Cleanup allocated services */
    if (server)
    {
        avahi_server_free(server);
    }

    cleanup();
    return false;
}

bool
dpp_mdns_stop(void)
{
    bool ret = true;

    if (!simple_poll)
    {
        return ret;
    }

    avahi_simple_poll_quit(simple_poll);

    if (pthread_join(polling_mdns_thread, NULL) != 0)
    {
        LOG_ERROR("Failure when waiting for mDNS thread to end\n");
        ret = false;
    }

    cleanup();

    return ret;
}
