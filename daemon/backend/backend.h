/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef BACKEND_H__
#define BACKEND_H__
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>

#include "mmsm_data.h"


typedef struct mmsm_backend_intf_t mmsm_backend_intf_t;


/**
 * The backend monitor data callback.
 *
 * Used for receiving asynchronous notifications as well as responses to
 * asynchronous requests.
 *
 * @param intf The interface that the data was received on
 * @param received The received data
 */
typedef void (*mmsm_backend_monitor_callback_t)(
    mmsm_backend_intf_t *intf, mmsm_data_item_t *received);


/**
 * The backend interface
 *
 * Provides two main categories of interfaces:
 * - Requests
 * - Notifications
 *
 * If the interface supports notifications, then it will provide the
 * register_callback, start, and stop APIs.
 *
 * Additionally, if the interface supports asynchronous requests, it will
 * provide the above APIs, as well as the req_async API.
 *
 * If the interface supports blocking requests, it will provide the req_blocking
 * API.
 *
 * All APIs are passed the interface struct itself as the first member to allow
 * multiple instantiations of backends and to allow them to manage their own
 * data. All APIs must be called in the following way:
 *
 *     my_backend_intf->do_something(my_backend_intf, ...);
  */
typedef struct mmsm_backend_intf_t
{
    /**
     * Registers a callback for passing data back to the Smart Manager engine.
     *
     * Must be called before any other of the asynchronous related functions:
     * start, stop, req_async
     *
     * @param intf The interface object
     * @param callback The callback to register
     *
     * @returns an appropriate error code
     */
    mmsm_error_code (*register_callback)(
        mmsm_backend_intf_t *intf,
        mmsm_backend_monitor_callback_t callback);


    /**
     * Starts receiving notifications and passing them up on the registered
     * callback.
     *
     * The callback must be registered before calling this function.
     *
     * @param intf The interface object
     *
     * @returns an appropriate error code
     */
    mmsm_error_code (*start)(mmsm_backend_intf_t *intf);


    /**
     * Stops receiving notifications.
     *
     * @param intf The interface object
     *
     * @returns an appropriate error code
     */
    mmsm_error_code (*stop)(mmsm_backend_intf_t *intf);


    /**
     * Sends an asynchronous request on the backend.
     *
     * The callback must be registered, and the backend must be started before
     * calling this function.
     *
     * On success, the response to the request is provided on the registered
     * callback.
     *
     * @param intf The interface object
     * @param the parsed result that goes back to the engine for pattern
     *        matching
     *
     * @returns an appropriate error code
     */
    mmsm_error_code (*req_async)(mmsm_backend_intf_t *intf,
                                 mmsm_data_item_t **result);


    /**
     * Sends a blocking request on the backend.
     *
     * This API blocks until the request has been fulfilled, and the result is
     * provided immediately back to the caller.
     *
     * @param intf The interface object
     * @param command The command to send
     * @param result The result structure to fill
     *
     * @returns an appropriate error code
     */
    mmsm_error_code (*req_blocking)(mmsm_backend_intf_t *intf,
                                    mmsm_data_item_t *command,
                                    mmsm_data_item_t **result);


    /**
     * Reads the command information requested byt the user and formats it
     * into something that will be accepted by the backend.
     *
     * See the backend specific variants of this for details on the command
     * formatting.
     *
     * @param intf The backend interface to be invoked
     * @param args A va list of args that corresponds to the relevant backend.
     *             (See backend_hostapd_process_request_args)
     *
     * @returns a data item that continas the processed args
     */
    mmsm_data_item_t* (*process_request_args)(mmsm_backend_intf_t *intf,
                                              va_list args);

} mmsm_backend_intf_t;


/**
 * Creates a hostapd ctrl interface backend
 *
 * The hostapd ctrl interface provides a means of communicating directly with
 * hostapd using the control interface that's typically set in /var/run/hostapd.
 *
 * Commands sent to this interface are passed as-is to hostapd, so consult the
 * hostapd control interface documentation for details of what commands can be
 * sent.
 *
 * The interface should in theory also be able to be used to talk with
 * wpa_supplicant.
 *
 * @param control_sock The path to the control socket to attach to
 *
 * @returns the created backend interface instance
 */
mmsm_backend_intf_t *
mmsm_backend_hostapd_ctrl_create(const char *control_sock);


/**
 * Destroys a hostapd control interface backend.
 *
 * @param handle The handle to the backend to destroy.
 */
void
mmsm_backend_hostapd_ctrl_destroy(mmsm_backend_intf_t *handle);


/**
 * Creates an nl80211 interface backend
 *
 * The nl80211 interface provides a means of communicating directly with
 * cfg80211 using the nl80211 protocols, and therefore provides a mechanism for
 * a Smart Manager application to access configurations within cfg80211 and the
 * WLAN driver.
 *
 * @returns the created backend interface instance
 */
mmsm_backend_intf_t *
mmsm_backend_nl80211_create(void);


/**
 * Destroys an nl80211 control interface backend.
 *
 * @param handle The handle to the backend to destroy.
 */
void
mmsm_backend_nl80211_destroy(mmsm_backend_intf_t *handle);


#endif /* BACKEND_H__ */
