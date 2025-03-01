/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef SMART_MANAGER_H
#define SMART_MANAGER_H

/**
 * @file smart_manager.h
 */

#include "backend/backend.h"
#include "mmsm_data.h"
#include "helpers.h"


/**
 * The callback function when data is passed back to the user application.
 *
 * @param context The user context provided with the callback
 * @param intf The interface that generated the data in this callback
 * @param result The data
 */
typedef void (*mmsm_data_callback_fn_t)(
    void *context, mmsm_backend_intf_t *intf, mmsm_data_item_t *result);


/**
 * Starts the Morse Micro Smart Manager.
 *
 * Initialises and runs all of the threads and background tasks enabling the
 * monitor and asynchronous APIs.
 *
 * @returns an appropriate status code
 */
mmsm_error_code mmsm_start(void);


/**
 * Stops the Morse Micro Smart Manager.
 *
 * Shuts down all of the threads and background tasks. No more callbacks will be
 * called once this function completes.
 *
 * @returns an appropriate status code
 */
mmsm_error_code mmsm_stop(void);


/**
 * Sends a request on the given interface.
 *
 * @note This request function will block the current thread until the response
 *       has been received.
 *
 * @param intf The interface to send the request on
 *
 * @returns the received result, or @c NULL on failure
 */
mmsm_data_item_t *
mmsm_request(mmsm_backend_intf_t *intf, ...);


/**
 * Registers a polling monitor on the given interface.
 *
 * The polling monitor repeatedly performs a request at the given frequency and
 * provides the response to the application on the provided callback.
 *
 * The monitoring itself doesn't actually happen until after the Smart Monitor
 * has been started with @ref mmsm_start
 *
 * @param intf The interface to send the request on
 * @param frequency_ms The frequency to send the request, in milliseconds
 * @param callback The callback to provide the response on
 * @param context Context to provide back to the application wit the callback
 */
mmsm_error_code
mmsm_monitor_polling(mmsm_backend_intf_t *intf,
                     uint32_t frequency_ms,
                     mmsm_data_callback_fn_t callback,
                     void *context,
                     ...);


/**
 * Registers a pattern monitor on the given interface.
 *
 * The pattern monitor scans incoming notifications on the interface and reports
 * any matches up to the application on the provided callback.
 *
 * @param intf The interface to send the request on
 * @param pattern The pattern to search for
 * @param callback The callback to provide the response on
 * @param context Context to provide back to the application wit the callback
 */
mmsm_error_code
mmsm_monitor_pattern(mmsm_backend_intf_t *intf,
                     const char *pattern,
                     mmsm_data_callback_fn_t callback,
                     void *context,
                     ...);


#endif
