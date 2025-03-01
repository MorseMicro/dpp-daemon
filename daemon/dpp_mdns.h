/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#include "logging.h"
#include "utils.h"

/**
 * The public interface to the DPP mDNS registrer which advertise DPP POST
 * request service
 *
 * Clients will look for the standard address which this daemon will advertise
 */

/**
 * This will begin running in its own thread.
 *
 * @param service_name The advertised service unicode name
 * @param port The TCP port number used by the http server which the mDNS
 *        is advertising
 *
 * @return true if successful, otherwise false if an error occurs. Details of
 * any error will be logged.
 */
extern bool
dpp_mdns_start(const char* _service_name, uint16_t _portno);


/**
 * Stops the server DPP HTTP server running and releases any resources.
 */
extern bool
dpp_mdns_stop(void);