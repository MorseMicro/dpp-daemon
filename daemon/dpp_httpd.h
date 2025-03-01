/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef DPP_HTTPD_H__
#define DPP_HTTPD_H__

/**
 * The public interface to the DPP HTTP server which handles the bskey POST
 * requests and authentication.
 *
 * Clients must authenticate themselves by presenting a valid HTTP
 * authentication digest.
 *
 * This server can be authenticated by the client through its HTTPS
 * certificate.
 */

#include <stdbool.h>
#include <stdint.h>


/**
 * Callback to handle a JSON POST to /dpp/bskey
 *
 * Thread context: This will be called from the dpp_httpd thread context.
 * The library is configured such that there is a single thread serving all
 * requests. As such this callback is always called by the same thread and
 * it should not block.
 *
 * @param dpp_uri The contents of dppURI from the JSON POST
 * @param dpp_role The contents of dppRole from the JSON POST
 * @return An http error code one of:
 *  - 200 OK
 *  - 429 Too Many Requests (E.g. Server busy, try again later)
 *  - 400 Bad Request (E.g. Bad data dpp_uri or dpp_role)
 */
typedef unsigned int (*dpp_httpd_bskey_cb_t)(const char *dpp_uri,
                                             const char *dpp_role);


/**
 * Initialises and starts the DPP HTTP server.
 *
 * This will begin running in its own thread.
 *
 * @param port The TCP port number to run the web server on
 * @param bskey_cb The callback called when a authenticated POST
 * @param server_cert The file path to the server certificate, PEM encoded
 * @param server_key The file path to the server certificate, PEM encoded
 * @param secrets The file path to the allowed usernames and passwords.
 *                Each line can either be:
 *                  - blank
 *                  - A comment denoted by a line starting with #
 *                  - Or a username and password separated by whitespace
 *
 *                Note: the first group of consecutive whitespace characters
 *                is used as the separator. Additional whitespaces are
 *                considered part of the password, expect for trailing
 *                whitespace which is stripped.
 *
 * If bskey_cd is set to NULL, then the successful POSTs will be logged to
 * stdout.
 *
 * If both server_cert and server_key are set to NULL or are an empty string.
 * Then TLS is disabled.
 *
 * If secrets is set to NULL or an empty string. Then the authentication digest
 * is disabled.
 *
 * @return true if successful, otherwise false if an error occurs. Details of
 * any error will be logged.
 */
extern bool
dpp_httpd_start(uint16_t port, dpp_httpd_bskey_cb_t bskey_cb,
                const char *server_cert, const char *server_key,
                const char *secrets);


/**
 * Stops the server DPP HTTP server running and releases any resources.
 */
extern void
dpp_httpd_stop(void);

#endif  /* DPP_HTTPD_H__ */
