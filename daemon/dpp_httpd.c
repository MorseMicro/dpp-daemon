/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
/**
 * The DPP HTTP server which handles the bskey POST requests and
 * authentication.
 */
#include "dpp_httpd.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <microhttpd.h>

#include "utils.h"
#include "logging.h"

/* Options for the jsmn JSON parsing library:
 * Track the parent of each token parsed
 * Enable stricter parse, though it is still pretty loose.
 * Avoid any potential conflicts by marking all functions as static.
 */
#define JSMN_PARENT_LINKS
#define JSMN_STRICT
#define JSMN_STATIC
#include "jsmn.h"

/** A helper to get the length of a jsmn token */
#define JSMN_TOK_LEN(token) ((token).end - (token).start)

/** The maximum number of JSON tokens to parse. We only 5, 32 gives allows
 * for some extra keys to be added in the future that we will ignore. */
#define JSON_MAX_NUM_TOK (32)


/* Style change by MHD, ints -> enum */
#ifdef MHD_YES
typedef int MHD_Result_t;
#else
typedef enum MHD_Result MHD_Result_t;
#endif


/** Digest Auth data the client will echo back to us unmodified. We don't use
 * it, however mHTTPD requires it, so we set an empty string. */
#define OPAQUE ""

/**
 * A HTTP server could have multiple different authentication realms for
 * different parts of a website. We only have one realm, the values isn't
 * particularly important.
 */
#define REALM "DPPAuthorization"


/**
 * A internal code to track a bad/missing Content-Type value.
 * It is converted to a 400 BAD_REQUEST response, with a specialised message.
 */
#define HTTP_STATUS_BAD_CONTENT_TYPE 2000

/**
 * Some versions of libmicrohttpd changed the name of this
 */
#ifndef MHD_HTTP_CONTENT_TOO_LARGE
#define MHD_HTTP_CONTENT_TOO_LARGE MHD_HTTP_PAYLOAD_TOO_LARGE
#endif

/* A default callback, used if a callback is not provided, that logs messages
 */
static unsigned int
dpp_httpd_default_cb(const char *dpp_uri, const char *dpp_uri_role)
{
    LOG_INFO("DPP request received URI=%s ROLE=%s\n", dpp_uri, dpp_uri_role);
    return 200;
}


/* A Digest Authentication Credential */
typedef struct credential_t
{
    const char *name;
    const char *password;
} credential_t;


/** Struct that holds this modules data */
typedef struct httpd_data_t
{
    /** The running microHTTP daemon, NULL if not running */
    struct MHD_Daemon *mhd_daemon;

    /** The user callback for handling a DPP POST */
    dpp_httpd_bskey_cb_t bskey_cb;

    /**
     * A malloc'd pointer the secrets file in memory.
     *
     * Note: this file has been tokenised, access secrets via auth_secrets
     */
    char *auth_secrets_memory;

    /**
     * A malloc'd block containing a list of authorised users and passwords
     *
     * If the mhd daemon is running and this is NULL, then client
     * authentication is disabled and auth_secrets_size is set to 0.
     *
     * Note: Credentials point into the auth_secrets_memory memory blob
     */
    credential_t *auth_secrets;

    /** The number of entries in auth_secrets */
    size_t auth_secrets_size;

    /** The TLS server certificate in PEM format */
    char *server_cert_mem;

    /** The TLS server key in PEM format */
    char *server_key_mem;

} httpd_data_t;


/** Persistent local module data */
static httpd_data_t httpd_data;  /* NULL initialised by default */


/**
 * Free certs from httpd_data, is safe to call more than once.
 *
 * Should only be called when mHTTPD is not running
 */
static void
dpp_httpd_free_cert(void)
{
    if (httpd_data.mhd_daemon != NULL)
    {
        LOG_WARN("Credentials free'd while mHTTPD is running\n");
    }
    free(httpd_data.server_cert_mem);
    free(httpd_data.server_key_mem);
    httpd_data.server_key_mem = NULL;
    httpd_data.server_cert_mem = NULL;
}


/**
 * Loads the server certificate and key from a file into httpd_data
 *
 * @param server_cert file path or NULL ("") to disable, PEM encoding
 * @param server_key file path or NULL ("") to disable, PEM encoding
 * @param flags A pointer to the mHTTPD daemon flags
 * @return true if successful, including when server_cert and server_key are
 *         NULL
 * @return false If an error occurred loading the files.
 */
static bool
dpp_httpd_load_cert(const char *server_cert, const char *server_key,
                    int *flags)
{
    if ((server_cert != NULL && strlen(server_cert) != 0) ||
        (server_key != NULL && strlen(server_key) != 0))
    {
        /* Check the user has supplied both */
        if (server_cert == NULL || strlen(server_cert) == 0)
        {
            LOG_ERROR("No TLS certificate was provided\n");
            return false;
        }
        if (server_key == NULL || strlen(server_key) == 0)
        {
            LOG_ERROR("No TLS key file was provided\n");
            return false;
        }

        /* Try and load the cert and key file */
        if (!load_file_as_string(server_cert, 4096, &httpd_data.server_cert_mem,
                                 NULL))
        {
            LOG_ERROR("Failed to load the server's TLS certificate %s\n",
                      server_cert);
            return false;
        }
        if (!load_file_as_string(server_key, 4096, &httpd_data.server_key_mem,
                                 NULL))
        {
            LOG_ERROR("Failed to load the server's TLS key file %s\n",
                      server_key);
            free(httpd_data.server_cert_mem);
            httpd_data.server_cert_mem = NULL;
            return false;
        }
        *flags |= MHD_USE_TLS;
    }
    return true;
}


/**
 * Free credentials from httpd_data, is safe to call more than once.
 *
 * Should only be called when mHTTPD is not running
 */
static void
dpp_httpd_free_credentials(void)
{
    if (httpd_data.mhd_daemon != NULL)
    {
        LOG_WARN("Credentials free'd while mHTTPD is running\n");
    }
    free(httpd_data.auth_secrets);
    free(httpd_data.auth_secrets_memory);
    httpd_data.auth_secrets_memory = NULL;
    httpd_data.auth_secrets = NULL;
    httpd_data.auth_secrets_size = 0;
}


/**
 * Loads credentials from a file
 *
 * If file_path is NULL or an empty string, authentication is disabled.
 *
 * @param file_path the credentials file - see dpp_httpd_start for the format
 * @return true At least one credential was loaded or authentication is
 *              disabled
 * @return false An error occurred while attempting to load credentials
 */
static bool
dpp_httpd_load_credentials(const char *file_path)
{
    size_t size;
    char *line_tok_state;
    char *line_tok_start;
    char *line;

    if (!load_file_as_string(file_path, 0, &httpd_data.auth_secrets_memory,
                             &size))
    {
        LOG_ERROR("Failed to load auth file %s\n", file_path);
        return false;
    }

    line_tok_start = httpd_data.auth_secrets_memory;

    /* Parse a line */
    while ((line = strtok_r(line_tok_start, "\n", &line_tok_state)) != NULL)
    {
        char *user_pass_tok_state;
        char *user = NULL;
        char *password = NULL;
        credential_t *new_auth_secrets = NULL;

        /* Pass NULL to subsequent calls of strtok_r */
        line_tok_start = NULL;

        if (line[0] == '#')
        {
            /* Skip comments */
            continue;
        }

        /* Split out the user and password */
        user = strtok_r(line, "\t ", &user_pass_tok_state);
        password = strtok_r(NULL, "", &user_pass_tok_state);

        if (user == NULL || password == NULL || strlen(user) == 0 ||
            strlen(password) == 0)
        {
            if (user != NULL && strlen(user) != 0 )
            {
                LOG_WARN("Skipping invalid credential line: %s\n", line);
            }
            continue;
        }

        /* Trim whitespace from around the password */
        while (password[0] == '\t' || password[0] == ' ')
        {
            password++;
        }
        for (int i = strlen(password) - 1; i >= 0; i--)
        {
            if (password[i] == '\t' || password[i] == ' ')
                password[i] = '\0';
            else
                break;
        }

        /* Check the password isn't empty */
        if (strlen(password) == 0)
        {
            LOG_WARN("Skipping invalid auth line: %s\n", line);
            continue;
        }

        httpd_data.auth_secrets_size++;
        new_auth_secrets = realloc(
            httpd_data.auth_secrets,
            sizeof(credential_t)*httpd_data.auth_secrets_size);

        if (new_auth_secrets == NULL)
        {
            dpp_httpd_free_credentials();
            LOG_ERROR("Out of memory\n");
            return false;
        }
        httpd_data.auth_secrets = new_auth_secrets;

        httpd_data.auth_secrets[httpd_data.auth_secrets_size-1].name = user;
        httpd_data.auth_secrets[httpd_data.auth_secrets_size-1].password =
            password;
    }

    if (httpd_data.auth_secrets_size == 0)
    {
        LOG_ERROR("No valid credentials found in %s\n", file_path);
        dpp_httpd_free_credentials();
        return false;
    }
    return true;
}


/**
 * Data kept per request.
 */
struct request_t
{

    /**
     * Post processor handling form data (IF this is
     * a POST request).
     */
    const char *encoding;

    /**
     * Set true once after digest authentication has been successful
     */
    bool authenticated;

    /**
     * Set to a HTTP status response code denoting if the POST was successful
     * or otherwise the error that occurred.
     *
     * Set to 0 until the POST is processed yet
     */
    unsigned int post_status_code;

};


/**
 * Sends an HTTP response along with a status message
 *
 * @param connection the connection to send the response to
 * @param code the HTTP status code to return either a MHD_HTTP* or
 *             HTTP_STATUS* code.
 */
static MHD_Result_t
dpp_httpd_send_response(struct MHD_Connection *connection, unsigned int code)
{
    struct MHD_Response *response;
    MHD_Result_t ret;
    const char *message = NULL;

    /* Get the error message for the response */
    switch (code)
    {
        case MHD_HTTP_OK:
            /* As per the DPP spec, there is no body/message to return OK */
            message = "";
            break;

        case MHD_HTTP_NOT_FOUND:
            message = "Page not found";
            break;

        case MHD_HTTP_UNAUTHORIZED:
            message = "Your username or password was incorrect";
            break;

        case MHD_HTTP_METHOD_NOT_ALLOWED:
            message = "A HTTP POST is expected";
            break;

        case MHD_HTTP_BAD_REQUEST:
            message = "Invalid POST data";
            break;

        case MHD_HTTP_TOO_MANY_REQUESTS:
            message = "The server is busy, try again later";
            break;

        case MHD_HTTP_CONTENT_TOO_LARGE:
            message = "POST content too large";
            break;

        case HTTP_STATUS_BAD_CONTENT_TYPE:
            code = MHD_HTTP_BAD_REQUEST;
            message = "Request requires the Content-Type: application/json";
            break;

        case 0:
            /* We have a code path that hasn't set the http status code */
            code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            message = "Invalid request or data";
            break;

        default:
            LOG_WARN("No message for HTTP error code %u, consider adding one\n",
                     code);
            message = "Invalid request or data";
            break;
    }
    LOG_INFO("Returning %i: %s\n", code, message);

    response = MHD_create_response_from_buffer(strlen(message),
                                               (void *)message,
                                               MHD_RESPMEM_PERSISTENT);
    if (message[0] != '\0')
    {
        ret = MHD_add_response_header(response,
                                MHD_HTTP_HEADER_CONTENT_ENCODING,
                                "text/plain");
        if (ret == MHD_NO)
        {
            LOG_ERROR("Failed Content-Encoding");
            MHD_destroy_response(response);
            return ret;
        }
    }
    ret = MHD_queue_response(connection,
                             code,
                             response);
    MHD_destroy_response(response);
    return ret;
}


/**
 * To be called from the MHD request handler on any connection without
 * request->authenticated set, requests and validates a HTTP digest auth.
 *
 * The value returned from this function.
 *
 * @param connection the connection
 * @param request the request data for this connection
 * @return MHD_Result_t the result to return from the main MHD request handler.
 */
static MHD_Result_t
dpp_httpd_do_authentication(struct MHD_Connection *connection,
                            struct request_t *request)
{
    struct MHD_Response *response;
    MHD_Result_t ret;
    char *username;

    /* Explicitly configured to skip auth */
    if (httpd_data.auth_secrets_size == 0)
    {
        request->authenticated = true;
        return MHD_YES;
    }

    /* A new connection won't include the auth digest yet. We need to request
     * it */
    username = MHD_digest_auth_get_username(connection);
    if (username == NULL)
    {
        const char *auth_msg = "Authentication needed";
        response = MHD_create_response_from_buffer(strlen(auth_msg),
                                                   (void *)auth_msg,
                                                   MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_auth_fail_response(connection, REALM,
                                           OPAQUE,
                                           response,
                                           MHD_NO);
        MHD_destroy_response(response);
        return ret;
    }

    /* Verify the auth digest */
    for (size_t i = 0; i < httpd_data.auth_secrets_size; i++)
    {
        if (strcmp(username, httpd_data.auth_secrets[i].name) == 0)
        {
            ret = MHD_digest_auth_check(connection, REALM,
                                        username,
                                        httpd_data.auth_secrets[i].password,
                                        300);
            if (ret == MHD_YES)
            {
                request->authenticated = true;
                break;
            }
        }
    }

    /* Either continue with the connection or send a 401 UNAUTHORIZED */
    if (request->authenticated)
    {
        LOG_INFO("Successfully authenticated %s\n", username);
        free(username);
        return MHD_YES;
    }

    LOG_WARN("Failed to authenticate %s\n", username);
    free(username);
    return dpp_httpd_send_response(connection, MHD_HTTP_UNAUTHORIZED);
}


/**
 * Main MHD callback for handling requests.
 *
 * For a normal request this gets called multiple times:
 *
 * 1) With only the request headers
 *  - The callback requests Digest authentication
 * 2) With only headers, this time authenticated
 *  - The callback requests validates the auth and either returns unauthorized
 *    or continues.
 * 3) With the post data
 *  - We trigger the user callback
 *  - We are not allowed to send a response in this state
 *  - If the request is very large this callback will be called repeatedly with
 *    incremental data. DPP keys are not large enough to trigger this, so
 *    handle this as an error
 * 4) Finally without any upload data
 *  - This is the end of the POST and we can response with an HTTP STATUS
 *
 * ptr holds information between calls to the callback in a request_t.
 *
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param connection handle identifying the incoming connection
 * @param url the requested url
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param ptr pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global "MHD_RequestCompleted" callback (which
 *        can be set with the MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, <tt>*con_cls</tt> will be NULL.
 * @return MHS_YES if the connection was handled successfully,
 *         MHS_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static MHD_Result_t
request_handler(void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **ptr)
{
    struct request_t *request;
    UNUSED(cls);
    UNUSED(version);

    if (upload_data == NULL)
    {
        LOG_DEBUG("HTTP %s %s\n", method, url);
    }
    else
    {
        LOG_DEBUG("HTTP %s %s data=%s\n", method, url, upload_data);
    }

    /* We only have one endpoint, return a 404 for any other URL */
    if (strcmp(url, "/dpp/bskey") != 0)
    {
        LOG_INFO("Client requested access an invalid URL %s\n", url);
        return dpp_httpd_send_response(connection, MHD_HTTP_NOT_FOUND);
    }

    /* We only support POST; anything else is a 405 wrong method */
    if (strcmp(method, MHD_HTTP_METHOD_POST) != 0)
    {
        LOG_INFO("Client requested an invalid HTTP method %s\n", method);
        return dpp_httpd_send_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED);
    }

    /* Create or get the existing data that we have for this connection */
    request = *ptr;
    if (request == NULL)
    {
        request = calloc(1, sizeof(struct request_t));
        if (request == NULL)
        {
            LOG_ERROR("No memory to allocate request data\n");
            return MHD_NO;
        }
        *ptr = request;
    }

    /* Check this connection is correctly authenticated */
    if (!request->authenticated)
    {
        return dpp_httpd_do_authentication(connection, request);
    }

    /* Check that the Content-Type encoding is correct */
    if (request->encoding == NULL)
    {
        const char content_type[] = "Content-Type";
        if (MHD_NO == MHD_lookup_connection_value_n(connection,
                                                    MHD_HEADER_KIND,
                                                    content_type,
                                                    sizeof(content_type) - 1,
                                                    &request->encoding,
                                                    NULL))
        {
            /* Not Content-Type, 400 BAD REQUEST */
            LOG_WARN("Client did not include Content-Type\n");
            return dpp_httpd_send_response(connection,
                                           HTTP_STATUS_BAD_CONTENT_TYPE);
        }
    }

    /* Android likes to add '; charset=UTF-8' to the application/json
     * so we search for application/json as a substring */
    if (request->encoding == NULL ||
        strstr(request->encoding, "application/json") == NULL)
    {
        /* Incorrect Content-Type, 400 BAD REQUEST */
        LOG_WARN("Client included an invalid Content-Type %s\n",
                 request->encoding);
        return dpp_httpd_send_response(connection,
                                       HTTP_STATUS_BAD_CONTENT_TYPE);
    }

    /* Parse the DPP POST message */
    if (*upload_data_size != 0)
    {
        int r;
        jsmn_parser p;
        jsmntok_t t[JSON_MAX_NUM_TOK];
        char *dpp_uri = NULL;
        char *dpp_role = NULL;

        if (request->post_status_code != 0)
        {
            LOG_WARN("Received more POST data than expected\n");
            /* Skip the extra data a content too large, it is unlikely our
             * previous attempt to parse was successful */
            request->post_status_code = MHD_HTTP_CONTENT_TOO_LARGE;
            return MHD_YES;
        }

        LOG_DEBUG("Processing upload_data=%.*s\n",
                  (int)*upload_data_size, upload_data);

        jsmn_init(&p);
        r = jsmn_parse(&p, upload_data, *upload_data_size, t, JSON_MAX_NUM_TOK);
        if (r <= 0)
        {
            LOG_WARN("Error parsing JSON data\n");
            *upload_data_size = 0;
            request->post_status_code = MHD_HTTP_BAD_REQUEST;
            return MHD_YES;
        }

        /* We expect a single parent object with the two keys dppUri and
         * dppRole */
        if (t[0].type != JSMN_OBJECT)
        {
            LOG_WARN("Invalid JSON data\n");
            *upload_data_size = 0;
            request->post_status_code = MHD_HTTP_BAD_REQUEST;
            return MHD_YES;
        }

        /* The array is laid out key-value after the initial object, we
         * iterate over values and verify the key (its parent) */
        for (int i = 2; i < r; i+=2)
        {
            jsmntok_t *parent;
            if (t[i].type != JSMN_STRING)
                continue;

            parent = &t[t[i].parent];
            if (parent->type != JSMN_STRING)
                continue;

            if (strncmp("dppUri", upload_data + parent->start,
                        JSMN_TOK_LEN(*parent)) == 0)
            {
                if (dpp_uri != NULL)
                    continue;

                /* Copy to a new buffer and add a NULL terminator */
                dpp_uri = calloc(1, 1 + JSMN_TOK_LEN(t[i]));
                if (dpp_uri != NULL)
                {
                    memcpy(dpp_uri, upload_data + t[i].start,
                           JSMN_TOK_LEN(t[i]));
                    LOG_INFO("Got dppUri=%s\n", dpp_uri);
                }
                else
                {
                    LOG_WARN("No memory to store the dppUri\n");
                }
                continue;
            }

            if (strncmp("dppRole", upload_data + parent->start,
                        JSMN_TOK_LEN(*parent)) == 0)
            {
                if (dpp_role != NULL)
                    continue;

                /* Copy to a new buffer and add a NULL terminator */
                dpp_role = calloc(1, 1 + t[i].end - t[i].start);
                if (dpp_role != NULL)
                {
                    memcpy(dpp_role, upload_data + t[i].start,
                           JSMN_TOK_LEN(t[i]));
                    LOG_INFO("Got dppRole=%s\n", dpp_role);
                }
                else
                {
                    LOG_WARN("No memory to store the dppRole\n");
                }
                continue;
            }
        }

        if (dpp_role != NULL && dpp_uri != NULL)
        {
            request->post_status_code = httpd_data.bskey_cb(dpp_uri, dpp_role);
        }
        else
        {
            /* We don't have both a error */
            request->post_status_code = MHD_HTTP_BAD_REQUEST;
        }

        /* Free any strings we may have malloc'd */
        free(dpp_role);
        free(dpp_uri);
        dpp_role = dpp_uri = NULL;

        /* We've processed all of the post data */
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* All data has been received, send our response */
    return dpp_httpd_send_response(connection, request->post_status_code);
}


/**
 * Callback called upon completion of a request.
 *
 * @param cls not used
 * @param connection connection that completed
 * @param con_cls session handle
 * @param toe status code
 */
static void
request_completed_callback(void *cls,
                           struct MHD_Connection *connection,
                           void **con_cls,
                           enum MHD_RequestTerminationCode toe)
{
    struct Request *request = *con_cls;
    UNUSED(cls);
    UNUSED(connection);
    UNUSED(toe);

    if (NULL == request)
        return;

    free(request);
    LOG_VERBOSE("Freeing a request\n");
}


/* Public API */

bool
dpp_httpd_start(uint16_t port, dpp_httpd_bskey_cb_t bskey_cb,
                const char *server_cert, const char *server_key,
                const char *secrets)
{
    int mhd_flags = MHD_USE_ERROR_LOG | MHD_USE_INTERNAL_POLLING_THREAD;
    /* Random data that mHTTPD uses as a seed for digest auth, it's value
     * should not be changed while the server is running. This must remain
     * accessible, hence the static storage. */
    static uint8_t rnd[8];
    /* /dev/urandom file handle */
    FILE *f_urand;

    if (httpd_data.mhd_daemon != NULL)
    {
        LOG_ERROR("HTTP server already running, cannot start it again\n");
        return false;
    }

    if (bskey_cb != NULL)
    {
        httpd_data.bskey_cb = bskey_cb;
    }
    else
    {
        httpd_data.bskey_cb = dpp_httpd_default_cb;
    }

    if (secrets == NULL || strlen(secrets) == 0)
    {
        LOG_WARN("Credential checks are disabled, the server should only be"
                 " used for debugging\n");
    }
    else
    {
        if (!dpp_httpd_load_credentials(secrets))
        {
            return false;
        }
    }

    if (!dpp_httpd_load_cert(server_cert, server_key, &mhd_flags))
    {
        dpp_httpd_free_credentials();
        return false;
    }

    if (httpd_data.server_cert_mem == NULL)
    {
        LOG_WARN("TLS is disabled, the server should only be used for"
                 " debugging\n");
    }

    /* initialize PRNG */
    srand((unsigned int)time(NULL));

    /* Fill rnd with PRNG data as a fall back. We try overwrite with
     * /dev/urandom next. */
    for (int i = 0; i < sizeof(rnd); i++)
    {
        rnd[i] = (uint8_t)rand();
    }

    /* Use /dev/urandom as our preferred random source */
    f_urand = fopen("/dev/urandom", "r");
    if (f_urand == NULL)
    {
        LOG_WARN("Error opening /dev/urandom, reverting to rand()\n");
    }
    else
    {
        size_t num_read = fread(rnd, 1, sizeof(rnd), f_urand);
        if (num_read != sizeof(rnd))
        {
            LOG_WARN("Error reading /dev/urandom, read %llu bytes"
                     "reverting to rand()\n", (unsigned long long)num_read);
        }
        fclose(f_urand);
    }

    httpd_data.mhd_daemon = MHD_start_daemon(
        mhd_flags,
        port,
        NULL, NULL,
        &request_handler, NULL,
        MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)5,
        /* The default nonce storage size is a bit too low and fill ups */
        MHD_OPTION_NONCE_NC_SIZE, 10,
        MHD_OPTION_NOTIFY_COMPLETED,
        &request_completed_callback, NULL,
        /* Chop off the HTTPS Cert and Key if we are not doing TLS so the
         * mHTTPD library doesn't generate extra warnings */
        (httpd_data.server_cert_mem == NULL) ?
            MHD_OPTION_END : MHD_OPTION_HTTPS_MEM_CERT,
                httpd_data.server_cert_mem,
        MHD_OPTION_HTTPS_MEM_KEY, httpd_data.server_key_mem,
        MHD_OPTION_END);

    if (httpd_data.mhd_daemon == NULL)
    {
        dpp_httpd_free_credentials();
        dpp_httpd_free_cert();
        LOG_ERROR("MHD_start_daemon failed to start\n");
        return false;
    }
    return true;
}


void
dpp_httpd_stop(void)
{
    MHD_stop_daemon(httpd_data.mhd_daemon);
    httpd_data.mhd_daemon = NULL;
    dpp_httpd_free_credentials();
    dpp_httpd_free_cert();
    httpd_data.bskey_cb = NULL;
}
