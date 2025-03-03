/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
/**
 * The main DDP daemon
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/stat.h>

#include "dpp_mdns.h"
#include "dpp_httpd.h"

#include "smart_manager.h"
#include "backend/backend.h"
#include "utils.h"
#include "logging.h"

#define DPP_ASSERT MMSM_ASSERT

#define DEFAULT_AP_CONF_MODE ("dpp")

#define CTRL_IF_CHECK_RESULTS(result, return_code, msg)  \
    do {                                                 \
        if (!(result))                                   \
        {                                                \
            LOG_ERROR(msg);                              \
            return (return_code);                        \
        }                                                \
    } while (0)

#define CTRL_IF_STATUS(alive, return_code, msg) \
    do {                                        \
        if (!(alive))                           \
        {                                       \
            LOG_ERROR(msg);                     \
            return (return_code);               \
        }                                       \
    } while (0)
/**
 *
 * @enum  DPP error codes
 *
 * @brief enum for the error codes returned by DPP
 **/
typedef enum dpp_error_code_t {
    DPP_ERROR_CODE_SUCCESS = 0,
    DPP_ERROR_CODE_DEBUG_MODE = DPP_ERROR_CODE_SUCCESS,
    DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR,
    DPP_ERROR_CODE_UNKNOWN_ERROR,
    DPP_ERROR_CODE_CTRL_IF_ERROR,
    DPP_ERROR_CODE_HOSTAPD_CFG_ERROR,
    DPP_ERROR_CODE_HOSTAPD_KEYS_ERROR,
    DPP_ERROR_CODE_HOSTAPD_DPP_ERROR,
    DPP_ERROR_CODE_OVERFLOW_ERROR,
    DPP_ERROR_CODE_MDNS_SERVICE_FAILURE,
    DPP_ERROR_CODE_HTTPD_SERVICE_FAILURE
} dpp_error_code_t;

/**
 *
 * @enum  DPP states
 *
 * @brief enum for the internal state of main DPP process
 **/
typedef enum dpp_states_t {
    DPP_STATE_INVALID = 0,
    DPP_STATE_UNINIT,
    DPP_STATE_DISCONNECTED,
    DPP_STATE_WAIT_APPLY_KEYS,
    DPP_STATE_WAIT_QR_CODE,
    DPP_STATE_RECEIVED_QR_CODE,
} dpp_states_t;


/** The pthread_t instance for polling Hostapd state requests */
pthread_t polling_hostapd_thread;

/** The mutex for communication with http server */
pthread_mutex_t dpp_mutex = PTHREAD_MUTEX_INITIALIZER;

/** The condition to notify changes to the main process from http server */
pthread_cond_t dpp_cond = PTHREAD_COND_INITIALIZER;

static int state = DPP_STATE_UNINIT;
static bool debug_mode = false;
static char *qrcode = NULL;
static char configurator_id = 1;
static char *dpp_conn_key, *dpp_csign, *dpp_netaccesskey;
static char *ctrl_if_path = NULL;


void
cleanups()
{
    free(dpp_conn_key);
    dpp_conn_key = NULL;
    free(dpp_csign);
    dpp_csign = NULL;
    free(dpp_netaccesskey);
    dpp_netaccesskey = NULL;
}


static int
ctrl_if_path_available()
{
    struct stat buf;
    return (stat(ctrl_if_path, &buf) == 0);
}


static void *
polling_hostapd_thread_fn(void *arg)
{
    while (1)
    {
        if (!ctrl_if_path_available())
        {
            DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);
            if (state > DPP_STATE_UNINIT)
            {
                LOG_NP(LOG_ERROR, "Hostapd connection was lost, trying to re-connect...\n");
                cleanups();
                state = DPP_STATE_UNINIT;
            }
            DPP_ASSERT(pthread_cond_signal(&dpp_cond) == 0);
            DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
        }
        else
        {
            DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);
            if (state == DPP_STATE_UNINIT)
            {
                state = DPP_STATE_DISCONNECTED;
            }
            DPP_ASSERT(pthread_cond_signal(&dpp_cond) == 0);
            DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
        }

        usleep(100000);
    }
}


static void
print_usage()
{
    printf("Usage: dppd [OPTIONS]\n"
        "Runs DPP AP side flow with HTTPD and mDNS in the background\n"
        "Example: dppd --port 1234 --ap-conf-mode 'sae'\n"
        "\nOptions:\n"
        "-h, --help               displays this message and exit\n"
        "-k, --qrcode=DPP_CODE    Debug mode with one shot using the\n"
        "\t\t\tsupplied code\n"
        "-p, --http-port=PORT     Sets the https server's port\n"
        "-i, --ctrl-if-path       Manually sets Hostapd control interface\n"
        "-s, --http-secrets=PATH  The path to a text file containing\n"
        "\t\t\tauthorised credentials used for\n"
        "\t\t\tclient auth. Set to an empty string\n"
        "\t\t\tto disable MD5 digest auth.\n"
        "-C, --tls-cert=PATH      The path to a PEM encoded TLS\n"
        "\t\t\tcertificate, defaults /etc/server.pem.\n"
        "\t\t\tSet the cert and key to an empty\n"
        "\t\t\tstring to disable TLS.\n"
        "-K, --tls-key=PATH       The path to a PEM encoded private key,\n"
        "\t\t\tdefaults to /etc/server.key. Set the\n"
        "\t\t\tcert and key to an empty string to\n"
        "\t\t\tdisable TLS.\n"
        "-m, --ap-conf-mode       Force the AP mode to either DPP/DPP-SAE\n"
        "-y, --configurator-key=PATH  The path to dpp_configurator_add\n"
        "\t\t\tcommand PEM file.\n"
        "-z, --configurator-private-key=PATH  The path to dpp_configurator_add\n"
        "\t\t\tcommand PEM file.\n"
        "-x, --passphrase=PASS    To be used in SAE DPP GAS and association\n"
        "-n, --service-name=NAME  The service name to advertise via DNS-SD.\n"
        "\t\t\t Defaults to 'DPP-Initiator'\n"
        );
}


static void
sm_livemon_dpp_connector_handler(void *context,
                                 mmsm_backend_intf_t *intf,
                                 mmsm_data_item_t *result)
{
    UNUSED(context);
    UNUSED(intf);
    uint8_t *field;

    DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);

    field = mmsm_find_value_by_key(result, "DPP-CONNECTOR");

    /* In case the AP mode is not DPP, connector will be missing, instead
     * we should look for the passphrase */
    if (!field)
        field = mmsm_find_value_by_key(result, "DPP-CONFOBJ-PASS");

    dpp_conn_key = strdup((char*)field);

    DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);

    LOG_DEBUG("DPP-CONNECTOR/PASS is %s\n", field);
    MMSM_DUMP_DATA_ITEM(result, LOG_LEVEL_INFO);
}


static void
sm_livemon_dpp_csign_handler(void *context,
                             mmsm_backend_intf_t *intf,
                             mmsm_data_item_t *result)
{
    UNUSED(context);
    UNUSED(intf);
    uint8_t *field;

    DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);

    field = mmsm_find_value_by_key(result, "DPP-C-SIGN-KEY");
    dpp_csign = strdup((char*)field);

    DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);

    LOG_DEBUG("DPP-C-SIGN-KEY is %s\n", field);
    MMSM_DUMP_DATA_ITEM(result, LOG_LEVEL_INFO);
}


static void
sm_livemon_dpp_netaccesskey_handler(void *context,
                                    mmsm_backend_intf_t *intf,
                                    mmsm_data_item_t *result)
{
    UNUSED(context);
    UNUSED(intf);
    uint8_t *field;

    DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);

    field = mmsm_find_value_by_key(result, "DPP-NET-ACCESS-KEY");
    dpp_netaccesskey = strdup((char*)field);

    if (dpp_conn_key && dpp_csign)
    {
        state = DPP_STATE_WAIT_APPLY_KEYS;
        DPP_ASSERT(pthread_cond_signal(&dpp_cond) == 0);
    }

    DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);

    LOG_DEBUG("DPP-NET-ACCESS-KEY is %s\n", field);
    MMSM_DUMP_DATA_ITEM(result, LOG_LEVEL_INFO);
}


/**
 * Called when the web server receives an authenticated dpp/bskey POST
 *
 * @param dpp_uri The uri that was encoded in the POST
 * @param dpp_role The role that was encoded in the POST
 * @return A HTTP status response
 */
static unsigned
dppd_bskey_handler(const char *dpp_uri, const char *dpp_role)
{
    LOG_INFO("Received POST, DPP role=%s  DPP URI=%s\n", dpp_role, dpp_uri);
    DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);

    if (strcmp(dpp_role, "sta") == 0)
    {
        /* TODO process the request here and validate dpp_uri*/
        if (qrcode != NULL)
        {
            LOG_INFO("Could not allocate the new QR Code, busy...\n");
            DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
            return 429; /* too many requests */
        }

        /* First, validate the bootstrapping information:
         * Should start with 'DPP:' and end with ';;' */
        if (strncmp(dpp_uri, "DPP:", 4))
        {
            DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
            return 400; /* Bad request */
        }
        if (strncmp(dpp_uri + strlen(dpp_uri) - 2, ";;", 2))
        {
            DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
            return 400; /* Bad request */
        }

        /* OK, success */
        qrcode = strdup(dpp_uri);
        state = DPP_STATE_RECEIVED_QR_CODE;
        DPP_ASSERT(pthread_cond_signal(&dpp_cond) == 0);
        DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
        return 200;
    }

    DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);

    /* Bad request */
    return 400;
}

static char*
hostapd_verify_conf(mmsm_backend_intf_t *hostapd)
{
    mmsm_data_item_t *result = NULL;
    char *field = NULL;
    char *ap_key_mgmt = NULL;
    int i;

    LOG_DEBUG("GET_CONFIG:\n");
    result = mmsm_request(hostapd, "GET_CONFIG");
    CTRL_IF_CHECK_RESULTS(result, NULL, "Hostapd configuration is invalid\n");
    MMSM_DUMP_DATA_ITEM(result, LOG_LEVEL_DEBUG);
    field = (char *)mmsm_find_value_by_key(result, "key_mgmt");

    ap_key_mgmt = strdup(field);
    for (i = 0; i < strlen(ap_key_mgmt); i++)
        ap_key_mgmt[i] = tolower(ap_key_mgmt[i]);

    mmsm_data_item_free(result);
    return ap_key_mgmt;
}


static int
hostapd_init_sequence(mmsm_backend_intf_t *hostapd,
                      const char *key,
                      const char *ppkey,
                      const char *ap_conf_mode,
                      const char *passphrase)
{
    mmsm_data_item_t *result = NULL;
    uint8_t *field = NULL;
    char conf_command[520];
    char hex_ap_ssid[65] = {0};
    char ap_ssid[33];
    char hex_passphrase[126] = {0};
    int len = 0;
    int i;

    /* Adding connector with no feedback */
    snprintf(conf_command, sizeof(conf_command),
             "DPP_CONFIGURATOR_ADD key=%s ppkey=%s",
             key, ppkey);
    result = mmsm_request(hostapd, conf_command);
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_CTRL_IF_ERROR,
                          "Make sure Hostapd is up and path is correct\n");
    mmsm_data_item_free(result);

    /* Get current Hostapd configuration and extract SSID */
    LOG_DEBUG("\nSTATUS:\n");
    result = mmsm_request(hostapd, "STATUS");
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_HOSTAPD_CFG_ERROR,
                          "Hostapd configuration is invalid\n");

    MMSM_DUMP_DATA_ITEM(result, LOG_LEVEL_DEBUG);
    field = mmsm_find_value_by_key(result, "ssid[0]");
    if (sizeof(ap_ssid) < strlen((char*)field))
    {
        return DPP_ERROR_CODE_OVERFLOW_ERROR;
    }
    strcpy(ap_ssid, (char*)field);
    mmsm_data_item_free(result);

    LOG_DEBUG("\nDPP_CONFIGURATOR_SIGN:\n");
    if (sizeof(hex_ap_ssid) <= (strlen(ap_ssid) * 2))
    {
        LOG_ERROR("Exit due to possible overflow of hex buffer\n");
        return DPP_ERROR_CODE_OVERFLOW_ERROR;
    }
    for (i = 0; i < strlen(ap_ssid); i++)
    {
        sprintf(hex_ap_ssid + (2 * i), "%02x", ap_ssid[i]);
    }
    len = snprintf(conf_command, sizeof(conf_command),
        "DPP_CONFIGURATOR_SIGN conf=ap-%s configurator=%d ssid=%s conf=sta-%s",
        ap_conf_mode, configurator_id, hex_ap_ssid, ap_conf_mode);

    if (strstr(ap_conf_mode, "sae"))
    {
        int pass_len = strlen(passphrase);

        if (pass_len == 0)
        {
            LOG_ERROR("Please supply password for SAE mode:\n"
                      "\t-x, --passphrase=PASS\n");
            return DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR;
        }

        if (pass_len > 63 || pass_len < 8)
        {
            LOG_ERROR("Invalid SAE passphrase length: should be between 8 to "
                      "63 characters\n");
            return DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR;
        }
        for (i = 0; i < pass_len; i++)
        {
            sprintf(hex_passphrase + (2 * i), "%02x", passphrase[i]);
        }
        snprintf(conf_command + len, sizeof(conf_command) - len,
            " pass=%s", hex_passphrase);
    }
    result = mmsm_request(hostapd, conf_command);
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_HOSTAPD_DPP_ERROR,
                          "Bad Hostapd DPP_CONFIGURATOR_SIGN command\n");
    mmsm_data_item_free(result);

    /* Update Hostapd internal passphrase as we do not use (cannot read from
     * the interface) the one in the config file */
    if (strstr(ap_conf_mode, "sae"))
    {
        snprintf(conf_command, sizeof(conf_command),
                 "SET sae_password %s", passphrase);
        result = mmsm_request(hostapd, conf_command);
        CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_CTRL_IF_ERROR,
                              "Make sure Hostapd is up and path is correct\n");
        mmsm_data_item_free(result);
    }

    result = mmsm_request(hostapd,
                          "SET dpp_configurator_params configurator=1");
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_CTRL_IF_ERROR,
                          "Make sure Hostapd is up and path is correct\n");
    mmsm_data_item_free(result);

    return DPP_ERROR_CODE_SUCCESS;
}


static int
hostapd_apply_keys(mmsm_backend_intf_t *hostapd, const char *ap_conf_mode)
{
    mmsm_data_item_t *result = NULL;
    char conf_command[512];

    if (!strstr(ap_conf_mode, "sae"))
    {
        snprintf(conf_command, sizeof(conf_command),
                "SET dpp_connector %s", dpp_conn_key);
        /* Adding connector with no feedback */
        result = mmsm_request(hostapd, conf_command);
        CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_HOSTAPD_KEYS_ERROR,
                            "Could not apply connector key\n");
        mmsm_data_item_free(result);
    }

    snprintf(conf_command, sizeof(conf_command),
             "SET dpp_csign %s", dpp_csign);
    result = mmsm_request(hostapd, conf_command);
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_HOSTAPD_KEYS_ERROR,
                          "Could not apply csign key\n");
    mmsm_data_item_free(result);

    snprintf(conf_command, sizeof(conf_command),
             "SET dpp_netaccesskey %s", dpp_netaccesskey);
    LOG_INFO("dpp_netaccesskey = %s\n", dpp_netaccesskey);
    result = mmsm_request(hostapd, conf_command);
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_HOSTAPD_KEYS_ERROR,
                          "Could not apply net-access key\n");
    mmsm_data_item_free(result);

    return DPP_ERROR_CODE_SUCCESS;
}


static int
hostapd_apply_qr_code(mmsm_backend_intf_t *hostapd, char *qrcode)
{
    mmsm_data_item_t *result = NULL;
    char conf_command[512];

    CTRL_IF_STATUS(hostapd != NULL, DPP_ERROR_CODE_CTRL_IF_ERROR,
        "Hostapd interface is down, cannot apply QR Code\n");

    snprintf(conf_command, sizeof(conf_command), "DPP_QR_CODE %s", qrcode);
    result = mmsm_request(hostapd, conf_command);
    CTRL_IF_CHECK_RESULTS(result, DPP_ERROR_CODE_CTRL_IF_ERROR,
                          "Could not apply QR code\n");
    mmsm_data_item_free(result);

    return DPP_ERROR_CODE_SUCCESS;
}


static void
mmsm_init()
{
    LOG_INFO("Initialising...\n");
    mmsm_init_time();
}


static mmsm_backend_intf_t *
hostapd_reconnect(char *ctrl_if_path)
{
    /* Initialise and set all smart-manager conditions */
    mmsm_backend_intf_t *hostapd;
    mmsm_init();
    hostapd = mmsm_backend_hostapd_ctrl_create(ctrl_if_path);

    if (!hostapd)
    {
        LOG_ERROR("Could not load Hostapd control interface...\n");
        return NULL;
    }

    return hostapd;
}


static int
hostapd_set_polling(mmsm_backend_intf_t *hostapd,
                          char **ap_conf_mode,
                          bool mmsm_poll_started)
{
    CTRL_IF_STATUS(hostapd != NULL, DPP_ERROR_CODE_CTRL_IF_ERROR,
        "Hostapd interface is down, cannot start DPP flow\n");

    if (!(*ap_conf_mode))
    {
        *ap_conf_mode = hostapd_verify_conf(hostapd);
        if (!(*ap_conf_mode))
        {
            LOG_WARN("AP configuration mode is not set nor found, using "
                     "default 'dpp'\n");
            *ap_conf_mode = strdup(DEFAULT_AP_CONF_MODE);
        }
    }

    /* Add a few live monitors */
    if (strstr(*ap_conf_mode, "sae"))
    {
        mmsm_monitor_pattern(hostapd, "", sm_livemon_dpp_connector_handler,
                             NULL, "DPP-CONFOBJ-PASS");
    }
    else
    {
        mmsm_monitor_pattern(hostapd, "", sm_livemon_dpp_connector_handler,
                             NULL, "DPP-CONNECTOR");
    }

    mmsm_monitor_pattern(hostapd, "", sm_livemon_dpp_csign_handler, NULL,
                         "DPP-C-SIGN-KEY");
    mmsm_monitor_pattern(hostapd, "", sm_livemon_dpp_netaccesskey_handler, NULL,
                         "DPP-NET-ACCESS-KEY");

    /* Polling monitors aren't started until mmsm_start is called */
    DPP_ASSERT(mmsm_poll_started == false);
    LOG_INFO("Start polling\n");
    return mmsm_start();
}


/**
 * Call with the port number (-p ####) and Hostapd/wpa_supplicant control
 * interface (-i /path/to/interface) as arguments for release mode. If in
 * debug mode (-k "DPP:...;;") need to supply QR-Code.
 * Never terminates in release mode (other than by signals, such as CTRL-C).
 * One shot flow in debug mode.
 *
 * TODO:
 *  - Fixed configurator ID = 1, might need to adapt in the future
 */
int
main (int argc, char *const *argv)
{
    /* Argument parsing variables */
    int ret = DPP_ERROR_CODE_SUCCESS;
    int arg_c;
    const char *port_number = "8080";
    const char *tls_cert = "/etc/server.pem";
    const char *tls_key = "/etc/server.key";
    const char *http_secrets = "/etc/auth_secrets.txt";
    uint16_t httpd_port = 0;
    int prev_state = DPP_STATE_INVALID;
    const char *configurator_key = "/etc/key.pem";
    const char *configurator_private_key = "/etc/ppkey.pem";
    const char *sae_passphrase = "";
    const char *service_name = "DPP-Initiator";
    char *key = NULL;
    char *ppkey = NULL;
    char *ap_conf_mode = NULL;

    /* declare and init smart manager variables */
    mmsm_backend_intf_t *hostapd = NULL;
    bool mmsm_poll_started = false;
    bool mdnsd_started = false;
    bool httpd_started = false;

    LOG_INFO("Parsing args...\n");
    while (1)
    {
        static struct option dpp_options[] =
        {
            {"help",                     no_argument,       0, 'h'},
            {"qrcode",                   required_argument, 0, 'k'},
            {"http-port",                required_argument, 0, 'p'},
            {"ctrl-if-path",             required_argument, 0, 'i'},
            {"http-secrets",             required_argument, 0, 's'},
            {"tls-cert",                 required_argument, 0, 'C'},
            {"tls-key",                  required_argument, 0, 'K'},
            {"ap-conf-mode",             required_argument, 0, 'm'},
            {"configurator-key",         required_argument, 0, 'y'},
            {"configurator-private-key", required_argument, 0, 'z'},
            {"passphrase",               required_argument, 0, 'x'},
            {"service-name",             required_argument, 0, 'n'},
            {0, 0, 0, 0}
        };

        /* getopt_long stores the option index here. */
        int option_index = 0;

        arg_c = getopt_long(argc, argv, "k:p:i:s:C:K:m:hy:z:x:n:",
                            dpp_options, &option_index);

        if (arg_c == -1)
            break;

        switch (arg_c)
        {
        case 'h':
            print_usage();
            ret = DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR;
            goto cleanup;
        case 'k':
            qrcode = strdup(optarg);
            debug_mode = true;
            break;
        case 'p':
            port_number = optarg;
            break;
        case 'i':
            ctrl_if_path = strdup(optarg);
            break;
        case 's':
            http_secrets = optarg;
            break;
        case 'K':
            tls_key = optarg;
            break;
        case 'C':
            tls_cert = optarg;
            break;
        case 'm':
            ap_conf_mode = strdup(optarg);
            break;
        case 'y':
            configurator_key = optarg;
            break;
        case 'z':
            configurator_private_key = optarg;
            break;
        case 'x':
            sae_passphrase = optarg;
            break;
        case 'n':
            service_name = optarg;
            break;
        case '?':
            /* Error message printing handled by getopt_long */
            LOG_INFO("Unexpected usage with value '%s', refer to:\n", optarg);
            print_usage();
            goto cleanup;
        default:
            ret = DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR;
            LOG_ERROR("Default: with arg %s\n", optarg);
            print_usage();
            goto cleanup;
        }
    }

    if (ctrl_if_path == NULL)
    {
        ret = DPP_ERROR_CODE_ARGUMENTS_PARSING_ERROR;
        LOG_ERROR("--ctrl-if-path/-i is required\n");
        print_usage();
        goto cleanup;
    }

    /* Handle keys for persistence Hostapd process */
    if (!load_key(configurator_key, &key) ||
        !load_key(configurator_private_key, &ppkey))
    {
        if (!key)
            LOG_ERROR("Could not load /etc/key.pem file/s\n");
        if (!ppkey)
            LOG_ERROR("Could not load /etc/ppkey.pem file/s\n");
        ret = DPP_ERROR_CODE_HOSTAPD_KEYS_ERROR;
        goto cleanup;
    }

    sscanf(port_number, "%" SCNu16, &httpd_port);

    while (!ctrl_if_path_available())
    {
        LOG_NP(LOG_ERROR, "hostapd control interface not available, re-trying...\n");
        sleep(1);
    }

    LOG_NP(LOG_ERROR, "Connecting to Hostapd...\n");
    /* coverity[missing_lock:SUPPRESS] */
    state = DPP_STATE_DISCONNECTED;

    while (1)
    {
        DPP_ASSERT(pthread_mutex_lock(&dpp_mutex) == 0);
        while (prev_state == state)
            DPP_ASSERT(pthread_cond_wait(&dpp_cond, &dpp_mutex) == 0);

        prev_state = state;

        if (state == DPP_STATE_UNINIT)
        {
            if (mmsm_poll_started)
            {
                mmsm_stop();
                mmsm_poll_started = false;
            }
            if (hostapd)
            {
                mmsm_backend_hostapd_ctrl_destroy(hostapd);
                hostapd = NULL;
            }
        }
        else if (state == DPP_STATE_DISCONNECTED)
        {
            LOG_INFO("Try to Connect to Hostapd interface\n");

            if (!ctrl_if_path_available())
            {
                goto mutex_unlock;
            }

            /* If we cannot connect to Hostapd, do no change state */
            if ((hostapd = hostapd_reconnect(ctrl_if_path)) == NULL)
            {
                goto mutex_unlock;
            }

            LOG_NP(LOG_ERROR, "Connected to Hostapd\n");

            ret = hostapd_set_polling(hostapd, &ap_conf_mode,
                                      mmsm_poll_started);
            if (ret != DPP_ERROR_CODE_SUCCESS)
            {
                LOG_ERROR("Could not start monitor polling\n");
                goto cleanup;
            }

            /* If hostapd_start_dpp_process succeed we nee dto mark the poll
             * as active, and handle it upon reconnect or cleanup */
            mmsm_poll_started = true;

            ret = hostapd_init_sequence(hostapd, key, ppkey, ap_conf_mode,
                                        sae_passphrase);

            /* Hostapd control interface is down */
            if (ret == DPP_ERROR_CODE_CTRL_IF_ERROR)
                goto mutex_unlock;

            if (ret != DPP_ERROR_CODE_SUCCESS)
            {
                DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
                LOG_ERROR("Initial sequence flow failed\n");
                goto cleanup;
            }

            if (pthread_create(&polling_hostapd_thread,
                               NULL,
                               polling_hostapd_thread_fn,
                               NULL))
            {
                LOG_ERROR("Could not start Hostapd polling thread");
            }
        }
        else if (state == DPP_STATE_WAIT_APPLY_KEYS)
        {
            if ((ret = hostapd_apply_keys(hostapd, ap_conf_mode)) !=
                DPP_ERROR_CODE_SUCCESS)
            {
                DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
                goto cleanup;
            }

            state = DPP_STATE_WAIT_QR_CODE;
            if (debug_mode)
                state = DPP_STATE_RECEIVED_QR_CODE;

            /* dpp_mdns start advertising */
            if (!mdnsd_started)
            {
                LOG_INFO("Start mDNS service\n");
                if(!dpp_mdns_start(service_name, httpd_port))
                {
                    LOG_ERROR("Could not start mDNS service\n");
                    ret = DPP_ERROR_CODE_MDNS_SERVICE_FAILURE;
                    goto cleanup;
                }
            }
            mdnsd_started = true;

            /* dpp_httpd to start the server */
            /* TODO replace the hardcoded cert and secrets path with argparse
             * Also, consider if we should default to looking in /etc/dppd/...
             *
             */
            if (!httpd_started)
            {
                if (!dpp_httpd_start(httpd_port,
                                dppd_bskey_handler,
                                tls_cert,
                                tls_key,
                                http_secrets))
                {
                    LOG_ERROR("Failed to start the HTTP server\n");
                    ret = DPP_ERROR_CODE_HTTPD_SERVICE_FAILURE;
                    goto cleanup;
                }
            }
            httpd_started = true;
        }
        else if (state == DPP_STATE_RECEIVED_QR_CODE)
        {
            if (debug_mode)
            {
                ret = hostapd_apply_qr_code(hostapd, qrcode);
                DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
                goto cleanup;
            }
            else
            {
                /* dppd_bskey_handler callback will update qrcode value, when
                 * this thread is not still busy, from a legal POST request */
                if (qrcode)
                {
                    if (hostapd_apply_qr_code(hostapd, qrcode) !=
                        DPP_ERROR_CODE_SUCCESS)
                        LOG_WARN("Could not apply QR Code: '%s'\n", qrcode);
                    free(qrcode);
                    qrcode = NULL;
                }
            }
            state = DPP_STATE_WAIT_QR_CODE;
        }
mutex_unlock:
        DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
    }

cleanup:
    dpp_mdns_stop();
    dpp_httpd_stop();

    if (mmsm_poll_started)
    {
        mmsm_stop();
    }
    if (hostapd)
    {
        mmsm_backend_hostapd_ctrl_destroy(hostapd);
        hostapd = NULL;
    }

    free(ctrl_if_path);
    ctrl_if_path = NULL;
    free(qrcode);
    qrcode = NULL;
    free(key);
    key = NULL;
    free(ppkey);
    ppkey = NULL;
    cleanups();
    DPP_ASSERT(pthread_mutex_unlock(&dpp_mutex) == 0);
    return ret;
}
