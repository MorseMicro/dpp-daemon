/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef UTILS_H__
#define UTILS_H__

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "logging.h"

/**
 * Gets a pointer to the container that contains the provided interface.
 *
 * The container must have a mmsm_backend_intf_t member called intf inside of
 * it, and ptr must point to an instance of mmsm_backend_intf_t. For example:
 *
 * typedef struct backend_hostapd_ctrl_t {
 *     mmsm_backend_intf_t intf;
 *     // etc.
 * }
 *
 * ... then convert from (mmsm_backend_intf_t *) to (backend_hostapd_ctrl_t *)
 * like this:
 *
 * backend_hostapd_ctrl_t *hostapd = get_container_from_intf(hostapd, intf)
 */
#define get_container_from_intf(container, ptr)                         \
    (typeof(container))(((void *)(ptr)) - offsetof(typeof(*container), intf))


/**
 * Asserts that condition x evaluates to true
 *
 * Prints out some useful information on assert failure and exits
 */
#define MMSM_ASSERT(x)                                    \
    do {                                                  \
        if (!(x))                                         \
        {                                                 \
            LOG_ERROR("ASSERT FAILED: %s\n", #x);            \
            LOG_ERROR("errno: %s\n", strerror(errno));       \
            exit(1);                                      \
        }                                                 \
    } while (0)


/**
 * Helper to mark the provided value as unused
 */
#define UNUSED(x) (void)(x)

bool
load_key(const char *key_file, char **output);

/**
 * Loads the contents of a file into memory as a NULL terminated string.
 *
 * The file path can point to a stream, such as a pipe.
 *
 * @param file the path to the file
 * @param max_size The maximum size the file is expected to be, if the file is
 *                 larger a failure will be returned. This size does not
 *                 include a final NULL terminator if one needs to be added.
 *                 If set to 0, there is no size limit. Internally the file is
 *                 read in chunks, so mallocs and reads can slightly exceed the
 *                 max size given.
 * @param output a pointer to a char * to store the malloc'd NULL output, if
 *               successful. You should free() this memory when you are done.
 * @param size a pointer to store the size of the output, set to NULL if not
 *             required. The size returned excludes any NULL terminators.
 *
 * @return On success, returns true and set both output and size. Otherwise
 * returns false and does not modify output or size. If the file is larger
 * than max_size given, it is considered a failure; false is returned.
 */
bool
load_file_as_string(const char *path, size_t max_size, char **output,
                    size_t *size);


#endif /* UTILS_H__ */
