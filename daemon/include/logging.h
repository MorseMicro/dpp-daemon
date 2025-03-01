/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef LOGGING_H__
#define LOGGING_H__

#include <stdint.h>


#define LOG_COLOUR_ENABLED

/** No logging messages. */
#define LOG_LEVEL_NONE   (0)

/** Print error messages. */
#define LOG_LEVEL_ERROR  (1)

/** Print warning messages. */
#define LOG_LEVEL_WARN   (2)

/** Print informative messages. */
#define LOG_LEVEL_INFO   (3)

/** Print debug messages. */
#define LOG_LEVEL_DEBUG  (4)

/** Print debug messages. */
#define LOG_LEVEL_VERBOSE  (5)

/* Set our global log level, allowing local log levels to take precedence. */
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_ERROR
#endif


/* Use milliseconds for the log time. */
#define LOG_TIME() (mmsm_get_run_time_ms())

#if defined(LOG_COLOUR_ENABLED)
#define LOG_COLOUR_RST "\x1b[0m"
#else
#define LOG_COLOUR_RST ""
#endif


/* Add fancy colours to the logs, if enabled. */
static const char *LOG_COLOURS[] __attribute__((unused)) = {
#if defined(LOG_COLOUR_ENABLED)
    "",
    "\x1b[31mERR",
    "\x1b[33mWRN",
    "\x1b[34mINF",
    "\x1b[0mDBG",
    "\x1b[35mVBS",
#else
    "",
    "ERR",
    "WRN",
    "INF",
    "DBG",
    "VBS",
#endif
};


#define LOG_PREFIX(level)                           \
    printf("%s %6u %s:%u %s",                       \
           LOG_COLOURS[level],                      \
           LOG_TIME(),                              \
           __FILE__, __LINE__,                      \
           LOG_COLOUR_RST);                         \


#define LOG(level, ...)                                     \
    do {                                                    \
        LOG_PREFIX(level);                                  \
        printf(__VA_ARGS__);                                \
    } while (0)


#define LOG_NP(level, ...) printf(__VA_ARGS__)


#define LOG_VAR(level, debug_level, ...)                            \
    do {                                                            \
        if ((debug_level) >= (level))                               \
            LOG(level, __VA_ARGS__);                                \
    } while (0)


#define LOG_VAR_NP(level, debug_level, ...)     \
    do {                                        \
        if ((debug_level) >= (level))           \
            printf(__VA_ARGS__);                \
    } while (0)


#define LOG_ERROR(...) LOG_VAR(LOG_LEVEL_ERROR, LOG_LEVEL, __VA_ARGS__)
#define LOG_ERROR_NP(...) LOG_VAR_NP(LOG_LEVEL_ERROR, LOG_LEVEL, __VA_ARGS__)

#define LOG_WARN(...) LOG_VAR(LOG_LEVEL_WARN, LOG_LEVEL, __VA_ARGS__)
#define LOG_WARN_NP(...) LOG_VAR_NP(LOG_LEVEL_WARN, LOG_LEVEL, __VA_ARGS__)

#define LOG_INFO(...) LOG_VAR(LOG_LEVEL_INFO, LOG_LEVEL, __VA_ARGS__)
#define LOG_INFO_NP(...) LOG_VAR_NP(LOG_LEVEL_INFO, LOG_LEVEL, __VA_ARGS__)

#define LOG_DEBUG(...) LOG_VAR(LOG_LEVEL_DEBUG, LOG_LEVEL, __VA_ARGS__)
#define LOG_DEBUG_NP(...) LOG_VAR_NP(LOG_LEVEL_DEBUG, LOG_LEVEL, __VA_ARGS__)

#define LOG_VERBOSE(...) LOG_VAR(LOG_LEVEL_VERBOSE, LOG_LEVEL, __VA_ARGS__)
#define LOG_VERBOSE_NP(...) \
    LOG_VAR_NP(LOG_LEVEL_VERBOSE, LOG_LEVEL, __VA_ARGS__)


#define LOG_DATA(level, data, size)                                   \
    do {                                                              \
        if (LOG_LEVEL >= (level))                                     \
            mmsm_dump_data(data, size);                               \
    } while(0)


/**
 * Initialize program running time. It is to be called at begginning of
 * the program starts.
 */
void
mmsm_init_time(void);


/**
 * Get program's current run time in milliseconds.
 *
 *  @returns current run time in milliseconds
 */
uint32_t
mmsm_get_run_time_ms(void);


/**
 * Dump the packet data.
 *
 * @param length The data length
 * @param data The data to dump
 */
void
mmsm_dump_data(uint8_t *data, uint32_t size);


#endif
