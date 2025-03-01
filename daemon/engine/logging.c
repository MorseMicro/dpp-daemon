/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/time.h>

#include "logging.h"

static uint64_t start_time = 0;


void
mmsm_init_time(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    start_time = te.tv_sec * 1000LL + te.tv_usec / 1000;
}


uint32_t
mmsm_get_run_time_ms(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    uint64_t current_time = te.tv_sec * 1000LL + te.tv_usec / 1000;
    uint32_t run_time = 0;

    if (start_time > 0 && current_time > start_time)
    {
        run_time = (uint32_t)(current_time - start_time);
    }
    return run_time;
}


void
mmsm_dump_data(uint8_t *data, uint32_t size)
{
    if (LOG_LEVEL < LOG_LEVEL_VERBOSE)
        return;

    for (int i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            LOG_VERBOSE("\t");

        printf("%02x ", data[i]);

        if (i % 16 == 7)
            printf(" ");
        else if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}
