/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "datalog.h"
#include "logging.h"


typedef struct timestamp_t
{
    uint16_t year;
    uint16_t month;
    uint16_t day;
    uint16_t hour;
    uint16_t minute;
    uint16_t second;
    uint16_t millisecond;
} timestamp_t;


/**
 * Get the current timestamp structure.
 */
timestamp_t
get_timestamp(void)
{
    time_t rawtime;
    struct tm tm_time;
    timestamp_t timestamp;

    time(&rawtime);
    (void)localtime_r(&rawtime, &tm_time);

    timestamp.year = tm_time.tm_year + 1900;
    timestamp.month = tm_time.tm_mon;
    timestamp.day = tm_time.tm_mday;
    timestamp.hour = tm_time.tm_hour;
    timestamp.minute = tm_time.tm_min;
    timestamp.second = tm_time.tm_sec;

    struct timeval te;
    gettimeofday(&te, NULL);
    timestamp.millisecond = (te.tv_usec / 1000) % 1000;
    return timestamp;
}


FILE *
datalog_create(char *name)
{
    int status = mkdir("./log", 0700);
    FILE *fptr;
    char file_name[128];

    if (status == -1 && errno != EEXIST)
    {
        LOG_ERROR("Cannot create directory ./log (%s)\n", strerror(errno));
        return NULL;
    }

    timestamp_t timestamp = get_timestamp();
    sprintf(file_name, "./log/%s_%04u_%02u_%02u_%02u_%02u_%02u.log", name,
        timestamp.year, timestamp.month, timestamp.day, timestamp.hour,
        timestamp.minute, timestamp.second);

    fptr = fopen(file_name,"w");
    if(fptr == NULL)
    {
        LOG_ERROR("Can't open data log file %s: %s\n",
                  file_name, strerror(errno));
    }
    return fptr;
}


bool
datalog_write_string(FILE *file, const char *str, ...)
{
    timestamp_t timestamp = get_timestamp();

    if (!file)
        return false;

    fprintf(file, "%04u/%02u/%02u:%02u:%02u:%02u:%03u ",
        timestamp.year, timestamp.month, timestamp.day, timestamp.hour,
        timestamp.minute, timestamp.second, timestamp.millisecond);

    va_list args;
    va_start(args, str);
    vfprintf(file, str, args);
    va_end(args);
    return true;
}


bool
datalog_write_data(FILE *file, uint8_t *data, uint32_t size)
{
    timestamp_t timestamp = get_timestamp();

    if (!file)
        return false;

    fprintf(file, "%04u/%02u/%02u:%02u:%02u:%02u:%03u \n",
        timestamp.year, timestamp.month, timestamp.day, timestamp.hour,
        timestamp.minute, timestamp.second, timestamp.millisecond);
    for (int i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            fprintf(file, "\t");

        fprintf(file, "%02x ", data[i]);

        if (i % 16 == 7)
            fprintf(file, " ");
        else if (i % 16 == 15)
            fprintf(file, "\n");
    }
    fprintf(file, "\n");
    return true;
}


bool
datalog_close(FILE *file)
{
    if (!file)
    {
        LOG_ERROR("Can't close data log file as File descriptor is NULL\n");
        return false;
    }

    if (fclose(file) > 0)
    {
        LOG_ERROR("Can't close data log file: %s\n", strerror(errno));
        return false;
    }

    return true;
}
