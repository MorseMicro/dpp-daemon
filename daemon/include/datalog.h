/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef DATALOG_H__
#define DATALOG_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


/**
 * Create data log file
 *
 * @param Log file name
 */
FILE *
datalog_create(char *name);


/**
 * Write string to the file
 *
 * @param file The file handler
 * @param length The data length
 * @param str, ...
 */
bool
datalog_write_string(FILE *file, const char *str, ...);


/**
 * Write plain data of hex bytes to the file
 *
 * @param file The file handler
 * @param data The data to be written
 * @param size The length of the data
 */
bool
datalog_write_data(FILE *file, uint8_t *data, uint32_t size);


/**
 * Close the file
 *
 * @param file The file handler
 */
bool
datalog_close(FILE *file);

#endif
