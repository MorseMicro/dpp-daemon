/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef MMSM_DATA_H__
#define MMSM_DATA_H__

#include <stdint.h>

/**
 * Identifies the type of data item in a mmsm data item key.
 */
typedef enum mmsm_key_type_t
{
    MMSM_KEY_TYPE_U32,
    MMSM_KEY_TYPE_STRING,
} mmsm_key_type_t;


/**
 * The key which is used to identify a data item in a list of many
 */
typedef struct mmsm_key_t
{
    /** The type of the data stored in the below union */
    mmsm_key_type_t type;
    union {
        /** The data as a string. Valid if type == MMSM_KEY_TYPE_STRING */
        char *string;
        /** The data as a uint32_t. Valid if type == MMSM_KEY_TYPE_U32 */
        uint32_t u32;
    } d;
} mmsm_key_t;


/**
 * Contains data for a series of data items that can be passed around smart
 * manager.
 *
 * This struct acts as a generic form of data transfer and can be used to
 * represent a number of different data structures.
 *
 * It's generally expected that the user of this data structure accesses it in a
 * way that depends on what they expect to be contained within it. The data that
 * is contained is context-sensitive, depending on the command that was sent,
 * and on what backend it was sent on.
 */
typedef struct mmsm_data_item_t
{
    /** The key which identifies the item. May be NULL if these data items are
     * more of a list structure */
    mmsm_key_t mmsm_key;

    /** The value being encoded. Should be accessed using the relevant helper
     * functions */
    uint8_t *mmsm_value;

    /** The length of mmsm_value. Take care that this is the actual data
     *  length so that if the mmsm_value is a string, this must include
     *  the terminating null in the length - so you cannot use the output
     *  of strlen to set this up you must add 1. */
    uint32_t mmsm_value_len;

    /** Contains a sub-list of values for nested data items */
    struct mmsm_data_item_t *mmsm_sub_values;

    /** The next value in this list of data items */
    struct mmsm_data_item_t *mmsm_next;
} mmsm_data_item_t;


/**
 *
 * @enum    mmsm_error_code
 *
 * @brief   enum for the error codes returned by mmsm functions
 **/
typedef enum mmsm_error_code {
    mmsm_success = 0,
    mmsm_unknown_error,
} mmsm_error_code;


#endif /* MMSM_DATA_H__ */
