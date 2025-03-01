/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#ifndef HELPERS_H__
#define HELPERS_H__

#include <stdbool.h>
#include <stdint.h>

#include "mmsm_data.h"


/**
 * Asserts that the statement x is mmsm_success, or exits
 */
#define ASSERT_SUCCESS(x)                               \
    do {                                                \
        mmsm_error_code err = x;                        \
        if (err != mmsm_success) {                      \
            printf("FATAL: "#x " failed: %d\n", err);   \
            exit(1);                                    \
        }                                               \
    } while (0);


/**
 * Dumps the given data to the log
 *
 * @param result The data to dump
 * @param level The log level to dump the data at
 */
#define MMSM_DUMP_DATA_ITEM(result, level) do       \
    {                                               \
        if (LOG_LEVEL >= (level))                   \
            _mmsm_dump_data_item(result, level);    \
    } while (0)


/**
 * Dumps the given data item to stdout
 *
 * Use the macro MMSM_DUMP_DATA_ITEM instead, which uses the local file's log
 * level.
 */
void
_mmsm_dump_data_item(mmsm_data_item_t *result, int log_level);


/**
 * Dumps the nl80211 data item to stdout
 *
 * @param result The data to dump
 */
void
mmsm_dump_nl80211_data_item(mmsm_data_item_t *result);


/**
 * Finds a string key within the data item and returns the associated value
 *
 * @param head The list to search
 * @param key The key to search for
 *
 * @returns the value if found, otherwise @c NULL
 */
uint8_t *
mmsm_find_value_by_key(mmsm_data_item_t *head, const char *key);


/**
 * Finds a key within the data item and returns the associated data_item
 *
 * @param head The list to search
 * @param key The mmsm_key_t to search for
 *
 * @returns a pointer to the data item that includes this key
 */
mmsm_data_item_t *
mmsm_find_key(mmsm_data_item_t *head, const mmsm_key_t *key);

/**
 * Finds an integer key within the data item and returns the associated value
 *
 * @param head The list to search
 * @param key The key to search for
 *
 * @returns the value if found, otherwise @c NULL
 */
uint8_t *
mmsm_find_value_by_intkey(mmsm_data_item_t *head, uint32_t key);


/**
 * Returns the nth value in the list
 *
 * @param head The head of the list
 * @param n Zero-based index of which item to find
 *
 * @returns the value if found, otherwise @c NULL
 */
uint8_t *
mmsm_find_nth_value(mmsm_data_item_t *head, uint32_t n);


/**
 * Find the item by keys in nl80211 data list
 *
 * @param head The head of the list
 * @param layers of keys to be matched tree data structure
 *
 * @returns the value if found, otherwise @c NULL
 */
uint8_t *
mmsm_find_by_nested_intkeys(mmsm_data_item_t *head, ...);


/**
 * Checks if the given flag is set within the value of the given key.
 *
 * Flags are in the format as provided by hostapd ctrl, for example, with a
 * result in the format like:
 *
 *  result = {
 *    "flags": "[AUTH][CONNECTED]"
 *  }
 *
 *  mmsm_is_flag_set_in(result, "flags", "CONNECTED") == true
 *  mmsm_is_flag_set_in(result, "flags", "ASSOC") == false
 *
 *  @param result The result structure to look at
 *  @param key The key to look for the flags within
 *  @param flag The flag to look for
 *
 *  @returns @c true if the flag exists, or @c false
 */
bool
mmsm_is_flag_set_in(
    mmsm_data_item_t *result, const char *key, const char *flag);


/**
 * Frees the item and all children
 *
 * mmsm_data_item_free(NULL) returns with no action.
 *
 * @param item The item to free
 */
void
mmsm_data_item_free(mmsm_data_item_t *item);

#endif /* HELPERS_H__ */
