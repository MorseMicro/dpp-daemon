/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include "helpers.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdarg.h>


uint8_t *
mmsm_find_value_by_intkey(mmsm_data_item_t *head, uint32_t key)
{
    while (head)
    {
        if (head->mmsm_key.type == MMSM_KEY_TYPE_U32 &&
            head->mmsm_key.d.u32 == key)
        {
            return head->mmsm_value;
        }

        head = head->mmsm_next;
    }
    return NULL;
}


static void
mmsm_dump_data_item_internal(mmsm_data_item_t *result,
                             int log_level,
                             int indent_level)
{
    while (result)
    {
        bool looks_binary = false;
        int i;

        LOG_PREFIX(log_level);

        for (i = 0; i < indent_level * 4; i++)
        {
            LOG_NP(log_level, " ");
        }

        switch (result->mmsm_key.type)
        {
        case MMSM_KEY_TYPE_U32:
            LOG_NP(log_level, "k=[%u]", result->mmsm_key.d.u32);
            break;

        case MMSM_KEY_TYPE_STRING:
            LOG_NP(log_level, "k=\"%s\"", result->mmsm_key.d.string);
            break;

        default:
            LOG_NP(log_level, "Key type %d is invalid\n",
                result->mmsm_key.type);
            MMSM_ASSERT(0);
            break;
        }

        if (result->mmsm_value_len > 0)
        {
            /* If we see any NULL characters, or we see anything above 127,
             * assume it's binary data */
            for (i = 0; i < result->mmsm_value_len - 1; i++)
            {
                if (result->mmsm_value[i] == 0 ||
                    result->mmsm_value[i] > 127)
                {
                    looks_binary = true;
                    break;
                }
            }
            /* We expect the last character to be NULL for this to be a
             * string */
            if (result->mmsm_value[i] != 0)
            {
                looks_binary = true;
            }

            if (looks_binary)
            {
                LOG_NP(log_level, " v={");
                for (i = 0; i < result->mmsm_value_len; i++)
                {
                    LOG_NP(log_level, " %02x", result->mmsm_value[i]);
                }
                LOG_NP(log_level, " }\n");
            }
            else
            {
                LOG_NP(log_level, " v=\"%s\"\n", (char *)result->mmsm_value);
            }
        }
        else
        {
            LOG_NP(log_level, " v=[]\n");
        }

        if (result->mmsm_sub_values)
        {
            mmsm_dump_data_item_internal(
                result->mmsm_sub_values, log_level, indent_level + 1);
        }

        result = result->mmsm_next;
    }
}


void
_mmsm_dump_data_item(mmsm_data_item_t *result, int log_level)
{
    mmsm_dump_data_item_internal(result, log_level, 0);
}


uint8_t *
mmsm_find_value_by_key(mmsm_data_item_t *head, const char *key)
{
    while (head)
    {
        if (head->mmsm_key.type == MMSM_KEY_TYPE_STRING &&
            strcmp(head->mmsm_key.d.string, key) == 0)
        {
            return head->mmsm_value;
        }

        head = head->mmsm_next;
    }
    return NULL;
}


mmsm_data_item_t *
mmsm_find_key(mmsm_data_item_t *head, const mmsm_key_t *key)
{
    while (head)
    {
        if (head->mmsm_key.type == key->type)
        {
            if (head->mmsm_key.type == MMSM_KEY_TYPE_STRING &&
                strcmp(head->mmsm_key.d.string, key->d.string) == 0)
            {
                return head;
            }

            if (head->mmsm_key.type == MMSM_KEY_TYPE_U32 &&
                head->mmsm_key.d.u32 == key->d.u32)
            {
                return head;
            }
        }

        head = head->mmsm_next;
    }
    return NULL;
}


uint8_t *
mmsm_find_nth_value(mmsm_data_item_t *head, uint32_t n)
{
    while (head && n > 0)
    {
        head = head->mmsm_next;
        n--;
    }
    if (!head)
        return NULL;

    return head->mmsm_value;
}


uint8_t *
mmsm_find_by_nested_intkeys(mmsm_data_item_t *head, ...)
{
    va_list args;
    int attr_id;
    mmsm_data_item_t *iter;

    va_start(args, head);
    iter = head;

    attr_id = va_arg(args, int);
    while (attr_id != -1)
    {
        for (; iter; iter = iter->mmsm_next)
        {
            if (iter->mmsm_key.type == MMSM_KEY_TYPE_U32 &&
                iter->mmsm_key.d.u32 == attr_id)
            {
                break;
            }
        }
        if (iter == NULL)
        {
            va_end(args);
            return NULL;
        }

        attr_id = va_arg(args, int);

        if (attr_id != -1)
            iter = iter->mmsm_sub_values;
    }

    va_end(args);
    return iter->mmsm_value;
}


bool
mmsm_is_flag_set_in(mmsm_data_item_t *result, const char *key, const char *flag)
{
    char *value = (char *)mmsm_find_value_by_key(result, key);
    char wrapped_flag[1024];
    char *test;

    if (sizeof(wrapped_flag) < strlen(flag))
    {
        return false;
    }

    strcpy(&wrapped_flag[1], flag);

    wrapped_flag[0] = '[';
    wrapped_flag[strlen(flag) + 1] = ']';
    wrapped_flag[strlen(flag) + 2] = 0;

    test = strstr(value, wrapped_flag);

    return test ? true : false;
}


void
mmsm_data_item_free(mmsm_data_item_t *item)
{
    mmsm_data_item_t *prev;

    while (item)
    {
        if (item->mmsm_sub_values)
        {
            mmsm_data_item_free(item->mmsm_sub_values);
            item->mmsm_sub_values = NULL;
        }
        if (item->mmsm_value) {
            free(item->mmsm_value);
            item->mmsm_value = NULL;
        }
        if (item->mmsm_key.type == MMSM_KEY_TYPE_STRING) {
            free(item->mmsm_key.d.string);
            item->mmsm_key.d.string = NULL;
        }
        prev = item;
        item = item->mmsm_next;
        free(prev);
    }
}
