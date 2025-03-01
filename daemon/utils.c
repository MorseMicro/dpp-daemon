/*
 * Copyright 2022 Morse Micro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include "utils.h"
#include <stdio.h>
#include <malloc.h>


bool
load_file_as_string(const char *path, size_t max_size, char **output,
                    size_t *size)
{
    FILE *f_handle;
    const size_t chunk_size = 1;
    size_t f_size = 0;
    char *f_data;

    if (path == NULL || output == NULL)
    {
        return false;
    }

    f_data = (char *)malloc(chunk_size);
    if (f_data == NULL)
    {
        LOG_WARN("Couldn't allocate memory\n");
        return false;
    }

    f_handle = fopen(path, "r");
    if (f_handle == NULL)
    {
        free(f_data);
        LOG_WARN("Error opening file %s\n", path);
        return false;
    }

    for (;;)
    {
        size_t num_read = fread(f_data + f_size, 1, chunk_size, f_handle);
        char *f_data_next;
        f_size += num_read;

        if (max_size != 0 && f_size > max_size)
        {
            free(f_data);
            fclose(f_handle);
            return false;
        }

        if (num_read != chunk_size && feof(f_handle))
        {
            /* Ensure the string is NULL terminated */
            if (f_data[f_size-1] != '\0')
            {
                f_data[f_size] = '\0';
            }
            else
            {
                f_size--;
            }

            fclose(f_handle);
            *output = f_data;
            if (size != NULL)
            {
                *size = f_size;
            }
            return true;
        }

        if (num_read != chunk_size && ferror(f_handle))
        {
            free(f_data);
            fclose(f_handle);
            LOG_WARN("Error reading file %s\n", path);
            return false;
        }

        f_data_next = realloc(f_data, f_size + chunk_size);
        if (f_data_next == NULL)
        {
            free(f_data);
            fclose(f_handle);
            LOG_WARN("Couldn't allocate memory\n");
            return false;
        }
        f_data = f_data_next;
    }
}

bool
load_key(const char *key_file, char **output)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    int i;
    unsigned char *der = NULL;
    int der_len;
    char *key = NULL;
    bool ret = true;

    if (key_file == NULL || output == NULL)
    {
        LOG_ERROR("File or output destination is NULL\n");
        ret = false;
        goto cleanup;
    }

    bio = BIO_new_file(key_file, "r");
    if (!bio)
    {
        LOG_ERROR("Could not allocate new BIO file\n");
        ret = false;
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        LOG_ERROR("Bad file '%s'\n", key_file);
        ret = false;
        goto cleanup;
    }

    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey)
    {
        LOG_ERROR("Could not allocate new EC_KEY\n");
        ret = false;
        goto cleanup;
    }

    der_len = i2d_ECPrivateKey(eckey, &der);
    if (der_len > 0) {
        key = malloc((der_len * 2) + 1);
        if (key == NULL)
        {
            LOG_ERROR("Couldn't allocate memory for keys\n");
            goto cleanup;
        }
        for (i = 0; i < der_len; i++)
        {
            sprintf((char*)(key + i * 2),"%02X", der[i]);
        }
        key[i * 2] = '\0';
    }
    else
    {
        LOG_ERROR("i2d_ECPrivateKey failed with '%s'\n",
            ERR_error_string(ERR_get_error(), NULL));
        ret = false;
        goto cleanup;
    }

    *output = key;

cleanup:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(der);
    return ret;
}
