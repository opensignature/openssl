/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include "e_pkcs11_err.h"

#define ENG_LIB_NAME "pkcs11 engine"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA ENG_str_functs[] = {
    {ERR_FUNC(ENG_F_CTX_CTRL_LOAD_CERT), "ctx_ctrl_load_cert"},
    {ERR_FUNC(ENG_F_CTX_CTRL_SET_PIN), "ctx_ctrl_set_pin"},
    {ERR_FUNC(ENG_F_CTX_ENGINE_CTRL), "ctx_engine_ctrl"},
    {ERR_FUNC(ENG_F_CTX_LOAD_CERT), "ctx_load_cert"},
    {ERR_FUNC(ENG_F_CTX_LOAD_KEY), "ctx_load_key"},
    {ERR_FUNC(ENG_F_CTX_LOAD_PRIVKEY), "ctx_load_privkey"},
    {ERR_FUNC(ENG_F_CTX_LOAD_PUBKEY), "ctx_load_pubkey"},
    {0, NULL}
};

static ERR_STRING_DATA ENG_str_reasons[] = {
    {ERR_REASON(ENG_R_INVALID_ID), "invalid id"},
    {ERR_REASON(ENG_R_INVALID_PARAMETER), "invalid parameter"},
    {ERR_REASON(ENG_R_OBJECT_NOT_FOUND), "object not found"},
    {ERR_REASON(ENG_R_UNKNOWN_COMMAND), "unknown command"},
    {0, NULL}
};

#endif

#ifdef ENG_LIB_NAME
static ERR_STRING_DATA ENG_lib_name[] = {
    {0, ENG_LIB_NAME},
    {0, NULL}
};
#endif

static int ENG_lib_error_code = 0;
static int ENG_error_init = 1;

int ERR_load_ENG_strings(void)
{
    if (ENG_lib_error_code == 0)
        ENG_lib_error_code = ERR_get_next_error_library();

    if (ENG_error_init) {
        ENG_error_init = 0;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(ENG_lib_error_code, ENG_str_functs);
        ERR_load_strings(ENG_lib_error_code, ENG_str_reasons);
#endif

#ifdef ENG_LIB_NAME
        ENG_lib_name->error = ERR_PACK(ENG_lib_error_code, 0, 0);
        ERR_load_strings(0, ENG_lib_name);
#endif
    }
    return 1;
}

void ERR_unload_ENG_strings(void)
{
    if (ENG_error_init == 0) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(ENG_lib_error_code, ENG_str_functs);
        ERR_unload_strings(ENG_lib_error_code, ENG_str_reasons);
#endif

#ifdef ENG_LIB_NAME
        ERR_unload_strings(0, ENG_lib_name);
#endif
        ENG_error_init = 1;
    }
}

void ERR_ENG_error(int function, int reason, char *file, int line)
{
    if (ENG_lib_error_code == 0)
        ENG_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(ENG_lib_error_code, function, reason, file, line);
}
