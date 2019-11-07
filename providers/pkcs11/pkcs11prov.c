/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include "pkcs11_err.h"
#include "pkcs11prov.h"

static PKCS11_CTX *pkcs11_ctx_new(void);

/* Functions provided by the core */
static OSSL_core_get_params_fn *c_get_params = NULL;

static const OSSL_PARAM pkcs11_param_types[] = {
    { "module_path", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static OSSL_provider_gettable_params_fn pkcs11_gettable_params;
static OSSL_provider_get_params_fn pkcs11_get_params;

static const OSSL_PARAM *pkcs11_gettable_params(void *_)
{
    return pkcs11_param_types;
}

static int pkcs11_get_params(void *vprov, OSSL_PARAM params[])
{
    const OSSL_PROVIDER *prov = vprov;
    OSSL_PARAM *p = params;
    int ok = 1;

    for (; ok && p->key != NULL; p++) {
        if (strcmp(p->key, "module_path") == 0) {
            static char *module_path;
            static OSSL_PARAM request[] = {
                { "module_path", OSSL_PARAM_UTF8_PTR,
                  &module_path, sizeof(&module_path), 0 },
                { NULL, 0, NULL, 0, 0 }
            };
            char buf[256];
            size_t buf_l;
            module_path = NULL;
            if (c_get_params(prov, request)) {
                if (module_path) {
                    strcpy(buf, module_path);
                }
            }
            p->return_size = buf_l = strlen(buf) + 1;
            if (p->data_size >= buf_l)
                strcpy(p->data, buf);
            else
                ok = 0;
        }
    }
    return ok;
}

static const OSSL_ALGORITHM *pkcs11_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH pkcs11_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pkcs11_get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pkcs11_gettable_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_query },
    { 0, NULL }
};

static PKCS11_CTX *pkcs11_ctx_new(void)
{
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
//        PKCS11err(PKCS11_F_PKCS11_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->lock = CRYPTO_THREAD_lock_new();
    return ctx;
}

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    PKCS11_CTX *pkcs11_ctx = NULL;
    static char *module_path = NULL;
    static OSSL_PARAM request[] = {
        { "module_path", OSSL_PARAM_UTF8_PTR,
          &module_path, sizeof(&module_path), 0 },
          { NULL, 0, NULL, 0, 0 }
        };
    char buf[256];

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    *out = pkcs11_dispatch_table;
    *vprovctx = (void *)provider;

    if (c_get_params(provider, request)) {
        if (module_path) {
            strcpy(buf, module_path);
        }
    }

    if (pkcs11_initialize(module_path) != CKR_OK)
        return 0;

    pkcs11_ctx = pkcs11_ctx_new();
    pkcs11_ctx->module_path = module_path;

    return 1;
}
