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
    { "pin", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "keylabel", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
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
    OSSL_PARAM *p = params;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Pkcs#11 Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "module_path"))
    p = OSSL_PARAM_locate(params, "module_path");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pin"))
    p = OSSL_PARAM_locate(params, "pin");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "keylabel"))
    p = OSSL_PARAM_locate(params, "keylabel");

    return 1;
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
    static char *keylabel = NULL;
    static char *pin = NULL;
    static OSSL_PARAM request[] = {
        { "module_path", OSSL_PARAM_UTF8_PTR,
          &module_path, sizeof(&module_path), 0 },
        { "pin", OSSL_PARAM_UTF8_PTR,
          &pin, sizeof(&pin), 0 },
        { "keylabel", OSSL_PARAM_UTF8_PTR,
          &keylabel, sizeof(&keylabel), 0 },
          { NULL, 0, NULL, 0, 0 }
        };

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
        if (module_path == NULL || pin == NULL || keylabel == NULL) return 0;
    } else return 0;

    pkcs11_ctx = pkcs11_ctx_new();
    pkcs11_ctx->module_path = module_path;
    pkcs11_ctx->pin = (CK_BYTE*) pin;
    pkcs11_ctx->label = (CK_BYTE*) keylabel;


    /* only for test */
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = 0;

    pkcs11_initialize(module_path);

    if (!pkcs11_get_slot(pkcs11_ctx))
        goto err;

    if (!pkcs11_start_session(pkcs11_ctx, &session))
        goto err;

    if (!pkcs11_login(session, pkcs11_ctx, CKU_USER))
        goto err;

    key = pkcs11_find_private_key(session, pkcs11_ctx);

    if (!key)
        goto err;

    pkcs11_load_pkey(session, pkcs11_ctx, key);

    return 1;

 err:
    PKCS11_trace("pkcs11_engine_load_private_key failed\n");
    return 0;
}
