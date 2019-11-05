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

/* Functions provided by the core */
static OSSL_core_get_params_fn *c_get_params = NULL;

static int pkcs11_get_params(const OSSL_PROVIDER *prov,
                             OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL PKCS#11 Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

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
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
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
    return 1;
}
