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
#include "prov/provider_ctx.h"

static OSSL_OP_keymgmt_importkey_fn pkcs11_rsa_importkey;
static OSSL_OP_signature_newctx_fn rsa_newctx;
static OSSL_OP_signature_sign_init_fn rsa_signature_init;
static OSSL_OP_signature_sign_fn rsa_sign;
static OSSL_OP_signature_freectx_fn rsa_freectx;

DEFINE_STACK_OF(BIGNUM)
DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

static PKCS11_CTX *pkcs11_ctx_new(void);

typedef struct {
    OPENSSL_CTX *libctx;
    RSA *rsa;
    size_t mdsize;
    /* Should be big enough */
    char mdname[80];
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
} PROV_RSA_CTX;

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

static void *pkcs11_rsa_importkey(void *provctx, const OSSL_PARAM params[])
{
    RSA *rsa;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = 0;

    if ((rsa = RSA_new()) == NULL) {
        RSA_free(rsa);
        return NULL;
    }

    PKCS11_CTX *pkcs11_ctx = provctx;

    pkcs11_initialize(pkcs11_ctx->module_path);

    if (!pkcs11_get_slot(pkcs11_ctx))
        goto err;

    if (!pkcs11_start_session(pkcs11_ctx, &session))
        goto err;

    if (!pkcs11_login(session, pkcs11_ctx, CKU_USER))
        goto err;

    key = pkcs11_find_private_key(session, pkcs11_ctx);

    if (!key)
        goto err;

    return pkcs11_load_pkey(session, pkcs11_ctx, key);

 err:
    return NULL;

}

static int pkcs11_get_params(void *vprov, OSSL_PARAM params[])
{
    OSSL_PARAM *p = params;
    PKCS11_CTX *pkcs11_ctx = vprov;
    /* Only for test */
    p->data = pkcs11_ctx->module_path;
    return 1;
}

const OSSL_DISPATCH pkcs11_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_IMPORTKEY, (void (*)(void))pkcs11_rsa_importkey },
    { 0, NULL }
};

const OSSL_DISPATCH rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))rsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))rsa_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))rsa_sign },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))rsa_freectx },
    { 0, NULL }
};

static const OSSL_ALGORITHM pkcs11_signature[] = {
#ifndef OPENSSL_NO_RSA
    { "RSA", "default=yes", rsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

/* The table of functions this provider offers */
static const OSSL_ALGORITHM pkcs11_keymgmt[] = {
#ifndef OPENSSL_NO_RSA
    { "RSA", "default=yes", pkcs11_rsa_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *pkcs11_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return pkcs11_keymgmt;
    case OSSL_OP_SIGNATURE:
        return pkcs11_signature;
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
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(PKCS11_CTX));
    if (ctx == NULL) {
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

    if (c_get_params(provider, request)) {
        if (module_path == NULL || pin == NULL || keylabel == NULL) return 0;
    } else return 0;

    pkcs11_ctx = pkcs11_ctx_new();
    pkcs11_ctx->module_path = module_path;
    pkcs11_ctx->pin = (CK_BYTE*) pin;
    pkcs11_ctx->label = (CK_BYTE*) keylabel;

    *out = pkcs11_dispatch_table;
    *vprovctx = pkcs11_ctx;

    return 1;
}

static void *rsa_newctx(void *provctx)
{
    PROV_RSA_CTX *prsactx = OPENSSL_zalloc(sizeof(PROV_RSA_CTX));

    if (prsactx == NULL)
        return NULL;

    prsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    return prsactx;
}

static int rsa_signature_init(void *vrsactx, void *vrsa)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vrsactx;

    if (prsactx == NULL || vrsa == NULL || !RSA_up_ref(vrsa))
        return 0;
    RSA_free(prsactx->rsa);
    prsactx->rsa = vrsa;
    return 1;
}

static int rsa_sign(void *vprsactx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    int ret;
    unsigned int sltmp;
    size_t rsasize = RSA_size(prsactx->rsa);
    PKCS11_CTX *pkcs11_ctx = (PKCS11_CTX *) prsactx->libctx;

    if (sigsize < (size_t)rsasize)
        return 0;

    if (prsactx->mdsize != 0 && tbslen != prsactx->mdsize)
        return 0;

    ret = pkcs11_rsa_sign(RSA_PKCS1_PADDING, tbs, tbslen, sig, &sltmp,
                          prsactx->rsa, pkcs11_ctx);

    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static void rsa_freectx(void *vprsactx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    RSA_free(prsactx->rsa);
    EVP_MD_CTX_free(prsactx->mdctx);
    EVP_MD_free(prsactx->md);

    OPENSSL_free(prsactx);
}
