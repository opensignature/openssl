/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "crypto/evp.h"
#include "testutil.h"
#include "internal/provider.h"

static char buf[256];
static OSSL_PARAM request[] = {
    { "module_path", OSSL_PARAM_UTF8_STRING, buf, sizeof(buf), 0 },
    { NULL, 0, NULL, 0, 0 }
};

static int test_provider(OSSL_PROVIDER *prov)
{
    const char *module_path = NULL;
    int ret = 0;
    EVP_KEYMGMT *km = NULL;
    OPENSSL_CTX *ctx;
    EVP_PKEY *k = NULL;
    RSA *rsa = NULL;

    ret =
        TEST_true(ossl_provider_activate(prov))
        && TEST_true(ossl_provider_get_params(prov, request))
        && TEST_ptr(module_path = request[0].data)
        && TEST_size_t_gt(request[0].data_size, 0);

    TEST_info("Module path: %s\n", module_path);

    ctx = ossl_provider_library_context(prov);
    km = EVP_KEYMGMT_fetch(ctx, "RSA", NULL);

    TEST_ptr(rsa = evp_keymgmt_importkey(km, request));
    TEST_ptr(k = EVP_PKEY_new());
    TEST_size_t_gt(EVP_PKEY_assign_RSA(k, rsa), 0);

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_PUBKEY(out, k);

    ossl_provider_free(prov);
    return ret;
}

#ifndef NO_PROVIDER_MODULE
static int test_loaded_provider(void)
{
    const char *name = "pkcs11";
    OSSL_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov = ossl_provider_find(NULL, name, 0))
        && test_provider(prov);
}
#endif

int setup_tests(void)
{
#ifndef NO_PROVIDER_MODULE
    ADD_TEST(test_loaded_provider);
#endif
    return 1;
}

