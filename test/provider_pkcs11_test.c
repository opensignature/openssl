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
#include "testutil.h"

static int test_provider(const char *name)
{
    OSSL_PROVIDER *prov = NULL;

    return
        TEST_ptr(prov = OSSL_PROVIDER_load(NULL, name))
        && TEST_true(OSSL_PROVIDER_unload(prov));
}

#ifndef NO_PROVIDER_MODULE
static int test_loaded_provider(void)
{
    const char *name = "pkcs11";

    return test_provider(name);
}
#endif

int setup_tests(void)
{
#ifndef NO_PROVIDER_MODULE
    ADD_TEST(test_loaded_provider);
#endif
    return 1;
}

