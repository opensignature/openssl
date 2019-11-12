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
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_SIGNATURE *rsaimpl = NULL;
    RSA *rsa = NULL;
    size_t sigLength;
    unsigned char *sig = NULL;
    BIO *out = NULL, *out2 = NULL;

    /* SHA256 digest */
    const unsigned char mdToSign[] = {
      0x27, 0x51, 0x8b, 0xa9, 0x68, 0x30, 0x11, 0xf6, 0xb3, 0x96, 0x07, 0x2c,
      0x05, 0xf6, 0x65, 0x6d, 0x04, 0xf5, 0xfb, 0xc3, 0x78, 0x7c, 0xf9, 0x24,
      0x90, 0xec, 0x60, 0x6e, 0x50, 0x92, 0xe3, 0x26
    };

    ret =
        TEST_true(ossl_provider_activate(prov))
        && TEST_true(ossl_provider_get_params(prov, request))
        && TEST_ptr(module_path = request[0].data)
        && TEST_size_t_gt(request[0].data_size, 0);

    if (!ret) goto err;

    /* Get params test */
    TEST_info("Module path: %s\n", module_path);

    /* Import key test */
    km = EVP_KEYMGMT_fetch(NULL, "RSA", NULL);

    if (!TEST_ptr(rsa = evp_keymgmt_importkey(km, NULL))
        || !TEST_ptr(k = EVP_PKEY_new()))
        goto err;

    if (!TEST_size_t_gt(EVP_PKEY_assign_RSA(k, rsa), 0))
        goto err;

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_PUBKEY(out, k);

    /* Sign test */
    kctx = EVP_PKEY_CTX_new(k, NULL);
    rsaimpl = EVP_SIGNATURE_fetch(NULL, "RSA", NULL);

    sig = OPENSSL_malloc(RSA_size(rsa));

    if (!TEST_ptr(kctx)
        || !TEST_ptr(rsaimpl)
        || !TEST_int_gt(EVP_PKEY_sign_init_ex(kctx, rsaimpl), 0))
        goto err;

    if (!TEST_int_eq(EVP_PKEY_sign(kctx, sig, &sigLength, mdToSign,
                                   sizeof(mdToSign)),1))
        goto err;

    out2 = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_dump(out2, (char *)sig, sigLength);

    ossl_provider_free(prov);
    return ret;

 err:
    ossl_provider_free(prov);
    return 0;
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

/* result expected

1..1
# INFO:
# Module path: /usr/lib/softhsm/libsofthsm.so
#

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA85fG4fjlLABqqqAkQpis
0djiifYIllUE1wsGJ/Qa7xSatXr756y0X+oOH9wBLnHhUiogaiUuhoIajwne2eN/
upgxJcBeLithEynkyRf1tN/imb1FjbzdEcrVcRDVFFEGaSTFaIamOFnV6FDINQtB
tCt0BCfRSwiqVLi1SkO9/I7ztZDClZIZB1tKm4rC6jOTLPRIrEfgoYjBrjt6PpS7
IxhwmsUcNZby83KPpTJ1pNQxQsrZlIFapXknRKd8NqCLHnm3qjGCWg7147+lsYBo
fT0er3mBZPJbRD2lxmv0TW7/NiRu5CKdRDMKFEvOkli2clVJ1zaGmDNuF4t8iLHF
IwIDAQAB
-----END PUBLIC KEY-----

0000 - 15 c3 11 ef 1e 53 4f af-c7 ed c6 08 89 ac 0b a9   .....SO.........
0010 - 5c b9 78 85 22 d7 56 19-04 a2 05 50 85 58 51 f1   \.x.".V....P.XQ.
0020 - e9 0d 8e 61 c1 43 33 06-00 b0 5d 82 6d b1 1a 1b   ...a.C3...].m...
0030 - f9 31 7c b1 76 f3 0d 2b-67 0b 80 c1 09 ba 07 53   .1|.v..+g......S
0040 - 6d 1b b0 54 9c 70 8b 51-82 9c 61 b5 84 03 c5 12   m..T.p.Q..a.....
0050 - af 42 85 1d 5a ac 5b b9-a8 b5 3e 42 f6 2d 7d 0a   .B..Z.[...>B.-}.
0060 - 5a bc 80 5e 60 8d 13 07-d7 77 68 ee e8 7f e1 89   Z..^`....wh.....
0070 - 5d 77 6b cb 77 87 40 e7-e5 c4 6a 8b 50 2a ec c4   ]wk.w.@...j.P*..
0080 - b4 62 9d 16 99 d2 ce da-ab 1f 30 0d 91 9f f5 3f   .b........0....?
0090 - 5f bc 3a 9d 5c 01 6b 9a-8f 6d 6a 00 15 45 43 a5   _.:.\.k..mj..EC.
00a0 - 52 15 72 f6 9d d5 07 38-ed 47 ed dc ff 3f f5 81   R.r....8.G...?..
00b0 - 5e e0 58 23 61 45 90 b8-0b ed 6c 92 cb 31 7e fd   ^.X#aE....l..1~.
00c0 - 1f 56 67 c3 06 b0 4c e2-a3 84 1a 45 24 6c d5 b8   .Vg...L....E$l..
00d0 - e8 6e fb 38 7b 0c 65 6a-7a d6 83 8b bb fb 3f fc   .n.8{.ejz.....?.
00e0 - a2 7f 02 e4 95 99 1e 1c-f5 5a fc 55 9f 28 77 9d   .........Z.U.(w.
00f0 - 36 4a ff 17 bf 8a fc 66-81 e9 10 1f 84 a4 99 b6   6J.....f........
ok 1 - test_loaded_provider
*/
