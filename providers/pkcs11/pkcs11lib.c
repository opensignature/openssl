/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "pkcs11prov.h"
#include "pkcs11_err.c"
#include <internal/dso.h>
#include <internal/nelem.h>
#include <openssl/bn.h>

static CK_RV pkcs11_load_functions(const char *library_path);
static CK_FUNCTION_LIST *pkcs11_funcs;
static int RSA_encode_pkcs1(unsigned char **out, int *out_len, int type,
                            const unsigned char *m, unsigned int m_len);
/*
static void pkcs11_ctx_free(PKCS11_CTX *ctx);
static int pkcs11_rsa_free(RSA *rsa);
*/

int rsa_pkcs11_idx = -1;

int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa, PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_ULONG num;
    CK_MECHANISM sign_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    unsigned char *tmps = NULL;
    int encoded_len = 0;
    const unsigned char *encoded = NULL;
    CK_OBJECT_HANDLE key = 0;

    num = RSA_size(rsa);

    if (!RSA_encode_pkcs1(&tmps, &encoded_len, alg, md, md_len))
        goto err;

    encoded = tmps;
    if ((unsigned int)encoded_len > (num - RSA_PKCS1_PADDING_SIZE)) {
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }

    sign_mechanism.mechanism = CKM_RSA_PKCS;

    key = pkcs11_find_private_key(ctx->session, ctx);
    rv = pkcs11_funcs->C_SignInit(ctx->session, &sign_mechanism, key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);
    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(ctx->session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    /* Sign */
    rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) encoded, encoded_len,
                              sigret, &num);

    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_FAILED);
        goto err;
    }
    *siglen = num;
    return 1;

 err:
    return 0;
}

int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding, PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_ULONG num;
    CK_MECHANISM enc_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_OBJECT_HANDLE key = 0;
    int useSign = 0;

    num = RSA_size(rsa);

    enc_mechanism.mechanism = CKM_RSA_PKCS;
    CRYPTO_THREAD_write_lock(ctx->lock);

    key = pkcs11_find_private_key(ctx->session, ctx);

    rv = pkcs11_funcs->C_EncryptInit(ctx->session, &enc_mechanism, key);

    if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        PKCS11_trace("C_EncryptInit failed try SignInit, error: %#08X\n", rv);
        rv = pkcs11_funcs->C_SignInit(ctx->session, &enc_mechanism, key);

        if (rv != CKR_OK) {
            PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_INIT_FAILED);
            goto err;
        }
        useSign = 1;
    }

    if (rv != CKR_OK) {
        PKCS11_trace("Init failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(ctx->session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    if (!useSign) {
        /* Encrypt */
        rv = pkcs11_funcs->C_Encrypt(ctx->session, (CK_BYTE *) from,
                                     flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Encrypt failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_ENCRYPT_FAILED);
            goto err;
        }
    } else {
        /* Sign */
        rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) from,
                                  flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_FAILED);
            goto err;
        }
    }

    CRYPTO_THREAD_unlock(ctx->lock);

    /* FIXME useless call */
    ERR_load_PKCS11_strings();
    ERR_unload_PKCS11_strings();

    return 1;

 err:
    return 0;
}

/**
 * Load the PKCS#11 functions into global function list.
 * @param library_path
 * @return
 */
static CK_RV pkcs11_load_functions(const char *library_path)
{
    CK_RV rv;
    DSO *pkcs11_dso = NULL;
    pkcs11_pFunc *pFunc;

    pkcs11_dso = DSO_load(NULL, library_path, NULL, 0);

    if (pkcs11_dso == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_LIBRARY_PATH_NOT_FOUND);
        return CKR_GENERAL_ERROR;
    }

    pFunc = (pkcs11_pFunc *)DSO_bind_func(pkcs11_dso, "C_GetFunctionList");

    if (pFunc == NULL) {
        PKCS11_trace("C_GetFunctionList() not found in module %s\n",
                     library_path);
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_GETFUNCTIONLIST_NOT_FOUND);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&pkcs11_funcs);
    return rv;
}

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11.
 * @param library_path
 * @return
 */
CK_RV pkcs11_initialize(const char *library_path)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args = { 0 };

    if (library_path == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        PKCS11_trace("Getting PKCS11 function list failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE,
                  PKCS11_R_GETTING_FUNCTION_LIST_FAILED);
        return rv;
    }

    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Initialize failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_INITIALIZE_FAILED);
        return rv;
    }

    return CKR_OK;
}

void pkcs11_finalize(void)
{
    pkcs11_funcs->C_Finalize(NULL);
}

int pkcs11_get_slot(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_ULONG slotCount;
    CK_SLOT_ID slotId;
    CK_SLOT_ID_PTR slotList = NULL;
    unsigned int i;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, NULL, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    if (slotCount == 0) {
        PKCS11_trace("C_GetSlotList failed, slotCount = 0\n");
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_SLOT_NOT_FOUND);
        goto err;
    }

    slotList = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);

    if (slotList == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        OPENSSL_free(slotList);
        goto err;
    }

    slotId = slotList[0]; /* Default value if slot not set*/
    for (i = 1; i < slotCount; i++) {
        if (ctx->slotid == slotList[i])
            slotId = slotList[i];
    }

    ctx->slotid = slotId;
    OPENSSL_free(slotList);
    return 1;

 err:
    return 0;
}

int pkcs11_start_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE *session)
{
    CK_RV rv;
    CK_SESSION_HANDLE s = 0;

    rv = pkcs11_funcs->C_OpenSession(ctx->slotid, CKF_SERIAL_SESSION, NULL,
                                     NULL, &s);
    if (rv != CKR_OK) {
        PKCS11_trace("C_OpenSession failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_START_SESSION,
                  PKCS11_R_OPEN_SESSION_ERROR);
        return 0;
    }
    *session = s;
    return 1;
}

int pkcs11_login(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                 CK_USER_TYPE userType)
{
    /* Binary pins not supported */
    CK_RV rv;
    if (ctx->pin != NULL) {
        rv = pkcs11_funcs->C_Login(session, userType, ctx->pin,
                                   (CK_ULONG)strlen((char *)ctx->pin));
        if (rv == CKR_GENERAL_ERROR && userType == CKU_CONTEXT_SPECIFIC) {
            rv = pkcs11_funcs->C_Login(session, CKU_USER, ctx->pin,
                                       (CK_ULONG)strlen((char *)ctx->pin));
        }
        if (rv != CKR_OK) {
            PKCS11_trace("C_Login failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_LOGIN, PKCS11_R_LOGIN_FAILED);
            return 0;
        }
    } else {
        PKCS11_trace("C_Login failed, PIN empty\n");
        return 0;
    }
    return 1;
}

int pkcs11_logout(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = pkcs11_funcs->C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_OK) {
        PKCS11_trace("C_Logout failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_R_LOGOUT_FAILED);
        return 0;
    }
    return 1;
}

void pkcs11_end_session(CK_SESSION_HANDLE session)
{
    pkcs11_funcs->C_CloseSession(session);
}

CK_OBJECT_HANDLE pkcs11_find_private_key(CK_SESSION_HANDLE session,
                                         PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    unsigned long count;
    CK_ATTRIBUTE tmpl[3];
    CK_OBJECT_HANDLE key = 0;

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_KEY_TYPE;
    tmpl[1].pValue = &key_type;
    tmpl[1].ulValueLen = sizeof(key_type);

    if (ctx->id != NULL) {
        tmpl[2].type = CKA_ID;
        tmpl[2].pValue = ctx->id;
        tmpl[2].ulValueLen = (CK_ULONG)strlen((char *)ctx->id);
    } else if (ctx->label != NULL) {
        tmpl[2].type = CKA_LABEL;
        tmpl[2].pValue = ctx->label;
        tmpl[2].ulValueLen = (CK_ULONG)strlen((char *)ctx->label);
    } else {
        PKCS11_trace("id and label empty\n");
    }

    rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl, OSSL_NELEM(tmpl));

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(session, &key, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjectsFinal(session);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsFinal failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FINAL_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           tmpl, OSSL_NELEM(tmpl));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    return key;

 err:
    return 0;
}

RSA *pkcs11_load_pkey(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                      CK_OBJECT_HANDLE key)
{
    CK_RV rv;
    CK_ATTRIBUTE rsa_attributes[2];
    RSA *rsa = NULL;

    rsa_attributes[0].type = CKA_MODULUS;
    rsa_attributes[0].pValue = NULL;
    rsa_attributes[0].ulValueLen = 0;
    rsa_attributes[1].type = CKA_PUBLIC_EXPONENT;
    rsa_attributes[1].pValue = NULL;
    rsa_attributes[1].ulValueLen = 0;
    rsa = RSA_new();

    if (rsa == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    if  (rsa_attributes[0].ulValueLen == 0
         || rsa_attributes[1].ulValueLen == 0)
        goto err;

    rsa_attributes[0].pValue = OPENSSL_malloc(rsa_attributes[0].ulValueLen);
    if (rsa_attributes[0].pValue == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rsa_attributes[1].pValue = OPENSSL_malloc(rsa_attributes[1].ulValueLen);
    if (rsa_attributes[1].pValue == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    RSA_set0_key(rsa,
                 BN_bin2bn(rsa_attributes[0].pValue,
                           rsa_attributes[0].ulValueLen, NULL),
                 BN_bin2bn(rsa_attributes[1].pValue,
                           rsa_attributes[1].ulValueLen, NULL),
                 NULL);

    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);

    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    ctx->session = session;
    return rsa;

 err:
    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    return NULL;
}

void PKCS11_trace(char *format, ...)
{
#ifdef DEBUG
# ifndef OPENSSL_NO_STDIO
    BIO *out;
    va_list args;

    out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (out == NULL) {
        PKCS11err(PKCS11_F_PKCS11_TRACE, PKCS11_R_FILE_OPEN_ERROR);
        return;
    }

    va_start(args, format);
    BIO_vprintf(out, format, args);
    va_end(args);
    BIO_free(out);
# endif
#endif
}

static int RSA_encode_pkcs1(unsigned char **out, int *out_len, int type,
                            const unsigned char *m, unsigned int m_len)
{
    X509_ALGOR algor;
    ASN1_TYPE parameter;
    ASN1_OCTET_STRING digest;
    uint8_t *der = NULL;
    int len;
    typedef struct PKCS11_sig_st {
        X509_ALGOR *algor;
        ASN1_OCTET_STRING *digest;
    } PKCS11_SIG;
    PKCS11_SIG sig;

    sig.algor = &algor;
    sig.algor->algorithm = OBJ_nid2obj(type);
    if (sig.algor->algorithm == NULL)
        return 0;
    if (OBJ_length(sig.algor->algorithm) == 0)
        return 0;

    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    sig.algor->parameter = &parameter;

    sig.digest = &digest;
    sig.digest->data = (unsigned char *)m;
    sig.digest->length = m_len;

    len = i2d_X509_SIG((X509_SIG *)&sig, &der);
    if (len < 0)
        return 0;

    *out = der;
    *out_len = len;
    return 1;
}
/*
static int pkcs11_rsa_free(RSA *rsa)
{
    RSA_set_ex_data(rsa, rsa_pkcs11_idx, 0);
    return 1;
}

static void pkcs11_ctx_free(PKCS11_CTX *ctx)
{
    PKCS11_trace("Calling pkcs11_ctx_free with %p\n", ctx);
    CRYPTO_THREAD_lock_free(ctx->lock);
    free(ctx->id);
    free(ctx->label);
}
*/
