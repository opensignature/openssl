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
static int pkcs11_get_key(OSSL_STORE_LOADER_CTX *store_ctx,
                          CK_OBJECT_HANDLE obj);
static int pkcs11_get_cert(OSSL_STORE_LOADER_CTX *store_ctx,
                           CK_OBJECT_HANDLE obj);
static int RSA_encode_pkcs1(unsigned char **out, int *out_len, int type,
                            const unsigned char *m, unsigned int m_len);
static int pkcs11_parse_items(PKCS11_CTX *ctx, const char *uri);
static int pkcs11_parse(PKCS11_CTX *ctx, const char *path, int store);
static char pkcs11_hex_int(char nib1, char nib2);
static int pkcs11_ishex(char *hex);
static char* pkcs11_hex2a(char *hex);
static void pkcs11_ctx_free(PKCS11_CTX *ctx);
static int pkcs11_rsa_free(RSA *rsa);
static RSA_METHOD *pkcs11_rsa = NULL;

/* store stuff */
static const char pkcs11_scheme[] = "pkcs11";
static OSSL_STORE_LOADER_CTX* pkcs11_store_open(
    const OSSL_STORE_LOADER *loader, const char *uri,
    const UI_METHOD *ui_method, void *ui_data);
static OSSL_STORE_INFO* pkcs11_store_load(OSSL_STORE_LOADER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data);
static int pkcs11_store_eof(OSSL_STORE_LOADER_CTX *ctx);
static int pkcs11_store_close(OSSL_STORE_LOADER_CTX *ctx);
static int pkcs11_store_error(OSSL_STORE_LOADER_CTX *ctx);
static OSSL_STORE_LOADER_CTX* OSSL_STORE_LOADER_CTX_new(void);
static void OSSL_STORE_LOADER_CTX_free(OSSL_STORE_LOADER_CTX* ctx);
static OSSL_STORE_INFO* pkcs11_store_load_cert(OSSL_STORE_LOADER_CTX *ctx,
                                               const UI_METHOD *ui_method,
                                               void *ui_data);
static OSSL_STORE_INFO* pkcs11_store_load_key(OSSL_STORE_LOADER_CTX *ctx,
                                              const UI_METHOD *ui_method,
                                              void *ui_data);
int rsa_pkcs11_idx = -1;

int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM sign_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_SESSION_HANDLE session = 0;
    unsigned char *tmps = NULL;
    int encoded_len = 0;
    const unsigned char *encoded = NULL;
    CK_OBJECT_HANDLE key = 0;

    /* TODO
    ctx = pkcs11_get_ctx(rsa);
    */

    if (!ctx->session) {
        return RSA_meth_get_sign(RSA_PKCS1_OpenSSL())
            (alg, md, md_len, sigret, siglen, rsa);
    }

    session = ctx->session;

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
    key = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa, rsa_pkcs11_idx);

    rv = pkcs11_funcs->C_SignInit(session, &sign_mechanism, key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);
    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    /* Sign */
    rv = pkcs11_funcs->C_Sign(session, (CK_BYTE *) encoded, encoded_len,
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
                        unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM enc_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = 0;
    int useSign = 0;

    /* TODO
    ctx = pkcs11_get_ctx(rsa);
    */

    if (!ctx->session) {
        return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
            (flen, from, to, rsa, padding);
    }

    session = ctx->session;

    num = RSA_size(rsa);

    enc_mechanism.mechanism = CKM_RSA_PKCS;
    CRYPTO_THREAD_write_lock(ctx->lock);

    key = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa, rsa_pkcs11_idx);
    rv = pkcs11_funcs->C_EncryptInit(session, &enc_mechanism, key);

    if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        PKCS11_trace("C_EncryptInit failed try SignInit, error: %#08X\n", rv);
        rv = pkcs11_funcs->C_SignInit(session, &enc_mechanism, key);

        if (rv != CKR_OK) {
            PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_INIT_FAILED);
            goto err;
        }
        useSign = 1;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    if (!useSign) {
        /* Encrypt */
        rv = pkcs11_funcs->C_Encrypt(session, (CK_BYTE *) from,
                                     flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Encrypt failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_ENCRYPT_FAILED);
            goto err;
        }
    } else {
        /* Sign */
        rv = pkcs11_funcs->C_Sign(session, (CK_BYTE *) from,
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

EVP_PKEY *pkcs11_load_pkey(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                           CK_OBJECT_HANDLE key)
{
    EVP_PKEY *k = NULL;
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

    k = EVP_PKEY_new();
    if (k == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    RSA_set_ex_data(rsa, rsa_pkcs11_idx, (char *) (CK_OBJECT_HANDLE) key);
    RSA_set0_key(rsa,
                 BN_bin2bn(rsa_attributes[0].pValue,
                           rsa_attributes[0].ulValueLen, NULL),
                 BN_bin2bn(rsa_attributes[1].pValue,
                           rsa_attributes[1].ulValueLen, NULL),
                 NULL);

    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
    EVP_PKEY_assign_RSA(k, rsa);
    rsa = NULL;

    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    ctx->session = session;
    return k;

 err:
    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    return NULL;
}

int pkcs11_search_next_ids(OSSL_STORE_LOADER_CTX *ctx, char **name,
                           char **description)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key;
    CK_ULONG ulObj = 1;
    unsigned int i;
    CK_ATTRIBUTE template[3];
    CK_BYTE_PTR id;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_CLASS key_class;

    session = ctx->session;
    rv = pkcs11_funcs->C_FindObjects(session, &key,
                                     1, &ulObj);

    if (rv != CKR_OK || ulObj == 0) {
        *name = NULL;
        *description = NULL;
        /* return eof */
        return 1;
    }

    template[0].type = CKA_CLASS;
    template[0].pValue = &key_class;
    template[0].ulValueLen = sizeof(key_class);
    template[1].type = CKA_LABEL;
    template[1].pValue = NULL;
    template[1].ulValueLen = 0;
    template[2].type = CKA_ID;
    template[2].pValue = NULL;
    template[2].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        *name = NULL;
        *description = NULL;
        /* return no eof, search next id */
        return 0;
    }

    template[1].pValue = OPENSSL_malloc(template[1].ulValueLen);

    id = (CK_BYTE_PTR) OPENSSL_malloc(template[2].ulValueLen);
    template[2].pValue = id;

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    *name = template[1].pValue;
    *(*name + template[1].ulValueLen) = '\0';

    *description = OPENSSL_malloc(template[2].ulValueLen * 3 + 23);

    if (key_class == CKO_CERTIFICATE)
        strncpy(*description, "Certificate ID: ", 16);
    else if (key_class == CKO_PUBLIC_KEY)
        strncpy(*description, "Public Key  ID: ", 16);
    else if (key_class == CKO_PRIVATE_KEY)
        strncpy(*description, "Private Key ID: ", 16);
    else 
        strncpy(*description, "Data        ID: ", 16);

    for (i=0; i < template[2].ulValueLen; i++)
          *(*description + i + 16) = id[i];

    *(*description + template[2].ulValueLen + 16) = '\0';
    strncat(*description, " hex: ", 6);

    for (i=0; i < template[2].ulValueLen; i++) {
          *(*description + 22 + template[2].ulValueLen + (i*2)) = \
           "0123456789abcdef"[id[i] >> 4];
          *(*description + 23 + template[2].ulValueLen + (i*2)) = \
           "0123456789abcdef"[id[i] % 16];
    }
    *(*description + 22 + (template[2].ulValueLen * 3)) = '\0';
    return 0;

 end:
    return 1;
}

int pkcs11_search_next_object(OSSL_STORE_LOADER_CTX *ctx,
                              CK_OBJECT_CLASS *class)
{
    CK_RV rv;
    CK_ATTRIBUTE template[1];
    CK_OBJECT_HANDLE obj;
    CK_ULONG nObj = 0;
    CK_OBJECT_CLASS key_class;
    int ret = 0;

    template[0].type = CKA_CLASS;
    template[0].pValue = &key_class;
    template[0].ulValueLen = sizeof(key_class);

    rv = pkcs11_funcs->C_FindObjects(ctx->session, &obj,
                                     1, &nObj);
    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects: Error = 0x%.8lX\n", rv);
        goto end;
    }

    if (nObj == 0)
        return 1;

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, obj,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }
    if (key_class == CKO_CERTIFICATE)
        ret = pkcs11_get_cert(ctx, obj);
    else if (key_class == CKO_PUBLIC_KEY)
        ret = pkcs11_get_key(ctx, obj);

    *class = key_class;
    return ret;
 end:
    return 1;
}

static int pkcs11_get_cert(OSSL_STORE_LOADER_CTX *store_ctx,
                           CK_OBJECT_HANDLE obj)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE tmpl_cert[2];

    tmpl_cert[0].type = CKA_CLASS;
    tmpl_cert[0].pValue = &key_class;
    tmpl_cert[0].ulValueLen = sizeof(key_class);
    tmpl_cert[1].type = CKA_VALUE;
    tmpl_cert[1].pValue = NULL;
    tmpl_cert[1].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_cert,
                                           OSSL_NELEM(tmpl_cert));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    tmpl_cert[1].pValue = OPENSSL_malloc(tmpl_cert[1].ulValueLen);

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_cert,
                                           OSSL_NELEM(tmpl_cert));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    if (tmpl_cert[1].ulValueLen > 0) {
        store_ctx->cert = tmpl_cert[1].pValue;
        store_ctx->certlen = tmpl_cert[1].ulValueLen;
        return 0;
    } else {
        PKCS11_trace("Certificate is empty\n");
        OPENSSL_free(tmpl_cert[1].pValue);
    }

 end:
    return 1;
}

static int pkcs11_get_key(OSSL_STORE_LOADER_CTX *store_ctx,
                         CK_OBJECT_HANDLE obj)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE tmpl_key[3];
    CK_BYTE_PTR pMod, pExp;
    EVP_PKEY* pRsaKey = NULL;
    RSA* rsa;

    tmpl_key[0].type = CKA_CLASS;
    tmpl_key[0].pValue = &key_class;
    tmpl_key[0].ulValueLen = sizeof(key_class);
    tmpl_key[1].type = CKA_MODULUS;
    tmpl_key[1].pValue = NULL;
    tmpl_key[1].ulValueLen = 0;
    tmpl_key[2].type = CKA_PUBLIC_EXPONENT;
    tmpl_key[2].pValue = NULL;
    tmpl_key[2].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_key,
                                           OSSL_NELEM(tmpl_key));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    pMod = (CK_BYTE_PTR) OPENSSL_malloc(tmpl_key[1].ulValueLen);
    tmpl_key[1].pValue = pMod;

    pExp = (CK_BYTE_PTR) OPENSSL_malloc(tmpl_key[2].ulValueLen);
    tmpl_key[2].pValue = pExp;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_key,
                                           OSSL_NELEM(tmpl_key));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    pRsaKey = EVP_PKEY_new();
    if (pRsaKey == NULL)
        goto end;

    rsa = RSA_new();
    RSA_set0_key(rsa,
                 BN_bin2bn(tmpl_key[1].pValue,
                           tmpl_key[1].ulValueLen, NULL),
                 BN_bin2bn(tmpl_key[2].pValue,
                           tmpl_key[2].ulValueLen, NULL),
                 NULL);

    EVP_PKEY_set1_RSA(pRsaKey, rsa);

    if (pRsaKey != NULL) {
        store_ctx->key = pRsaKey;
        return 0;
    } else {
        PKCS11_trace("Public Key is empty\n");
        OPENSSL_free(pMod);
        OPENSSL_free(pExp);
    }

 end:
    return 1;
}

int pkcs11_search_start(OSSL_STORE_LOADER_CTX *store_ctx,
                        PKCS11_CTX *pkcs11_ctx)
{
    CK_RV rv;
    CK_ATTRIBUTE tmpl[2];
    CK_SESSION_HANDLE session;
    CK_OBJECT_CLASS key_class;
    int idx = 0;

    session = store_ctx->session;

    if (pkcs11_ctx->type != NULL) {
        if (strncmp(pkcs11_ctx->type, "public", 6) == 0)
           key_class = CKO_PUBLIC_KEY;
        else if (strncmp(pkcs11_ctx->type, "cert", 4) == 0)
           key_class = CKO_CERTIFICATE;
        else if (strncmp(pkcs11_ctx->type, "private", 7) == 0)
           key_class = CKO_PRIVATE_KEY;
        else
           pkcs11_ctx->type = NULL;
    }

    if (pkcs11_ctx->type != NULL) {
        tmpl[0].type = CKA_CLASS;
        tmpl[0].pValue = &key_class;
        tmpl[0].ulValueLen = sizeof(key_class);
    }

    if (pkcs11_ctx->id != NULL) {
        idx++;
        tmpl[idx].type = CKA_ID;
        tmpl[idx].pValue = pkcs11_ctx->id;
        tmpl[idx].ulValueLen = (CK_ULONG)strlen((char *)pkcs11_ctx->id);
    } else if (pkcs11_ctx->label != NULL) {
        idx++;
        tmpl[idx].type = CKA_LABEL;
        tmpl[idx].pValue = pkcs11_ctx->label;
        tmpl[idx].ulValueLen = (CK_ULONG)strlen((char *)pkcs11_ctx->label);
    }

    if (pkcs11_ctx->pin != NULL) {
        if (!pkcs11_login(session, pkcs11_ctx, CKU_USER))
            goto err;
    }

    if (pkcs11_ctx->type == NULL && pkcs11_ctx->id == NULL
        && pkcs11_ctx->label == NULL)
        rv = pkcs11_funcs->C_FindObjectsInit(session, NULL_PTR, 0);
    else
        rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl, idx + 1);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit: Error = 0x%.8lX\n", rv);
        goto err;
    }
    return 1;
 err:
    return 0;
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

static char pkcs11_hex_int(char nib1, char nib2)
{
    int ret = (nib1-(nib1 <= 57 ? 48 : (nib1 < 97 ? 55 : 87)))*16;
    ret += (nib2-(nib2 <= 57 ? 48 : (nib2 < 97 ? 55 : 87)));
    return ret;
}

static char* pkcs11_hex2a(char *hex)
{
    int vlen, j = 0, i, ishex;
    char *hex2a;

    hex2a = OPENSSL_malloc(strlen(hex) + 1);

    if (hex2a == NULL)
        return NULL;

    vlen = strlen(hex);
    ishex = pkcs11_ishex(hex);
    for (i = 0; i < vlen; i++) {
        if ((*(hex+i) == '%' && i < (vlen-2)) || ishex) {
            *(hex2a+j) = pkcs11_hex_int(*(hex+i+1-ishex), *(hex+i+2-ishex));
            i += (2-ishex);
        } else {
            *(hex2a+j) = *(hex+i);
        }
        j++;
    }
    *(hex2a+j) = '\0';
    return hex2a;
}

static int pkcs11_ishex(char *hex)
{
    size_t i, len, h = 0;

    len = strlen(hex);
    for (i = 0; i < len; i++) {
        if ((*(hex+i) >= '0' && *(hex+i) <= '9')
            || (*(hex+i) >= 'a' && *(hex+i) <= 'f')
            || (*(hex+i) >= 'A' && *(hex+i) <= 'F'))
            h++;
        else
            return 0;
    }
    if (!(h % 2))
        return 1;
    return 0;
}

static int pkcs11_parse_items(PKCS11_CTX *ctx, const char *uri)
{
    char *p, *q, *tmpstr;
    int len = 0;

    p = q = (char *) uri;
    len = strlen(uri);

    while (q - uri <= len) {
        if (*q != ';' && *q != '\0') {
            q++;
            continue;
        }
        if (p != q) {
            /* found */
            *q = '\0';
            if (strncmp(p, "pin-value=", 10) == 0 && ctx->pin == NULL) {
                p += 10;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->pin = (CK_BYTE *) tmpstr;
            } else if (strncmp(p, "object=", 7) == 0 && ctx->label == NULL) {
                p += 7;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->label = (CK_BYTE *) pkcs11_hex2a(tmpstr);
            } else if (strncmp(p, "id=", 3) == 0 && ctx->id == NULL) {
                p += 3;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->id = (CK_BYTE *) pkcs11_hex2a(tmpstr);
            } else if (strncmp(p, "type=", 5) == 0 && ctx->type == NULL) {
                p += 5;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->type = tmpstr;
            } else if (strncmp(p, "module-path=", 12) == 0
                && ctx->module_path == NULL) {
                p += 12;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->module_path = tmpstr;
            } else if (strncmp(p, "slot-id=", 8) == 0 && ctx->slotid == 0) {
                p += 8;
                tmpstr = OPENSSL_strdup(p);
                if (tmpstr == NULL)
                    goto memerr;
                ctx->slotid = (CK_SLOT_ID) atoi(tmpstr);
            }
        }
        p = ++q;
    }
    return 1;

 memerr:
    PKCS11err(PKCS11_F_PKCS11_PARSE_ITEMS, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int pkcs11_get_console_pin(char **pin)
{
#ifndef OPENSSL_NO_UI_CONSOLE
    int i;
    const int buflen = 512;
    char *strbuf = OPENSSL_malloc(buflen);

    if (strbuf == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_CONSOLE_PIN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (;;) {
        char prompt[200];
        BIO_snprintf(prompt, sizeof(prompt), "Enter PIN: ");
        strbuf[0] = '\0';
        i = EVP_read_pw_string((char *)strbuf, buflen, prompt, 0);
        if (i == 0) {
            if (strbuf[0] == '\0') {
                goto err;
            }
            *pin = strbuf;
            return 1;
        }
        if (i < 0) {
            PKCS11_trace("bad password read\n");
            goto err;
        }
    }

 err:
    OPENSSL_free(strbuf);
#endif

    return 0;
}

static int pkcs11_parse(PKCS11_CTX *ctx, const char *path, int store)
{
    char *pin = NULL;
    char *id = NULL;

    if (path == NULL) {
        PKCS11_trace("URI is empty\n");
        return 0;
    }

    if (strncmp(path, "pkcs11:", 7) == 0) {
        path += 7;
        pkcs11_parse_items(ctx, path);

        if (ctx->id == NULL && ctx->label == NULL && !store) {
            PKCS11_trace("ID and OBJECT are null\n");
            goto err;
         }
    } else {
        id = OPENSSL_strdup(path);
        if (id == NULL) {
            PKCS11err(PKCS11_F_PKCS11_PARSE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        id = pkcs11_hex2a(id);
    }

    if (ctx->module_path == NULL) {
            PKCS11_trace("Module path is null\n");
            goto err;
    }

    if (ctx->pin == NULL && (!store || (store
        && ctx->type != NULL && strncmp(ctx->type, "private", 7) == 0))) {
        if (!pkcs11_get_console_pin(&pin))
            goto err;
        ctx->pin = (CK_BYTE *) pin;
        if (ctx->pin == NULL) {
            PKCS11_trace("PIN is invalid\n");
            goto err;
        }
    }
    return 1;

 err:
    return 0;
}

static OSSL_STORE_LOADER_CTX* pkcs11_store_open(
    const OSSL_STORE_LOADER *loader, const char *uri,
    const UI_METHOD *ui_method, void *ui_data)
{
    PKCS11_CTX *pkcs11_ctx;
    OSSL_STORE_LOADER_CTX *store_ctx = NULL;
    CK_SESSION_HANDLE session = 0;

    store_ctx = OSSL_STORE_LOADER_CTX_new();

    /* TODO
    pkcs11_ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    */

    if (pkcs11_ctx == NULL)
        return NULL;

    if (!pkcs11_parse(pkcs11_ctx, uri, 1))
        return NULL;

    if (pkcs11_initialize(pkcs11_ctx->module_path) != CKR_OK)
        return NULL;

    if (!pkcs11_get_slot(pkcs11_ctx))
        return NULL;

    if (!pkcs11_start_session(pkcs11_ctx, &session))
        return NULL;

    /* NEW store-ctx->session, not a copy of pkcs11_ctx->session */
    store_ctx->session = session;

    if (!pkcs11_search_start(store_ctx, pkcs11_ctx))
        return NULL;

    if (pkcs11_ctx->label == NULL && pkcs11_ctx->id == NULL)
        store_ctx->listflag = 1;    /* we want names */

    return store_ctx;
}

static OSSL_STORE_INFO* pkcs11_store_load(OSSL_STORE_LOADER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data)
{
    OSSL_STORE_INFO *ret = NULL;

    if (ctx->listflag) {
        char *name;
        char *description;

        ctx->eof = pkcs11_search_next_ids(ctx, &name, &description);
        if (!ctx->eof) {
            ret = OSSL_STORE_INFO_new_NAME(name);
            OSSL_STORE_INFO_set0_NAME_description(ret, description);
        }
    } else {
        CK_OBJECT_CLASS class;

        ctx->eof = pkcs11_search_next_object(ctx, &class);
        if (!ctx->eof) {
            if (class == CKO_CERTIFICATE)
                ret = pkcs11_store_load_cert(ctx, ui_method, ui_data);
            if (class == CKO_PUBLIC_KEY)
                ret = pkcs11_store_load_key(ctx, ui_method, ui_data);
        }
    }
    return ret;
}

static int pkcs11_store_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    return ctx->eof;
}

static int pkcs11_store_close(OSSL_STORE_LOADER_CTX *ctx)
{
    pkcs11_end_session(ctx->session);
    pkcs11_finalize();
    OSSL_STORE_LOADER_CTX_free(ctx);
    return 1;
}

static int pkcs11_store_error(OSSL_STORE_LOADER_CTX *ctx)
{
/* TODO */
    return 0;
}

static OSSL_STORE_LOADER_CTX* OSSL_STORE_LOADER_CTX_new(void)
{
    OSSL_STORE_LOADER_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->error = 0;
    ctx->listflag = 0;
    ctx->eof = 0;
    ctx->cert = NULL;
    ctx->session = 0;
    return ctx;
}

static void OSSL_STORE_LOADER_CTX_free(OSSL_STORE_LOADER_CTX* ctx)
{
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx);
}

static OSSL_STORE_INFO* pkcs11_store_load_cert(OSSL_STORE_LOADER_CTX *ctx,
                                               const UI_METHOD *ui_method,
                                               void *ui_data)
{
    X509 *x = NULL;

    x = d2i_X509(NULL, &ctx->cert, ctx->certlen);
    return OSSL_STORE_INFO_new_CERT(x);
}

static OSSL_STORE_INFO* pkcs11_store_load_key(OSSL_STORE_LOADER_CTX *ctx,
                                               const UI_METHOD *ui_method,
                                               void *ui_data)
{
    return OSSL_STORE_INFO_new_PKEY(ctx->key);
}

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
