/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define MAX 32
#define CK_PTR *

#ifdef _WIN32
# pragma pack(push, cryptoki, 1)
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
# define NULL_PTR 0
#endif

#include "pkcs11.h"

#ifdef _WIN32
# pragma pack(pop, cryptoki)
#endif

typedef struct PKCS11_CTX_st {
    CK_BYTE *id;
    CK_BYTE *label;
    CK_BYTE *pin;
    char *type;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    char *module_path;
    CRYPTO_RWLOCK *lock;
} PKCS11_CTX;

struct ossl_store_loader_ctx_st {
    int error;
    int eof;
    int listflag;
    size_t certlen;
    const unsigned char *cert;
    EVP_PKEY *key;
    CK_SESSION_HANDLE session;
};

CK_RV pkcs11_initialize(const char *library_path);
int pkcs11_start_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE *session);
int pkcs11_login(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                 CK_USER_TYPE userType);
EVP_PKEY *pkcs11_load_pkey(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                           CK_OBJECT_HANDLE key);
int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa);
int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
int pkcs11_get_slot(PKCS11_CTX *ctx);
CK_OBJECT_HANDLE pkcs11_find_private_key(CK_SESSION_HANDLE session,
                                         PKCS11_CTX *ctx);
void PKCS11_trace(char *format, ...);
PKCS11_CTX *pkcs11_get_ctx(const RSA *rsa);
int pkcs11_search_next_ids(OSSL_STORE_LOADER_CTX *ctx, char **name,
                           char **description);
int pkcs11_search_next_object(OSSL_STORE_LOADER_CTX *ctx,
                              CK_OBJECT_CLASS *class);
int pkcs11_search_start(OSSL_STORE_LOADER_CTX *store_ctx,
                        PKCS11_CTX *pkcs11_ctx);
void pkcs11_finalize(void);
void pkcs11_end_session(CK_SESSION_HANDLE session);
int pkcs11_logout(CK_SESSION_HANDLE session);
typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);
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
static PKCS11_CTX *pkcs11_ctx_new(void);
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
