/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <internal/dso.h>
#include <internal/nelem.h>

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

#define PKCS11_CMD_MODULE_PATH            ENGINE_CMD_BASE
#define PKCS11_CMD_PIN                    (ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] = {
    {PKCS11_CMD_MODULE_PATH,
     "MODULE_PATH",
     "Module path",
     ENGINE_CMD_FLAG_STRING},
    {PKCS11_CMD_PIN,
     "PIN",
     "PIN",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

struct X509_sig_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};

typedef struct PKCS11_CTX_st {
    CK_BYTE *id;
    CK_BYTE *label;
    CK_BYTE *pin;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    char *module_path;
    CRYPTO_RWLOCK *lock;
} PKCS11_CTX;

CK_RV pkcs11_initialize(const char *library_path);
int pkcs11_start_session(PKCS11_CTX *ctx);
int pkcs11_login(PKCS11_CTX *ctx, CK_USER_TYPE userType);
EVP_PKEY *pkcs11_load_pkey(PKCS11_CTX *ctx);
int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa);
int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
int pkcs11_get_slot(PKCS11_CTX *ctx);
int pkcs11_find_private_key(PKCS11_CTX *ctx);
void PKCS11_trace(char *format, ...);
int pkcs11_encode_pkcs1(unsigned char **out, int *out_len, int type,
                        const unsigned char *m, unsigned int m_len);
PKCS11_CTX *pkcs11_get_cms(const RSA *rsa);
