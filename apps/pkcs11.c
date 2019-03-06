/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
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

typedef struct PKCS11_CTX_st {
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    char *module_path;
} PKCS11_CTX;

CK_RV pkcs11_initialize(const char *library_path);
void pkcs11_finalize(void);
int pkcs11_start_session(PKCS11_CTX *ctx);
void pkcs11_end_session(CK_SESSION_HANDLE session);
int pkcs11_get_slot(PKCS11_CTX *ctx);
void PKCS11_trace(char *format, ...);
CK_RV pkcs11_load_functions(const char *library_path);
CK_FUNCTION_LIST *pkcs11_funcs;
char *module = NULL;

typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_PUBKEYS, OPT_MODULE
} OPTION_CHOICE;

const OPTIONS pkcs11_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options]\n"},
    {"pubkeys", OPT_PUBKEYS, '-', "list public keys"},
    {"module", OPT_MODULE, 's', "PKCS#11 module"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {NULL}
};

int pkcs11_main(int argc, char **argv)
{
    OPTION_CHOICE o;
    char *prog;
    int ret = 1;
    CK_RV rv;
    CK_BYTE attr_id[2];
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE tmpl[2];
    CK_OBJECT_HANDLE akey[255];
    CK_ULONG ulObj = 1;
    int i;

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_ID;
    tmpl[1].pValue = &attr_id;
    tmpl[1].ulValueLen = sizeof(attr_id);

    prog = opt_init(argc, argv, pkcs11_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_PUBKEYS:
            /* nothing now */
        case OPT_MODULE:
            module = opt_arg();
            break;
        case OPT_HELP:
            opt_help(pkcs11_options);
            ret = 0;
            goto end;
        }
    }

    if (module == NULL) {
        BIO_printf(bio_err, "Module is mandatory.\n");
        goto end;
    }

    ret = 0;
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    ctx->module_path = module;
    ctx->slotid = 0;

    rv = pkcs11_initialize(ctx->module_path);
    if (rv != CKR_OK)
        goto end;
    if (!pkcs11_get_slot(ctx))
        goto end;
    if (!pkcs11_start_session(ctx))
        goto end;

    rv = pkcs11_funcs->C_FindObjectsInit(ctx->session, tmpl, 1);

    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_FindObjectsInit: Error = 0x%.8lX\n", rv);
        goto end;
    }

    rv = pkcs11_funcs->C_FindObjects(ctx->session, akey,
                                     OSSL_NELEM(akey), &ulObj);
    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_FindObjects: Error = 0x%.8lX\n", rv);
        goto end;
    }

    for (i = 0; i < ulObj; i++) {
         unsigned int j, len;
         CK_BYTE label[256];
         CK_BYTE id[255];
         CK_ATTRIBUTE template[2];

         template[0].type = CKA_LABEL;
         template[0].pValue = &label;
         template[0].ulValueLen = sizeof(label) - 1;
         template[1].type = CKA_ID;
         template[1].pValue = &id;
         template[1].ulValueLen = sizeof(id);

         memset(label, 0, sizeof(label));
         memset(id, 0, sizeof(id));

         rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, akey[i],
                                                template, OSSL_NELEM(template));
         if (rv != CKR_OK) {
             BIO_printf(bio_err, "C_GetAttributeValue[%u]: rv = 0x%.8lX\n", i, rv);
             goto end;
         }

         len = template[1].ulValueLen;
         BIO_printf(bio_out, "label: %s, id (hex): ",label);
         for (j = 0; j < (len < 254 ? len : 254); j++)
              BIO_printf(bio_out, "%02x",id[j]);
         BIO_printf(bio_out, ", id (ascii): ");
         for (j = 0; j < (len < 254 ? len : 254); j++)
              BIO_printf(bio_out, "%c",id[j]);
         BIO_printf(bio_out, "\n");
    }
    pkcs11_end_session(ctx->session);
    pkcs11_finalize();

 end:
    return ret;
}

/**
 * Load the PKCS#11 functions into global function list.
 * @param library_path
 * @return
 */
CK_RV pkcs11_load_functions(const char *library_path)
{
    CK_RV rv;
    DSO *pkcs11_dso = NULL;
    pkcs11_pFunc *pFunc;

    pkcs11_dso = DSO_load(NULL, library_path, NULL, 0);

    if (pkcs11_dso == NULL) {
        BIO_printf(bio_err, "C_GetFunctionList() not found in module %s\n");
        return CKR_GENERAL_ERROR;
    }

    pFunc = (pkcs11_pFunc *)DSO_bind_func(pkcs11_dso, "C_GetFunctionList");

    if (pFunc == NULL) {
        BIO_printf(bio_err, "C_GetFunctionList() not found in module %s\n",
                   library_path);
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
        BIO_printf(bio_err, "Getting PKCS11 function list failed, \
                   error: %#08X\n", rv);
        return rv;
    }

    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_Initialize failed, error: %#08X\n", rv);
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
    CK_SLOT_ID_PTR slotList;
    unsigned int i;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, NULL, &slotCount);

    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_GetSlotList failed, error: %#08X\n", rv);
        goto err;
    }

    if (slotCount == 0) {
        BIO_printf(bio_err, "Slot not found\n");
        goto err;
    }

    slotList = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);

    if (slotList == NULL) {
        BIO_printf(bio_err, "Malloc failure\n");
        goto err;
    }

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_GetSlotList failed, error: %#08X\n", rv);
        OPENSSL_free(slotList);
        goto err;
    }

    slotId = slotList[0]; /* Default value if slot not set*/
    for (i = 1; i < slotCount; i++) {
        if (ctx->slotid == slotList[i]) slotId = slotList[i];
    }

    ctx->slotid = slotId;
    OPENSSL_free(slotList);
    return 1;

 err:
    return 0;
}

int pkcs11_start_session(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    rv = pkcs11_funcs->C_OpenSession(ctx->slotid, CKF_SERIAL_SESSION, NULL,
                                     NULL, &session);
    if (rv != CKR_OK) {
        BIO_printf(bio_err, "C_OpenSession failed, error: %#08X\n", rv);
        return 0;
    }
    ctx->session = session;
    return 1;
}

void pkcs11_end_session(CK_SESSION_HANDLE session)
{
    pkcs11_funcs->C_CloseSession(session);
}
