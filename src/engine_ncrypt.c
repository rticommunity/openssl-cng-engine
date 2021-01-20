/*
 * (c) 2020-2021 Copyright, Real-Time Innovations, Inc. (RTI)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define CMN_THIS_FILE "src/engine_ncrypt.c"

/* Implementation */
#include <stdbool.h>
#include "c_cmn.h"
#include "s_ncrypt.h"
#include "s_ncrypt_ec.h"
#include "s_ncrypt_err.h"
#include "s_ncrypt_loader.h"
#include "s_ncrypt_rsa.h"

#include <openssl/store.h>
#include <openssl/engine.h>

/* We depend on the following libraries */
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcrypto.lib")

const char *S_engine_id = "engine-ncrypt";
const char *S_engine_name = "CryptoAPI: Next Gen (CNG) NCrypt STORE Engine";

#define NCRYPT_CMD_DBG_LEVEL (ENGINE_CMD_BASE)

const ENGINE_CMD_DEFN ncrypt_cmd_defns[] = {
    {.cmd_num = NCRYPT_CMD_DBG_LEVEL,
     .cmd_name = "debug_level",
     .cmd_desc =
         "debug level (<0=nothing, 0=errors, 1=warnings, 2=api, 3+=trace)",
     .cmd_flags = ENGINE_CMD_FLAG_NUMERIC},
    /* Terminator */
    {0, NULL, NULL, 0}};

BOOL CALLBACK
new_index(PINIT_ONCE initOnce, PVOID index_ptr, /* int* */
          LPVOID *vptr /* not used */)
{
    BOOL result = FALSE;
    int index;

    CMN_DBG_ASSERT_NOT_NULL(index_ptr);

    CMN_UNUSED(initOnce);
    CMN_UNUSED(vptr);

    index = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (index == -1) {
        S_NCRYPT_osslerr(ENGINE_get_ex_new_index,
                         "Getting NCrypt engine ex index");
        goto done;
    }

    *((int *)index_ptr) = index;
    result = TRUE;

done:
    return result;
}

static bool
ncrypt_engine_index_get(int *index_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static int s_index;

    if (!InitOnceExecuteOnce(&s_once, new_index, &s_index, NULL)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winwarn(last_error, InitOnceExecuteOnce,
                         "RNG one-time initialization");
        goto done;
    }

    *index_out = s_index;
    result = true;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ncrypt_control(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(e);
    CMN_UNUSED(p);
    CMN_UNUSED(f);

    switch (cmd) {
    case NCRYPT_CMD_DBG_LEVEL:
#ifdef _DEBUG
        c_cmn_dbg_set_threshold(i);
#else
        CMN_UNUSED(i);
#endif
        break;
    default:
        CMN_DBG_ERROR("Control invoked with unknown cmd %d", cmd);
        goto done;
    }
    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_finish(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int ex_index;
    OSSL_STORE_LOADER *loader;

    CMN_DBG_PRECOND_NOT_NULL(engine);

    /* Finalize submodules */

    s_ncrypt_ec_finalize();
    s_ncrypt_rsa_finalize();

    if (!ncrypt_engine_index_get(&ex_index))
        goto done;
    loader = ENGINE_get_ex_data(engine, ex_index);
    if (loader == NULL) {
        S_NCRYPT_osslerr(ENGINE_get_ex_data, "Freeing engine");
        goto done;
    }
    s_ncrypt_loader_free(loader, engine);

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_destroy(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    CMN_UNUSED(engine);

    CMN_DBG_API_LEAVE;
    return 1;
}

/* Use the store to load a private key */
/* Store has been registered during initialization of the engine */
static EVP_PKEY *
cng_store_load_privkey(ENGINE *engine, const char *uri, UI_METHOD *ui_method,
                       void *callback_data)
{
    CMN_DBG_API_ENTER;

    EVP_PKEY *result = NULL;
    EVP_PKEY *key;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    CMN_UNUSED(engine);
    CMN_DBG_PRECOND_NOT_NULL(uri);

    ctx = OSSL_STORE_open(uri, ui_method, callback_data, NULL, NULL);
    if (ctx == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_open, "Loading private key");
        goto done;
    }

    /* We are only interested in private keys here */
    if (OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_expect, "Loading private key");
        goto done;
    }

    info = OSSL_STORE_load(ctx);
    if (info == NULL) {
        if (OSSL_STORE_error(ctx) == 1) {
            S_NCRYPT_osslerr(OSSL_STORE_error, "Loading erroneous private key");
            goto done;
        }
        if (OSSL_STORE_eof(ctx) == 1) {
            S_NCRYPT_osslerr(OSSL_STORE_eof,
                             "Loading private key from empty store");
            goto done;
        }
        /* We should never get here */
        CMN_DBG_ASSERT_NOT_NULL(info);
        goto done;
    }

    key = OSSL_STORE_INFO_get1_PKEY(info);
    if (key == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_INFO_get1_PKEY, "Loading private key");
        goto done;
    }

    result = key;

done:
    OSSL_STORE_INFO_free(info);
    OSSL_STORE_close(ctx);

    CMN_DBG_API_LEAVE;
    return result;
}

/* Use the store to load a public key */
/* Store has been registered during initialization of the engine */
static EVP_PKEY *
cng_store_load_pubkey(ENGINE *engine, const char *uri, UI_METHOD *ui_method,
                      void *callback_data)
{
    CMN_DBG_API_ENTER;

    EVP_PKEY *result = NULL;
    EVP_PKEY *key;
    X509 *cert;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    CMN_UNUSED(engine);
    CMN_DBG_PRECOND_NOT_NULL(uri);

    ctx = OSSL_STORE_open(uri, ui_method, callback_data, NULL, NULL);
    if (ctx == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_open, "Loading public key");
        goto done;
    }

    /* The public key will be determined from the certificate that
     * contains it */
    if (OSSL_STORE_expect(ctx, OSSL_STORE_INFO_CERT) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_expect, "Loading public key");
        goto done;
    }

    info = OSSL_STORE_load(ctx);
    if (info == NULL) {
        if (OSSL_STORE_error(ctx) == 1) {
            S_NCRYPT_osslerr(OSSL_STORE_error, "Loading erroneous public key");
            goto done;
        }
        if (OSSL_STORE_eof(ctx) == 1) {
            S_NCRYPT_osslerr(OSSL_STORE_eof,
                             "Loading public key from empty store");
            goto done;
        }
        /* We should never get here */
        CMN_DBG_ASSERT_NOT_NULL(info);
        goto done;
    }

    cert = OSSL_STORE_INFO_get0_CERT(info);
    if (cert == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_INFO_get0_CERT, "Loading public key");
        goto done;
    }

    key = X509_get_pubkey(cert);
    if (key == NULL) {
        S_NCRYPT_osslerr(X509_get_pubkey, "Loading public key");
        goto done;
    }

    result = key;

done:
    OSSL_STORE_INFO_free(info);
    OSSL_STORE_close(ctx);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_initialize(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int ex_index;
    OSSL_STORE_LOADER *loader;

    /* Initialize submodules */
    if (s_ncrypt_rsa_initialize() != 1)
        goto done;
    if (s_ncrypt_ec_initialize() != 1)
        goto done;

    if (ENGINE_set_flags(engine, ENGINE_FLAGS_NO_REGISTER_ALL) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_flags, "Initializing NCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that iplements the finalization. */
    if (ENGINE_set_finish_function(engine, ncrypt_finish) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_finish_function,
                         "Initializing NCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that iplements the destruction. */
    if (ENGINE_set_destroy_function(engine, ncrypt_destroy) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_destroy_function,
                         "Initializing NCrypt engine");
        goto done;
    }

    /* Initialize the error strings */
    if (ERR_load_SNCRYPT_strings() != 1) {
        /* Not fatal, just mention it */
        CMN_DBG_ERROR("Can not load NCrypt engine error strings");
    }

    /* Create and register a store loader for NCrypt */
    loader = s_ncrypt_loader_new(engine);
    if (loader == NULL)
        goto done;

    if (!ncrypt_engine_index_get(&ex_index))
        goto done;
    if (ENGINE_set_ex_data(engine, ex_index, loader) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_ex_data, "Initializing NCrypt engine");
        goto done;
    }

    /* Add engine key loader functions, will be loading from the store
         under the hood. */
    if (ENGINE_set_load_privkey_function(engine, cng_store_load_privkey) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_load_privkey_function,
                         "Initializing NCrypt engine");
        goto done;
    }

    if (ENGINE_set_load_pubkey_function(engine, cng_store_load_pubkey) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_load_pubkey_function,
                         "Initializing NCrypt engine");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Functions to implement standard dynamic loading behavior */
static int
ncrypt_store_bind_helper(ENGINE *engine, const char *engine_id)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    /* If engine_id is given, make sure it's the correct one */
    if ((engine_id != NULL) && (strcmp(engine_id, S_engine_id) != 0)) {
        CMN_DBG_ERROR("Can not bind engine \"%s\", only know \"%s\"", engine_id,
                      S_engine_id);
        goto done;
    }

    if (ENGINE_set_id(engine, S_engine_id) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_id, "NCrypt engine binding");
        goto done;
    }

    if (ENGINE_set_name(engine, S_engine_name) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_name, "NCrypt engine binding");
        goto done;
    }

    /* Set a pointer to a function that provides the list of commands. */
    if (ENGINE_set_cmd_defns(engine, ncrypt_cmd_defns) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_cmd_defns, "NCrypt engine binding");
        goto done;
    }

    /* Set a pointer to a function that implements the control. */
    if (ENGINE_set_ctrl_function(engine, ncrypt_control) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_ctrl_function, "NCrypt engine binding");
        goto done;
    }

#if OSSL_INITIALIZES_ENGINE
    /* Set the init function, where all methods will be bound */
    if (ENGINE_set_init_function(engine, ncrypt_initialize) != 1) {
        S_NCRYPT_osslerr(ENGINE_set_init_function, "NCrypt engine binding");
        goto done;
    }
#else
    /* OpenSSL tools do not properly invoke the initialize function,
       so let's do it here */
    if (ncrypt_initialize(engine) != 1)
        goto done;
#endif

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(ncrypt_store_bind_helper)

/* -------------------------------------------------- *
 * - External helper function for cert verification - *
 * -------------------------------------------------- */

const char *STORE_URI = "cert:/LocalMachine/My/";

OPENSSL_EXPORT
int
e_ncrypt_x509_verify_helper(X509_STORE_CTX *x509_store_ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int ctrl_result = 0;
    OSSL_STORE_CTX *ossl_store_ctx = NULL;

    /* Get context from OSSL_STORE */
    ossl_store_ctx = OSSL_STORE_open(STORE_URI, NULL, NULL, NULL, NULL);
    if (ossl_store_ctx == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_open, "X509 certificate verification");
        goto done;
    }

    if (OSSL_STORE_ctrl(ossl_store_ctx, NCRYPT_CMD_VERIFY_CERT, x509_store_ctx,
                        &ctrl_result) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_ctrl, "X509 certificate verification");
        goto done;
    }

    result = ctrl_result;

done:
    OSSL_STORE_close(ossl_store_ctx);

    CMN_DBG_API_LEAVE;
    return result;
}
