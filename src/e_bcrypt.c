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

#define CMN_THIS_FILE "src/e_bcrypt.c"

#include "c_cmn.h"
#include "e_bcrypt_cipher.h"
#include "e_bcrypt_digest.h"
#include "e_bcrypt_pkey.h"
#include "e_bcrypt_rsa.h"
#include "e_bcrypt_dh.h"
#include "e_bcrypt_ec.h"
#include "e_bcrypt_err.h"
#include "e_bcrypt_rand.h"

#include <openssl/engine.h>

const char *bcrypt_evp_id = "engine-bcrypt";
const char *bcrypt_evp_name = "CryptoAPI: Next Gen (CNG) BCrypt EVP Engine";

#define BCRYPT_CMD_DBG_LEVEL (ENGINE_CMD_BASE)

const ENGINE_CMD_DEFN bcrypt_cmd_defns[] = {
    {.cmd_num = BCRYPT_CMD_DBG_LEVEL,
     .cmd_name = "debug_level",
     .cmd_desc =
         "debug level (<0=nothing, 0=errors, 1=warnings, 2=api, 3+=trace)",
     .cmd_flags = ENGINE_CMD_FLAG_NUMERIC},
    /* Terminator */
    {0, NULL, NULL, 0}};

static int
bcrypt_control(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(e);
    CMN_UNUSED(p);
    CMN_UNUSED(f);

    switch (cmd) {
    case BCRYPT_CMD_DBG_LEVEL:
#ifdef _DEBUG
        c_cmn_dbg_set_threshold(i);
#else
        CMN_UNUSED(i);
#endif
        break;
    default:
        goto done;
    }
    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_destroy(ENGINE *e)
{
    CMN_DBG_API_ENTER;

    CMN_UNUSED(e);

    CMN_DBG_API_LEAVE;
    return 1;
}

static int
bcrypt_finish(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    int result = 1;

    CMN_UNUSED(engine);

    if (e_bcrypt_rand_finalize() != 1)
        result = 0;
    if (e_bcrypt_pkey_finalize() != 1)
        result = 0;
    if (e_bcrypt_cipher_finalize() != 1)
        result = 0;
    if (e_bcrypt_digest_finalize() != 1)
        result = 0;
    if (e_bcrypt_dh_finalize() != 1)
        result = 0;
    if (e_bcrypt_rsa_finalize() != 1)
        result = 0;
    if (e_bcrypt_ec_finalize() != 1)
        result = 0;
    if (ERR_unload_EBCRYPT_strings() != 1)
        result = 0;

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_initialize(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    const RAND_METHOD *rand_method;
    const RSA_METHOD *rsa_method;
    const DH_METHOD *dh_method;
    const EC_KEY_METHOD *ec_key_method;

    if (ENGINE_set_flags(engine, ENGINE_FLAGS_NO_REGISTER_ALL) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_flags, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that iplements the finalization. */
    if (ENGINE_set_finish_function(engine, bcrypt_finish) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_finish_function,
                         "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that iplements the destruction. */
    if (ENGINE_set_destroy_function(engine, bcrypt_destroy) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_destroy_function,
                         "Initializing BCrypt engine");
        goto done;
    }

    /* Initialize the error strings */
    if (ERR_load_EBCRYPT_strings() != 1) {
        /* Not fatal, just mention it */
        CMN_DBG_ERROR("Can not load BCrypt engine error strings");
    }

    /* Set a pointer to a RNG methods struct */
    if (e_bcrypt_rand_initialize() != 1)
        goto done;
    rand_method = e_bcrypt_rand_get();
    if (rand_method == NULL)
        goto done;
    if (ENGINE_set_RAND(engine, rand_method) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_RAND, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that provides the PKEY methods. */
    if (e_bcrypt_pkey_initialize() != 1)
        goto done;
    if (ENGINE_set_pkey_meths(engine, e_bcrypt_pkey_get) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_pkey_meths, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that provides the cipher methods. */
    if (e_bcrypt_cipher_initialize() != 1)
        goto done;
    if (ENGINE_set_ciphers(engine, e_bcrypt_cipher_get) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_ciphers, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a function that provides the digest methods. */
    if (e_bcrypt_digest_initialize() != 1)
        goto done;
    if (ENGINE_set_digests(engine, e_bcrypt_digest_get) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_digests, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a RSA methods struct */
    if (e_bcrypt_rsa_initialize() != 1)
        goto done;
    rsa_method = e_bcrypt_rsa_get();
    if (rsa_method == NULL)
        goto done;
    if (ENGINE_set_RSA(engine, rsa_method) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_RSA, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a DH methods struct */
    if (e_bcrypt_dh_initialize() != 1)
        goto done;
    dh_method = e_bcrypt_dh_get();
    if (dh_method == NULL)
        goto done;
    if (ENGINE_set_DH(engine, dh_method) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_DH, "Initializing BCrypt engine");
        goto done;
    }

    /* Set a pointer to a EC_KEY methods struct */
    if (e_bcrypt_ec_initialize() != 1)
        goto done;
    ec_key_method = e_bcrypt_ec_get();
    if (ec_key_method == NULL)
        goto done;
    if (ENGINE_set_EC(engine, ec_key_method) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_EC, "Initializing BCrypt engine");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Functions to implement standard dynamic loading behavior */
int
bcrypt_evp_bind(ENGINE *engine)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    if (ENGINE_set_id(engine, bcrypt_evp_id) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_id, "BCrypt engine binding");
        goto done;
    }

    if (ENGINE_set_name(engine, bcrypt_evp_name) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_name, "BCrypt engine binding");
        goto done;
    }

    /* Set a pointer to a function that provides the list of commands. */
    if (ENGINE_set_cmd_defns(engine, bcrypt_cmd_defns) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_cmd_defns, "BCrypt engine binding");
        goto done;
    }

    /* Set a pointer to a function that implements the control. */
    if (ENGINE_set_ctrl_function(engine, bcrypt_control) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_ctrl_function, "BCrypt engine binding");
        goto done;
    }

#if OSSL_INITIALIZES_ENGINE
    /* Set the init function, where all methods will be bound */
    if (ENGINE_set_init_function(engine, bcrypt_initialize) != 1) {
        E_BCRYPT_osslerr(ENGINE_set_init_function, "BCrypt engine binding");
        goto done;
    }
#else
    /* OpenSSL tools do not properly invoke the initialize function,
       so let's do it here */
    if (bcrypt_initialize(engine) != 1)
        goto done;
#endif
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* External function for loading the engine in case of static linking */
void
engine_load_bcrypt_evp(void)
{
    CMN_DBG_API_ENTER;

    /* Too early for error reporting here, just return in cas of failure */
    ENGINE *e = ENGINE_new();
    if (e == NULL)
        goto done;
    if (!bcrypt_evp_bind(e)) {
        ENGINE_free(e);
        goto done;
    }
    ENGINE_add(e);
    ENGINE_free(e);
    ERR_clear_error();
done:
    CMN_DBG_API_LEAVE;
}
