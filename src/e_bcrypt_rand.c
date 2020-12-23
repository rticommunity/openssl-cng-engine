/*
 * (c) 2020 Copyright, Real-Time Innovations, Inc. (RTI)
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

#define CMN_THIS_FILE "src/e_bcrypt_rand.c"

/* Interface */
#include "e_bcrypt_rand.h"

/* Implementation */
#include "e_bcrypt_provider.h"
#include "e_bcrypt_err.h"

/* CNG Engine header files */
#include "c_cmn.h"

/* OpenSSL implementation header files */
#include <openssl/evp.h>
#include <openssl/rand.h> /* for RAND_METHOD */

static int
alg_provider_rng_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_RNG_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_rng_get, last_error, InitOnceExecuteOnce,
                        "RNG one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ----------------------------------------- */
/* Functions that implement the RAND methods */
/* ----------------------------------------- */

/* Get random data from the CNG RNG */
static int
bcrypt_rand_bytes(unsigned char *buffer, int buffer_len)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_ALG_HANDLE h_rand_alg = NULL;
    NTSTATUS cng_retval;

    CMN_DBG_PRECOND_NOT_NULL(buffer);

    if (alg_provider_rng_get(&h_rand_alg) != 1)
        goto done;

    cng_retval = BCryptGenRandom(h_rand_alg, buffer, buffer_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_rand_bytes, cng_retval, BCryptGenRandom,
                        "Invoking random by generator");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static RAND_METHOD *S_rand_method = NULL;

int
e_bcrypt_rand_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_ASSERT(S_rand_method == NULL);

    if (S_rand_method == NULL) {
        /* There is no constructor for this, weird */
        S_rand_method = CMN_malloc(sizeof(*S_rand_method));
        if (S_rand_method == NULL) {
            E_BCRYPT_err(e_bcrypt_rand_initialize, R_MALLOC_FAILED,
                         "Initializing PRNG");
            goto done;
        }
        S_rand_method->bytes = bcrypt_rand_bytes;
        S_rand_method->pseudorand = bcrypt_rand_bytes;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_rand_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    CMN_DBG_ASSERT_NOT_NULL(S_rand_method);

    if (S_rand_method != NULL) {
        CMN_free(S_rand_method);
        S_rand_method = NULL;
    }

    CMN_DBG_TRACE_LEAVE;
    return 1;
}

const RAND_METHOD *
e_bcrypt_rand_get(void)
{
    CMN_DBG_TRACE_ENTER;

    const RAND_METHOD *result = S_rand_method;

    CMN_DBG_TRACE_LEAVE;
    return result;
}
