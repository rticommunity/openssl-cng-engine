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

#define CMN_THIS_FILE "src/e_bcrypt_provider.c"

/* Interface */
#include "e_bcrypt_provider.h"
#include "e_bcrypt_err.h"

/* Implementation */
#include "c_cmn.h"
#include "c_cmn_dbg.h"

BOOL CALLBACK
alg_provider_open(PINIT_ONCE initOnce,
                  PVOID algorithm_ptr, /* enum bcrypt_algorithm* */
                  LPVOID *handle_out /* BCRYPT_ALG_HANDLE* */)
{
    CMN_DBG_TRACE_ENTER;

    BOOL result = FALSE;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE alg_handle = NULL;
    enum bcrypt_algorithm alg_kind = *((enum bcrypt_algorithm *)algorithm_ptr);
    LPCWSTR alg_id;
    ULONG alg_flags;

    CMN_UNUSED(initOnce);

    CMN_DBG_ASSERT_NOT_NULL(handle_out);

    alg_id = alg_provider_name(alg_kind);
    if (alg_id == NULL)
        goto done;

    if ((alg_kind == B_HMAC_SHA1_ALG) || (alg_kind == B_HMAC_SHA256_ALG) ||
        (alg_kind == B_HMAC_SHA384_ALG) || (alg_kind == B_HMAC_SHA512_ALG)) {
        alg_flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
    } else {
        alg_flags = 0;
    }

    cng_retval =
        BCryptOpenAlgorithmProvider(&alg_handle, alg_id, NULL, alg_flags);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(alg_provider_open, cng_retval,
                        BCryptOpenAlgorithmProvider,
                        "Loading algorithm provider");
        goto done;
    }

    /* Additional action for AES-GCM only */
    if (alg_kind == B_AES_GCM_ALG) {
        /* Instruct provider to use GCM mode of operation */
        cng_retval = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE,
                                       (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                                       sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(alg_provider_open, cng_retval, BCryptSetProperty,
                            "Setting AES provider to GCM mode");
            goto done;
        }
    }

    *handle_out = alg_handle;
    result = TRUE;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

WCHAR const *
alg_provider_name(enum bcrypt_algorithm alg_kind)
{
    WCHAR const *result = NULL;
    WCHAR const *alg_id;

    switch (alg_kind) {
    case B_AES_GCM_ALG:
        alg_id = BCRYPT_AES_ALGORITHM;
        break;
    case B_DH_ALG:
        alg_id = BCRYPT_DH_ALGORITHM;
        break;
    case B_ECDH_P256_ALG:
        alg_id = BCRYPT_ECDH_P256_ALGORITHM;
        break;
    case B_ECDH_P384_ALG:
        alg_id = BCRYPT_ECDH_P384_ALGORITHM;
        break;
    case B_ECDH_P521_ALG:
        alg_id = BCRYPT_ECDH_P521_ALGORITHM;
        break;
    case B_ECDSA_P256_ALG:
        alg_id = BCRYPT_ECDSA_P256_ALGORITHM;
        break;
    case B_ECDSA_P384_ALG:
        alg_id = BCRYPT_ECDSA_P384_ALGORITHM;
        break;
    case B_ECDSA_P521_ALG:
        alg_id = BCRYPT_ECDSA_P521_ALGORITHM;
        break;
    case B_HMAC_SHA1_ALG:
        alg_id = BCRYPT_SHA1_ALGORITHM;
        break;
    case B_HMAC_SHA256_ALG:
        alg_id = BCRYPT_SHA256_ALGORITHM;
        break;
    case B_HMAC_SHA384_ALG:
        alg_id = BCRYPT_SHA384_ALGORITHM;
        break;
    case B_HMAC_SHA512_ALG:
        alg_id = BCRYPT_SHA512_ALGORITHM;
        break;
    case B_RSA_ALG:
        alg_id = BCRYPT_RSA_ALGORITHM;
        break;
    case B_RNG_ALG:
        /* The default random number provider implements an algorithm for
         * generating random numbers that complies with the NIST SP800-90
         * standard, specifically the CTR_DRBG portion of that standard.*/
        alg_id = BCRYPT_RNG_ALGORITHM;
        break;
    case B_SHA1_ALG:
        alg_id = BCRYPT_SHA1_ALGORITHM;
        break;
    case B_SHA256_ALG:
        alg_id = BCRYPT_SHA256_ALGORITHM;
        break;
    case B_SHA384_ALG:
        alg_id = BCRYPT_SHA384_ALGORITHM;
        break;
    case B_SHA512_ALG:
        alg_id = BCRYPT_SHA512_ALGORITHM;
        break;
    default:
        E_BCRYPT_err(alg_provider_open, R_PASSED_UNKNOWN_VALUE,
                     "Unknown algorithm kind value");
        goto done;
    }

    result = alg_id;

done:
    return result;
}
