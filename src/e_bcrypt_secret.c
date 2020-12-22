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

#define CMN_THIS_FILE "src/e_bcrypt_secret.c"

/* Interface */
#include "e_bcrypt_secret.h"
#include "e_bcrypt_err.h"

/* Implementation */
#include "c_cmn.h"
#include "c_cmn_dbg.h"

#if B_NO_RAW_SECRET

/* For the older versions of Windows that do not support the RAW key format,
 *   we choose an appropriate digest which depends on the magic value. */
int
secret_derive(BCRYPT_KEY_HANDLE h_my_private_key,
              BCRYPT_KEY_HANDLE h_other_public_key, int magic, PUCHAR *key_out,
              ULONG *len_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG result_len;
    PUCHAR secret = NULL;
    ULONG len;
    BCRYPT_SECRET_HANDLE h_shared_secret = NULL;
    WCHAR const *sha_alg;
    BCryptBufferDesc parameterDesc = {0};
    const DWORD paramCount = 1;
    BCryptBuffer paramList[1] = {0};

    /* Determine shared secret */
    cng_retval = BCryptSecretAgreement(h_my_private_key, h_other_public_key,
                                       &h_shared_secret, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptSecretAgreement,
                        "Caclculating shared secret");
        goto done;
    }

    switch (magic) {
    case BCRYPT_DH_PRIVATE_MAGIC:
        sha_alg = BCRYPT_SHA256_ALGORITHM;
        break;
    case BCRYPT_ECDH_PRIVATE_P256_MAGIC:
        sha_alg = BCRYPT_SHA256_ALGORITHM;
        break;
    case BCRYPT_ECDH_PRIVATE_P384_MAGIC:
        sha_alg = BCRYPT_SHA384_ALGORITHM;
        break;
    case BCRYPT_ECDH_PRIVATE_P521_MAGIC:
        sha_alg = BCRYPT_SHA512_ALGORITHM;
        break;
    default:
        goto done;
        break;
    }

    /* specify hash algorithm */
    paramList[0].BufferType = KDF_HASH_ALGORITHM;
    paramList[0].cbBuffer = (DWORD)((wcslen(sha_alg) + 1) * sizeof(WCHAR));
    paramList[0].pvBuffer = (PVOID)sha_alg;

    parameterDesc.cBuffers = paramCount;
    parameterDesc.pBuffers = paramList;
    parameterDesc.ulVersion = BCRYPTBUFFER_VERSION;

    /* Get the required size of the buffer space for the key */
    cng_retval = BCryptDeriveKey(h_shared_secret, BCRYPT_KDF_HASH,
                                 &parameterDesc, NULL, 0, &len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptDeriveKey,
                        "Obtaining size of derived key from shared secret");
        goto done;
    }

    /* Allocate the required space */
    secret = CMN_malloc(len);
    if (secret == NULL) {
        E_BCRYPT_err(secret_derive, R_MALLOC_FAILED,
                     "Allocating CNG secret key");
        goto done;
    }

    /* Derive key from shared secret */
    result_len = len;
    cng_retval = BCryptDeriveKey(h_shared_secret, BCRYPT_KDF_HASH,
                                 &parameterDesc, secret, len, &result_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptDeriveKey,
                        "Deriving key from shared secret");
        goto done;
    }
    CMN_DBG_ASSERT(result_len <= len);

    *key_out = secret;
    *len_out = len;
    result = 1;

done:
    if (result != 1) {
        CMN_free(secret);
    }
    if (h_shared_secret != NULL) {
        cng_retval = BCryptDestroySecret(h_shared_secret);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroySecret,
                             "Destroying temporary CNG shared secret");
        }
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

#else /* B_NO_RAW_SECRET */

int
secret_derive(BCRYPT_KEY_HANDLE h_my_private_key,
              BCRYPT_KEY_HANDLE h_other_public_key, PUCHAR *key_out,
              ULONG *len_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG result_len;
    PUCHAR secret = NULL;
    ULONG len;
    BCRYPT_SECRET_HANDLE h_shared_secret = NULL;
    PUCHAR pb, pe;

    /* Determine shared secret */
    cng_retval = BCryptSecretAgreement(h_my_private_key, h_other_public_key,
                                       &h_shared_secret, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptSecretAgreement,
                        "Caclculating shared secret");
        goto done;
    }

    /* Get the required size of the buffer space for the key */
    cng_retval = BCryptDeriveKey(h_shared_secret, BCRYPT_KDF_RAW_SECRET, NULL,
                                 NULL, 0, &len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptDeriveKey,
                        "Obtaining size of derived key from shared secret");
        goto done;
    }

    /* Allocate the required space */
    secret = CMN_malloc(len);
    if (secret == NULL) {
        E_BCRYPT_err(secret_derive, R_MALLOC_FAILED,
                     "Allocating CNG secret key");
        goto done;
    }

    /* Derive key from shared secret */
    result_len = len;
    cng_retval = BCryptDeriveKey(h_shared_secret, BCRYPT_KDF_RAW_SECRET, NULL,
                                 secret, len, &result_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(secret_derive, cng_retval, BCryptDeriveKey,
                        "Deriving key from shared secret");
        goto done;
    }
    CMN_DBG_ASSERT(result_len <= len);

    /* For some reason, the RAW mode returns the secret as little endian, whereas
     * everything/body else uses big endian. Do the swapping here */
    pb = secret;
    pe = &secret[result_len - 1];
    while (pb < pe) {
        unsigned char c = *pb;
        *(pb++) = *pe;
        *(pe--) = c;
    }

    *key_out = secret;
    *len_out = len;
    result = 1;

done:
    if (result != 1) {
        CMN_free(secret);
    }
    if (h_shared_secret != NULL) {
        cng_retval = BCryptDestroySecret(h_shared_secret);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroySecret,
                             "Destroying temporary CNG shared secret");
        }
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

#endif /* B_NO_RAW_SECRET */
