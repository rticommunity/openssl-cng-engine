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

#define CMN_THIS_FILE "src/s_ncrypt_pkey.c"

/* Interface */
#include "s_ncrypt_evp_pkey_lcl.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt_err.h"
#include "s_ncrypt_ec_lcl.h"
#include "s_ncrypt_rsa_lcl.h"

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

/* Standard includes */
#include <stdbool.h>

EVP_PKEY *
ncrypt_evp_pkey_new(PCCERT_CONTEXT cert_ctx)
{
    CMN_DBG_TRACE_ENTER;

    EVP_PKEY *result = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    RSA *rsa_key = NULL;
    LPSTR objId;

    CMN_DBG_PRECOND_NOT_NULL(cert_ctx);

    objId = cert_ctx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    CMN_DBG_ASSERT_NOT_NULL(objId);

    /* Create PKEY that holds the EC or RSA key */
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        S_NCRYPT_osslerr(EVP_PKEY_new, "Creating new PKEY");
        goto done;
    }

    if (strcmp(szOID_ECC_PUBLIC_KEY, objId) == 0) {
        /* This is an EC key*/
        ec_key = ncrypt_ec_key_new(cert_ctx);
        if (ec_key == NULL)
            goto done;
        if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
            S_NCRYPT_osslerr(EVP_PKEY_set1_EC_KEY, "Setting EC key of PKEY");
            goto done;
        }
    } else if (strcmp(szOID_RSA_RSA, objId) == 0) {
        /* This is an RSA key */
        rsa_key = ncrypt_rsa_new(cert_ctx);
        if (rsa_key == NULL)
            goto done;
        if (EVP_PKEY_set1_RSA(pkey, rsa_key) != 1) {
            S_NCRYPT_osslerr(EVP_PKEY_set1_RSA, "Setting RSA key of PKEY");
            goto done;
        }
    } else {
        /* The type of this key is not recognised */
        CMN_DBG_ERROR("Encountered unsupported key type %s", objId);
        S_NCRYPT_err(ncrypt_evp_pkey_free, R_NOT_SUPPORTED,
                     "Encountered unsupported key type");
        goto done;
    }

    /* Success */
    result = pkey;

done:
    if (result == NULL) {
        EVP_PKEY_free(pkey);
    }
    EC_KEY_free(ec_key);
    RSA_free(rsa_key);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
ncrypt_evp_pkey_free(EVP_PKEY *pkey)
{
    CMN_DBG_TRACE_ENTER;

    CMN_DBG_PRECOND_NOT_NULL(pkey);

    EVP_PKEY_free(pkey);

    CMN_DBG_TRACE_LEAVE;
    return;
}
