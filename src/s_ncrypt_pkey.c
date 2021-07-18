/*
 * (c) 2021 Copyright, Real-Time Innovations, Inc. (RTI)
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
#include "s_ncrypt_pkey.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt_rsa_lcl.h"
#include "s_ncrypt_err.h"

/* OpenSSL headers used */
#include <openssl/evp.h>

/* ------------------------------------------------- */
/* Functions that implement the RSA pkey methods     */
/* ------------------------------------------------- */

/* This PKEY implementation is needed to work around the
 * lack of support for PSS padding in the built-in object */

/* This PKEY implementation is needed to work around the
 * lack of support for PSS padding in the built-in object */

/* Returns 0 in case of error, 1 in case of success */
static int
rsa_pss_saltlen_normalized(const RSA *rsa, const EVP_MD *md, int saltlen,
                           unsigned int *nsaltlen_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int saltlen_out;

    CMN_DBG_ASSERT_NOT_NULL(nsaltlen_out);

    if (saltlen > 0) {
        saltlen_out = saltlen;
    } else if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
        saltlen_out = EVP_MD_size(md);
    } else if ((saltlen == RSA_PSS_SALTLEN_AUTO) ||
               (saltlen == RSA_PSS_SALTLEN_MAX) ||
               (saltlen == RSA_PSS_SALTLEN_MAX_SIGN)) {
        int msbits = (RSA_bits(rsa) - 1) & 0x7;
        int emlen = RSA_size(rsa);
        int hlen = EVP_MD_size(md);
        if (msbits == 0)
            emlen--;
        saltlen_out = emlen - hlen - 2;
    } else {
        S_NCRYPT_err(rsa_pss_saltlen_normalized, R_INCORRECT_USAGE,
                     "Encounter improper saltlen");
        goto done;
    }
    CMN_DBG_ASSERT(nsaltlen_out >= 0);
    *nsaltlen_out = saltlen_out;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ncrypt_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                     const unsigned char *tbs, size_t tbslen)
{
    CMN_DBG_API_ENTER;

    int result = -1;
    int padding;
    EVP_PKEY *pkey;
    RSA *rsa;
    const EVP_MD *md;
    int md_type;
    unsigned int tmp_siglen;
    const EVP_MD *pss_md_mgf1;
    int pss_saltlen;
    unsigned int norm_len;

    CMN_DBG_PRECOND_NOT_NULL(siglen);

    if (EVP_PKEY_CTX_get_signature_md(ctx, &md) <= 0) {
        S_NCRYPT_osslerr(EVP_PKEY_CTX_get_signature_md,
                         "Getting digest for RSA signing");
        goto done;
    }

    md_type = EVP_MD_type(md);
    if (md_type == NID_undef) {
        S_NCRYPT_osslerr(EVP_MD_type, "Getting digest type for RSA signing");
        goto done;
    }

    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
        S_NCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_padding,
                         "Getting padding type for RSA signing");
        goto done;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == NULL) {
        S_NCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey,
                         "Getting EVP key for RSA signing");
        goto done;
    }

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        S_NCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey, "Getting RSA key for signing");
        goto done;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        /* Forward the signing to the "normal" RSA sign function */
        tmp_siglen = (unsigned int)(*siglen);
        if (RSA_sign(md_type, tbs, (unsigned int)tbslen, sig, &tmp_siglen,
                     rsa) != 1) {
            S_NCRYPT_osslerr(RSA_sign, "RSA signing");
            goto done;
        }
        *siglen = tmp_siglen;
        break;
    case RSA_PKCS1_PSS_PADDING:
        if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &pss_md_mgf1) <= 0) {
            S_NCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_mgf1_md,
                             "Getting RSA-PSS mgf1 parameter");
            goto done;
        }
        if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &pss_saltlen) <= 0) {
            S_NCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_pss_saltlen,
                             "Getting RSA-PSS saltlen parameter");
            goto done;
        }
        if (rsa_pss_saltlen_normalized(rsa, md, pss_saltlen, &norm_len) != 1)
            goto done;

        /* Invoke internal signing function that supports PSS directly */
        tmp_siglen = (unsigned int)(*siglen);
        if (ncrypt_rsa_pss_sign_digest(md_type, tbs, (unsigned int)tbslen, sig,
                                       &tmp_siglen, rsa, pss_md_mgf1,
                                       norm_len) != 1)
            goto done;
        *siglen = tmp_siglen;
        break;
    default:

        goto done;
    }

    result = (int)*siglen;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* ----------------------------------------------- */
/* Functions for initializing all pkey methods etc */
/* ----------------------------------------------- */

static EVP_PKEY_METHOD *S_rsa_pkey_meth = NULL;

static int
ncrypt_pkey_rsa_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EVP_PKEY_METHOD *rsa_pkey_meth = NULL;
    const EVP_PKEY_METHOD *rsa_pkey_meth_orig;

    rsa_pkey_meth_orig = EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if (rsa_pkey_meth_orig == NULL) {
        S_NCRYPT_osslerr(EVP_PKEY_meth_find, "Finding PKEY method for RSA key");
        goto done;
    }

    rsa_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
    if (rsa_pkey_meth == NULL) {
        S_NCRYPT_osslerr(EVP_PKEY_meth_new, "Creating PKEY method for RSA key");
        goto done;
    }

    /* Duplicate original method */
    EVP_PKEY_meth_copy(rsa_pkey_meth, rsa_pkey_meth_orig);
    /* But override the signing method to allow for CNG
     * doing most of the PSS logic. */
    EVP_PKEY_meth_set_sign(rsa_pkey_meth, NULL, ncrypt_pkey_rsa_sign);
    S_rsa_pkey_meth = rsa_pkey_meth;

    result = 1;

done:
    if (result != 1) {
        EVP_PKEY_meth_free(rsa_pkey_meth);
    }
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
s_ncrypt_pkey_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = ncrypt_pkey_rsa_initialize();

    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
s_ncrypt_pkey_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    EVP_PKEY_meth_free(S_rsa_pkey_meth);
    S_rsa_pkey_meth = NULL;

    result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------ */
/* Function for querying pkey methods         */
/* ------------------------------------------ */

int
s_ncrypt_pkey_get(ENGINE *engine, EVP_PKEY_METHOD **pkey, const int **nids,
                  int nid)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    /* Supported methods for keys */
    static int pkey_nids[] = {EVP_PKEY_RSA};

    /* Exactly of the two has to be non-null */
    CMN_DBG_PRECOND((pkey == NULL) != (nids == NULL));

    CMN_UNUSED(engine);

    /* Apparently, this function may be invoked after finalization */
    if (S_rsa_pkey_meth == NULL) {
        if (nids == NULL) {
            S_NCRYPT_err(s_ncrypt_pkey_get, R_INCORRECT_USAGE, "Getting pkey");
            goto done;
        }
        *nids = NULL;
        result = 0;
    } else {
        if (pkey == NULL) {
            if (nids == NULL) {
                S_NCRYPT_err(s_ncrypt_pkey_get, R_INCORRECT_USAGE,
                             "Getting pkey");
                goto done;
            }
            *nids = pkey_nids;
            /* returns the number of registered pkeys */
            result = (sizeof(pkey_nids) / sizeof(*pkey_nids));
        } else {
            switch (nid) {
            case EVP_PKEY_RSA:
                CMN_DBG_ASSERT_NOT_NULL(S_rsa_pkey_meth);
                *pkey = S_rsa_pkey_meth;
                break;
            default:
                S_NCRYPT_err(s_ncrypt_pkey_get, R_NOT_SUPPORTED,
                             "Unknown key type, only RSA supported");
                goto done;
            }
            result = 1;
        }
    }
done:
    CMN_DBG_API_LEAVE;
    return result;
}
