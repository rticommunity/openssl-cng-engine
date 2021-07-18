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

#define CMN_THIS_FILE "src/e_bcrypt_pkey.c"

/* Interface */
#include "e_bcrypt_pkey.h"

/* Implementation */
#include "c_cmn.h"
#include "e_bcrypt_rsa_lcl.h"
#include "e_bcrypt_err.h"

/* OpenSSL headers used */
#include <openssl/evp.h>

/* ------------------------------------------------- */
/* Functions that implement the HMAC pkey methods    */
/* ------------------------------------------------- */

/* HMAC key does not do anything with CNG directly, but relies *
 * on a properly instantiated, keyed digest instead. */

/* Mandatory function, even though it does not do anything. */
static int
bcrypt_pkey_hmac_copy(EVP_PKEY_CTX *dst_ctx, EVP_PKEY_CTX *src_ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(src_ctx);
    CMN_UNUSED(dst_ctx);

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

/* Mandatory function, even though it does not do anything. */
static int
bcrypt_pkey_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *md_ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(ctx);
    CMN_UNUSED(md_ctx);

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_pkey_hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         EVP_MD_CTX *md_ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    const EVP_MD *md;
    int (*final)(EVP_MD_CTX * md_ctx, unsigned char *md);

    CMN_UNUSED(ctx);

    CMN_DBG_PRECOND_NOT_NULL(siglen);
    CMN_DBG_PRECOND_NOT_NULL(md_ctx);

    md = EVP_MD_CTX_md(md_ctx);
    CMN_DBG_ASSERT_NOT_NULL(md);

    if (sig != NULL) {
        if (EVP_MD_size(md) > (int)*siglen) {
            E_BCRYPT_err(bcrypt_pkey_hmac_signctx, R_INCORRECT_USAGE,
                         "Not enough space to store signature");
            goto done;
        }
        final = EVP_MD_meth_get_final(md);
        if (final == NULL) {
            E_BCRYPT_osslerr(EVP_MD_meth_get_final,
                             "Looking up PKEY\'s digest\'s final method");
            goto done;
        }
        if (final(md_ctx, sig) != 1)
            goto done;
    }

    *siglen = EVP_MD_size(md);
    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(ctx);
    CMN_UNUSED(p1);

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    switch (type) {
    case EVP_PKEY_CTRL_MD:
    case EVP_PKEY_CTRL_DIGESTINIT:
        CMN_UNUSED(p2);
        break;
    default:
        E_BCRYPT_err(bcrypt_pkey_hmac_ctrl, R_PASSED_UNKNOWN_VALUE,
                     "Unknown HMAC key ctrl command");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* ------------------------------------------------- */
/* Functions that implement the RSA pkey methods     */
/* ------------------------------------------------- */

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
        E_BCRYPT_err(rsa_pss_saltlen_normalized, R_INCORRECT_USAGE,
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
bcrypt_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
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
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get_signature_md,
                         "Getting digest for RSA signing");
        goto done;
    }

    md_type = EVP_MD_type(md);
    if (md_type == NID_undef) {
        E_BCRYPT_osslerr(EVP_MD_type, "Getting digest type for RSA signing");
        goto done;
    }

    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_padding,
                         "Getting padding type for RSA signing");
        goto done;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey,
                         "Getting EVP key for RSA signing");
        goto done;
    }

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey, "Getting RSA key for signing");
        goto done;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        /* Forward the signing to the "normal" RSA sign function */
        tmp_siglen = (unsigned int)(*siglen);
        if (RSA_sign(md_type, tbs, (unsigned int)tbslen, sig, &tmp_siglen,
                     rsa) != 1) {
            E_BCRYPT_osslerr(RSA_sign, "RSA signing");
            goto done;
        }
        *siglen = tmp_siglen;
        break;
    case RSA_PKCS1_PSS_PADDING:
        if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &pss_md_mgf1) <= 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_mgf1_md,
                             "Getting RSA-PSS mgf1 parameter");
            goto done;
        }
        if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &pss_saltlen) <= 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_pss_saltlen,
                             "Getting RSA-PSS saltlen parameter");
            goto done;
        }
        if (rsa_pss_saltlen_normalized(rsa, md, pss_saltlen, &norm_len) != 1)
            goto done;

        /* Invoke internal signing function that supports PSS directly */
        tmp_siglen = (unsigned int)(*siglen);
        if (bcrypt_rsa_pss_sign_digest(md_type, tbs, (unsigned int)tbslen, sig,
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

static int
bcrypt_pkey_rsa_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                       size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int padding;
    EVP_PKEY *pkey;
    RSA *rsa;
    const EVP_MD *md;
    int md_type;
    const EVP_MD *pss_md_mgf1;
    int pss_saltlen;
    unsigned int norm_len;

    if (EVP_PKEY_CTX_get_signature_md(ctx, &md) <= 0) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get_signature_md,
                         "Getting digest for RSA verifying");
        goto done;
    }

    md_type = EVP_MD_type(md);
    if (md_type == NID_undef) {
        E_BCRYPT_osslerr(EVP_MD_type, "Getting digest type for RSA verifying");
        goto done;
    }

    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_padding,
                         "Getting padding type for RSA signing");
        goto done;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey,
                         "Getting EVP key for RSA signing");
        goto done;
    }

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_CTX_get0_pkey, "Getting RSA key for signing");
        goto done;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        /* Forward the signing to the "normal" RSA sign function */
        if (RSA_verify(md_type, tbs, (unsigned int)tbslen, sig,
                       (unsigned int)siglen, rsa) != 1) {
            E_BCRYPT_osslerr(RSA_sign, "RSA signing");
            goto done;
        }
        break;
    case RSA_PKCS1_PSS_PADDING:
        if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &pss_md_mgf1) <= 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_mgf1_md,
                             "Getting RSA-PSS mgf1 parameter");
            goto done;
        }
        if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &pss_saltlen) <= 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_get_rsa_pss_saltlen,
                             "Getting RSA-PSS saltlen parameter");
            goto done;
        }
        if (rsa_pss_saltlen_normalized(rsa, md, pss_saltlen, &norm_len) != 1)
            goto done;

        /* Invoke internal signing function that supports PSS directly */
        if (bcrypt_rsa_pss_verify_digest(md_type, tbs, (unsigned int)tbslen,
                                         sig, (unsigned int)siglen, rsa,
                                         pss_md_mgf1, norm_len) != 1)
            goto done;
        break;
    default:

        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* ------------------------------------------ */
/* Functions for initializing all pkeys etc */
/* ------------------------------------------ */

static EVP_PKEY_METHOD *S_hmac_pkey_meth = NULL;

static int
bcrypt_pkey_hmac_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EVP_PKEY_METHOD *hmac_pkey_meth = NULL;

    hmac_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (hmac_pkey_meth == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_meth_new,
                         "Creating PKEY method for HMAC key");
        goto done;
    }

    EVP_PKEY_meth_set_copy(hmac_pkey_meth, bcrypt_pkey_hmac_copy);
    EVP_PKEY_meth_set_signctx(hmac_pkey_meth, bcrypt_pkey_hmac_signctx_init,
                              bcrypt_pkey_hmac_signctx);
    EVP_PKEY_meth_set_ctrl(hmac_pkey_meth, bcrypt_pkey_hmac_ctrl, NULL);
    S_hmac_pkey_meth = hmac_pkey_meth;

    result = 1;

done:
    if (result != 1) {
        EVP_PKEY_meth_free(hmac_pkey_meth);
    }
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static EVP_PKEY_METHOD *S_rsa_pkey_meth = NULL;

static int
bcrypt_pkey_rsa_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EVP_PKEY_METHOD *rsa_pkey_meth = NULL;
    const EVP_PKEY_METHOD *rsa_pkey_meth_orig;

    rsa_pkey_meth_orig = EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if (rsa_pkey_meth_orig == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_meth_find, "Finding PKEY method for RSA key");
        goto done;
    }

    rsa_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
    if (rsa_pkey_meth == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_meth_new, "Creating PKEY method for RSA key");
        goto done;
    }

    /* Duplicate original method */
    EVP_PKEY_meth_copy(rsa_pkey_meth, rsa_pkey_meth_orig);
    /* But override the signing and verification methods to allow for CNG
     * doing most of the PSS logic. */
    EVP_PKEY_meth_set_sign(rsa_pkey_meth, NULL, bcrypt_pkey_rsa_sign);
    EVP_PKEY_meth_set_verify(rsa_pkey_meth, NULL, bcrypt_pkey_rsa_verify);
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
e_bcrypt_pkey_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int sum = 0;

    sum += bcrypt_pkey_hmac_initialize();
    sum += bcrypt_pkey_rsa_initialize();
    if (sum == 2)
        result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_pkey_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    EVP_PKEY_meth_free(S_hmac_pkey_meth);
    S_hmac_pkey_meth = NULL;

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
e_bcrypt_pkey_get(ENGINE *engine, EVP_PKEY_METHOD **pkey, const int **nids,
                  int nid)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    /* Supported methods for keys */
    static int pkey_nids[] = {EVP_PKEY_HMAC, EVP_PKEY_RSA};

    /* Exactly of the two has to be non-null */
    CMN_DBG_PRECOND((pkey == NULL) != (nids == NULL));

    CMN_UNUSED(engine);

    /* Apparently, this function may be invoked after finalization */
    if ((S_hmac_pkey_meth == NULL) || (S_rsa_pkey_meth == NULL)) {
        if (nids == NULL) {
            E_BCRYPT_err(e_bcrypt_pkey_get, R_INCORRECT_USAGE, "Getting pkey");
            goto done;
        }
        *nids = NULL;
        result = 0;
    } else {
        if (pkey == NULL) {
            if (nids == NULL) {
                E_BCRYPT_err(e_bcrypt_pkey_get, R_INCORRECT_USAGE,
                             "Getting pkey");
                goto done;
            }
            *nids = pkey_nids;
            /* returns the number of registered pkeys */
            result = (sizeof(pkey_nids) / sizeof(*pkey_nids));
        } else {
            switch (nid) {
            case EVP_PKEY_HMAC:
                CMN_DBG_ASSERT_NOT_NULL(S_hmac_pkey_meth);
                *pkey = S_hmac_pkey_meth;
                break;
            case EVP_PKEY_RSA:
                CMN_DBG_ASSERT_NOT_NULL(S_rsa_pkey_meth);
                *pkey = S_rsa_pkey_meth;
                break;
            default:
                E_BCRYPT_err(e_bcrypt_pkey_get, R_NOT_SUPPORTED,
                             "Unknown key type, only HMAC and RSA supported");
                goto done;
            }
            result = 1;
        }
    }
done:
    CMN_DBG_API_LEAVE;
    return result;
}
