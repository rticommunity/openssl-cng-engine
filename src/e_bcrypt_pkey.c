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

#define CMN_THIS_FILE "src/e_bcrypt_pkey.c"

/* Interface */
#include "e_bcrypt_pkey.h"

/* Implementation */
#include "c_cmn.h"
#include "e_bcrypt_err.h"

/* OpenSSL headers used */
#include <openssl/evp.h>

/* ------------------------------------------------- */
/* Functions that implement the pkey methods         */
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

/* ------------------------------------------ */
/* Functions for initializing all pkeys etc */
/* ------------------------------------------ */

static EVP_PKEY_METHOD *S_hmac_pkey_meth = NULL;

int
e_bcrypt_pkey_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EVP_PKEY_METHOD *meth;

    meth = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (meth == NULL) {
        E_BCRYPT_osslerr(EVP_PKEY_meth_new,
                         "Creating PKEY method for HMAC key");
        goto done;
    }

    EVP_PKEY_meth_set_copy(meth, bcrypt_pkey_hmac_copy);

    EVP_PKEY_meth_set_signctx(meth, bcrypt_pkey_hmac_signctx_init,
                              bcrypt_pkey_hmac_signctx);

    EVP_PKEY_meth_set_ctrl(meth, bcrypt_pkey_hmac_ctrl, NULL);

    S_hmac_pkey_meth = meth;
    result = 1;

done:
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
    static int pkey_nids[] = {EVP_PKEY_HMAC};

    /* Exactly of the two has to be non-null */
    CMN_DBG_PRECOND((pkey == NULL) != (nids == NULL));

    CMN_UNUSED(engine);

    /* Apparently, this function may be invoked after finalization */
    if (S_hmac_pkey_meth == NULL) {
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
            if (nid != EVP_PKEY_HMAC) {
                E_BCRYPT_err(e_bcrypt_pkey_get, R_NOT_SUPPORTED,
                             "Unknown key type, only HMAC is supported");
                goto done;
            }
            CMN_DBG_ASSERT_NOT_NULL(S_hmac_pkey_meth);
            /* No need to do any looking up, there is one meth only */
            *pkey = S_hmac_pkey_meth;
            result = 1;
        }
    }
done:
    CMN_DBG_API_LEAVE;
    return result;
}
