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

#define CMN_THIS_FILE "src/e_bcrypt_digest.c"

/* Interface */
#include "e_bcrypt_digest.h"

/* Implementation */
#include "e_bcrypt_provider.h"
/* Depending on cipher for HMAC */
#include "e_bcrypt_cipher.h"
#include "e_bcrypt_err.h"

/* Common header files */
#include "c_cmn.h"
#include <stdbool.h>

/* OpenSSL implementation header files */
#include <openssl/sha.h>
#include <openssl/evp.h>

static int
alg_provider_sha1_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_SHA1_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_sha1_get, last_error, InitOnceExecuteOnce,
                        "SHA1 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_hmac_sha1_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_HMAC_SHA1_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_hmac_sha1_get, last_error,
                        InitOnceExecuteOnce,
                        "HMAC-SHA1 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_sha256_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_SHA256_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_sha256_get, last_error,
                        InitOnceExecuteOnce, "SHA256 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_hmac_sha256_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_HMAC_SHA256_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_hmac_sha256_get, last_error,
                        InitOnceExecuteOnce,
                        "HMAC-SHA256 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_sha384_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_SHA384_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_sha384_get, last_error,
                        InitOnceExecuteOnce, "SHA384 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_hmac_sha384_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_HMAC_SHA384_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_hmac_sha384_get, last_error,
                        InitOnceExecuteOnce,
                        "HMAC-SHA384 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_sha512_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_SHA512_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_sha512_get, last_error,
                        InitOnceExecuteOnce, "SHA512 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_hmac_sha512_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_HMAC_SHA512_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_hmac_sha512_get, last_error,
                        InitOnceExecuteOnce,
                        "HMAC-SHA512 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ----------------------------------------- */
/* Storing and manipulating the CNG elements */
/* ----------------------------------------- */

typedef struct BCRYPT_MD_CTX_st {
    BCRYPT_HASH_HANDLE hash_handle;
    DWORD hash_object_length;
    BYTE *hash_object /*[hash_object_length]*/;
} BCRYPT_MD_CTX;

/* ------------------------------------------------- */
/* Functions that implement the digest methods       */
/* These are not aware of any CNG types or functions */
/* ------------------------------------------------- */

static int
bcrypt_digest_sha_init(EVP_MD_CTX *ctx)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey = NULL; /* Initialize to silence compiler */
    int nid;
    bool has_hmac;
    size_t hmac_key_len;
    const unsigned char *hmac_key_bytes;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_hash_alg = NCRYPT_NULL;
    BCRYPT_HASH_HANDLE hash_handle;
    DWORD hash_object_length;
    BYTE *hash_object = NULL;
    ULONG bytes_used;
    BCRYPT_MD_CTX *md_ctx;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    md_ctx = EVP_MD_CTX_md_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx);

    nid = EVP_MD_CTX_type(ctx);

    /* Get HMAC key, optionally */
    has_hmac = false;
    pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (pkey_ctx != NULL) {
        pkey = EVP_PKEY_CTX_get0_pkey(pkey_ctx);
        if (pkey != NULL) {
            has_hmac = (EVP_PKEY_id(pkey) == EVP_PKEY_HMAC);
        }
    }

    if (has_hmac) {
        /* Keyed hash */
        hmac_key_bytes = EVP_PKEY_get0_hmac(pkey, &hmac_key_len);
        if (hmac_key_bytes == NULL) {
            E_BCRYPT_osslerr(EVP_PKEY_get0_hmac, "Getting expected HMAC key");
            goto done;
        }
        switch (nid) {
        case NID_sha1:
            if (alg_provider_hmac_sha1_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha256:
            if (alg_provider_hmac_sha256_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha384:
            if (alg_provider_hmac_sha384_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha512:
            if (alg_provider_hmac_sha512_get(&h_hash_alg) != 1)
                goto done;
            break;
        }
    } else {
        /* Plain hash */
        hmac_key_len = 0;
        hmac_key_bytes = NULL;
        switch (nid) {
        case NID_sha1:
            if (alg_provider_sha1_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha256:
            if (alg_provider_sha256_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha384:
            if (alg_provider_sha384_get(&h_hash_alg) != 1)
                goto done;
            break;
        case NID_sha512:
            if (alg_provider_sha512_get(&h_hash_alg) != 1)
                goto done;
            break;
        }
    }
    CMN_DBG_ASSERT(h_hash_alg != NCRYPT_NULL);

    /* Calculate the size of the buffer to hold the hash object */
    cng_retval = BCryptGetProperty(h_hash_alg, BCRYPT_OBJECT_LENGTH,
                                   (PBYTE)&hash_object_length,
                                   sizeof(hash_object_length), &bytes_used, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_digest_init, cng_retval, BCryptGetProperty,
                        "Getting hash object length");
        goto done;
    }
    CMN_DBG_ASSERT(sizeof(hash_object_length) == bytes_used);

    /* Get the length of a CNG hash object, in bytes */
    hash_object = CMN_malloc(hash_object_length);
    if (hash_object == NULL) {
        E_BCRYPT_err(bcrypt_digest_init, R_MALLOC_FAILED,
                     "Allocating for CNG hash object");
        goto done;
    }

    /* Create a CNG hash object */
    CMN_DBG_ASSERT_NOT_NULL(md_ctx);
    cng_retval = BCryptCreateHash(h_hash_alg, &hash_handle, hash_object,
                                  hash_object_length, (PUCHAR)hmac_key_bytes,
                                  (ULONG)hmac_key_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_digest_init, cng_retval, BCryptCreateHash,
                        "Creating CNG hash object");
        goto done;
    }

    md_ctx->hash_handle = hash_handle;
    md_ctx->hash_object_length = hash_object_length;
    md_ctx->hash_object = hash_object;

    result = 1;

done:
    if (result != 1) {
        CMN_free(hash_object);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
bcrypt_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    BCRYPT_MD_CTX *md_ctx;

    CMN_DBG_PRECOND_NOT_NULL(ctx);
    CMN_DBG_PRECOND_NOT_NULL(data);

    md_ctx = EVP_MD_CTX_md_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx);

    cng_retval =
        BCryptHashData(md_ctx->hash_handle, (PUCHAR)data, (ULONG)count, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_digest_update, cng_retval, BCryptHashData,
                        "Adding data to hash input");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_MD_CTX *md_ctx;
    NTSTATUS cng_retval;
    BCRYPT_HASH_HANDLE hash_handle;
    ULONG digest_len;

    CMN_DBG_PRECOND_NOT_NULL(ctx);
    CMN_DBG_PRECOND_NOT_NULL(digest);

    digest_len = EVP_MD_CTX_size(ctx);

    md_ctx = EVP_MD_CTX_md_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx);

    hash_handle = md_ctx->hash_handle;
    CMN_DBG_ASSERT_NOT_NULL(hash_handle);

    cng_retval = BCryptFinishHash(hash_handle, (PUCHAR)digest, digest_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_digest_final, cng_retval, BCryptFinishHash,
                        "Calculating hash value from final input");
        goto done;
    }

    result = 1;

done:
    if (md_ctx->hash_handle != NULL) {
        cng_retval = BCryptDestroyHash(md_ctx->hash_handle);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(bcrypt_digest_final, cng_retval, BCryptDestroyHash,
                            "Destroying CNG Hash object");
        }
        md_ctx->hash_handle = NULL;
    }
    CMN_free(md_ctx->hash_object);
    md_ctx->hash_object = NULL;

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    BCRYPT_MD_CTX *md_ctx_to;
    BCRYPT_MD_CTX *md_ctx_from;

    CMN_DBG_PRECOND_NOT_NULL(to);
    CMN_DBG_PRECOND_NOT_NULL(from);

    md_ctx_to = EVP_MD_CTX_md_data(to);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx_to);
    md_ctx_from = EVP_MD_CTX_md_data(from);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx_from);

    md_ctx_to->hash_object_length = md_ctx_from->hash_object_length;
    md_ctx_to->hash_object = CMN_malloc(md_ctx_to->hash_object_length);
    if (md_ctx_to->hash_object == NULL) {
        E_BCRYPT_err(bcrypt_digest_copy, R_MALLOC_FAILED,
                     "Unable to allocate memory for destination hash object");
        goto done;
    }

    cng_retval =
        BCryptDuplicateHash(md_ctx_from->hash_handle, &md_ctx_to->hash_handle,
                            md_ctx_to->hash_object,
                            md_ctx_to->hash_object_length, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_digest_copy, cng_retval, BCryptDuplicateHash,
                        "Duplicating CNG hash object");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_digest_cleanup(EVP_MD_CTX *ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_MD_CTX *md_ctx;
    NTSTATUS cng_retval;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    md_ctx = EVP_MD_CTX_md_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(md_ctx);

    /* This is normally done in the final() call, but double check
       in case that was not invoked earlier */
    if (md_ctx->hash_handle != NULL) {
        cng_retval = BCryptDestroyHash(md_ctx->hash_handle);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyHash,
                             "Destroying CNG hash object");
        }
    }

    result = 1;

    /* This has to be done in any case */
    CMN_free(md_ctx->hash_object);

    CMN_DBG_API_LEAVE;
    return result;
}

/* The control functions sometimes get invoked without any context.
 * Therefore, a different function per nid is required :-( */

static char *
micalg_from_nid(int nid)
{
    char *result = NULL;
    enum bcrypt_algorithm alg_kind;
    WCHAR const *alg_namew;
    char *alg_name;

    switch (nid) {
    case NID_sha1:
        alg_kind = B_SHA1_ALG;
        break;
    case NID_sha256:
        alg_kind = B_SHA256_ALG;
        break;
    case NID_sha384:
        alg_kind = B_SHA384_ALG;
        break;
    case NID_sha512:
        alg_kind = B_SHA512_ALG;
        break;
    default:
        E_BCRYPT_err(bcrypt_digest_control, R_PASSED_UNKNOWN_VALUE,
                     "Received unknown digest kind");
        goto done;
    }

    alg_namew = alg_provider_name(alg_kind);
    if (alg_namew == NULL)
        goto done;
    alg_name = cmn_win_wstr_to_str_utf8(alg_namew);
    if (alg_name == NULL)
        goto done;

    result = alg_name;

done:
    return result;
}

static int
digest_control_for_nid(int nid, EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    int result = 0;
    void *void_res;

    CMN_UNUSED(ctx);
    CMN_UNUSED(p1);

    switch (cmd) {
    case EVP_MD_CTRL_MICALG:
        void_res = micalg_from_nid(nid);
        break;
    default:
        E_BCRYPT_err(bcrypt_digest_control, R_PASSED_UNKNOWN_VALUE,
                     "Received unknown control value");
        goto done;
    }

    *((void **)p2) = void_res;
    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_digest_control_sha1(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return digest_control_for_nid(NID_sha1, ctx, cmd, p1, p2);
}

static int
bcrypt_digest_control_sha256(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return digest_control_for_nid(NID_sha256, ctx, cmd, p1, p2);
}

static int
bcrypt_digest_control_sha384(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return digest_control_for_nid(NID_sha384, ctx, cmd, p1, p2);
}

static int
bcrypt_digest_control_sha512(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return digest_control_for_nid(NID_sha512, ctx, cmd, p1, p2);
}

/* ------------------------------------------ */
/* Functions for initializing all digests etc */
/* ------------------------------------------ */

/* Common setters for all SHA sizes */
static int
digest_sha_init(EVP_MD *digest, int nid)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    switch (nid) {
    case NID_sha1:
        EVP_MD_meth_set_result_size(digest, SHA_DIGEST_LENGTH);
        EVP_MD_meth_set_input_blocksize(digest, SHA_CBLOCK);
        EVP_MD_meth_set_ctrl(digest, bcrypt_digest_control_sha1);
        break;
    case NID_sha256:
        EVP_MD_meth_set_result_size(digest, SHA256_DIGEST_LENGTH);
        EVP_MD_meth_set_input_blocksize(digest, SHA256_CBLOCK);
        EVP_MD_meth_set_ctrl(digest, bcrypt_digest_control_sha256);
        break;
    case NID_sha384:
        EVP_MD_meth_set_result_size(digest, SHA384_DIGEST_LENGTH);
        EVP_MD_meth_set_input_blocksize(digest, SHA512_CBLOCK);
        EVP_MD_meth_set_ctrl(digest, bcrypt_digest_control_sha384);
        break;
    case NID_sha512:
        EVP_MD_meth_set_result_size(digest, SHA512_DIGEST_LENGTH);
        EVP_MD_meth_set_input_blocksize(digest, SHA512_CBLOCK);
        EVP_MD_meth_set_ctrl(digest, bcrypt_digest_control_sha512);
        break;
    default:
        E_BCRYPT_err(digest_sha_init, R_NOT_SUPPORTED,
                     "Initializing digest for unsupported output size");
        goto done;
        break;
    }

    EVP_MD_meth_set_app_datasize(digest, sizeof(BCRYPT_MD_CTX));
    EVP_MD_meth_set_init(digest, bcrypt_digest_sha_init);
    EVP_MD_meth_set_update(digest, bcrypt_digest_update);
    EVP_MD_meth_set_final(digest, bcrypt_digest_final);
    EVP_MD_meth_set_copy(digest, bcrypt_digest_copy);
    EVP_MD_meth_set_cleanup(digest, bcrypt_digest_cleanup);

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static EVP_MD *S_sha1_digest = NULL;
static EVP_MD *S_sha256_digest = NULL;
static EVP_MD *S_sha384_digest = NULL;
static EVP_MD *S_sha512_digest = NULL;

int
e_bcrypt_digest_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    if (S_sha1_digest == NULL) {
        S_sha1_digest = EVP_MD_meth_new(NID_sha1, NID_undef);
        if (S_sha1_digest == NULL) {
            E_BCRYPT_osslerr(EVP_MD_meth_new, "Instantiating SHA-1 struct");
            goto done;
        }
        if (digest_sha_init(S_sha1_digest, NID_sha1) != 1)
            goto done;
    }

    if (S_sha256_digest == NULL) {
        S_sha256_digest = EVP_MD_meth_new(NID_sha256, NID_undef);
        if (S_sha256_digest == NULL) {
            E_BCRYPT_osslerr(EVP_MD_meth_new, "Instantiating SHA-256 struct");
            goto done;
        }
        if (digest_sha_init(S_sha256_digest, NID_sha256) != 1)
            goto done;
    }

    if (S_sha384_digest == NULL) {
        S_sha384_digest = EVP_MD_meth_new(NID_sha384, NID_undef);
        if (S_sha384_digest == NULL) {
            E_BCRYPT_osslerr(EVP_MD_meth_new, "Instantiating SHA-384 struct");
            goto done;
        }
        if (digest_sha_init(S_sha384_digest, NID_sha384) != 1)
            goto done;
    }

    if (S_sha512_digest == NULL) {
        S_sha512_digest = EVP_MD_meth_new(NID_sha512, NID_undef);
        if (S_sha512_digest == NULL) {
            E_BCRYPT_osslerr(EVP_MD_meth_new, "Instantiating SHA-512 struct");
            goto done;
        }
        if (digest_sha_init(S_sha512_digest, NID_sha512) != 1)
            goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_digest_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    EVP_MD_meth_free(S_sha512_digest);
    S_sha512_digest = NULL;
    EVP_MD_meth_free(S_sha384_digest);
    S_sha384_digest = NULL;
    EVP_MD_meth_free(S_sha256_digest);
    S_sha256_digest = NULL;
    EVP_MD_meth_free(S_sha1_digest);
    S_sha1_digest = NULL;

    result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------ */
/* Function for querying digests              */
/* ------------------------------------------ */

int
e_bcrypt_digest_get(ENGINE *engine, const EVP_MD **digest, const int **nids,
                    int nid)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    /* Supported hashes */
    static int cng_digests_nids[] = {NID_sha1, NID_sha256, NID_sha384,
                                     NID_sha512};

    CMN_UNUSED(engine);

    /* Exactly one of them has to be non-null */
    CMN_DBG_PRECOND((digest == NULL) != (nids == NULL));

    if (digest == NULL) {
        *nids = cng_digests_nids;
        /* returns the number of registered digest algs */
        result = (sizeof(cng_digests_nids) / sizeof(*cng_digests_nids));
    } else {
        /* Helper variable for selecting the right pointer */
        const EVP_MD *ret_digest = NULL;
        switch (nid) {
        case NID_sha1:
            ret_digest = S_sha1_digest;
            break;
        case NID_sha256:
            ret_digest = S_sha256_digest;
            break;
        case NID_sha384:
            ret_digest = S_sha384_digest;
            break;
        case NID_sha512:
            ret_digest = S_sha512_digest;
            break;
        default:
            E_BCRYPT_err(e_bcrypt_digest_get, R_PASSED_UNKNOWN_VALUE,
                         "Received unknown digest nid value");
            goto done;
        }

        *digest = ret_digest;
        result = 1;
    }

done:
    CMN_DBG_API_LEAVE;
    return result;
}
