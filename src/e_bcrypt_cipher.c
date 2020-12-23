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

#define CMN_THIS_FILE "src/e_bcrypt_cipher.c"

/* Interface */
#include "e_bcrypt_cipher.h"

/* Implementation */
#include "e_bcrypt_err.h"
#include "e_bcrypt_provider.h"

/* Common header files */
#include "c_cmn.h"

/* OpenSSL implementation header files */
#include <openssl/evp.h>

/* Need to check for STATUS_AUTH_TAG_MISMATCH, defined here: */
#include <ntstatus.h>
#include <stdbool.h>

static int
alg_provider_aes_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_AES_GCM_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_aes_get, last_error, InitOnceExecuteOnce,
                        "AES-GCM one-time initialization");
        goto done;
    }
    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------- */
/* Functions that implement the cipher methods */
/* ------------------------------------------- */

/* -------------------------------- ciphers ---------------------------*/

#define BCRYPT_AES_GCM_BLOCK_LEN   (16)
#define BCRYPT_AES_GCM_MAX_TAG_LEN (16)
#define BCRYPT_AES_GCM_IV_LEN      (12)

/* Algorithm-specific data to be attached to the context */

typedef struct BCRYPT_CIPHER_CTX_st {
    BCRYPT_KEY_HANDLE key_handle; /* Opaque CNG handle*/
    BCRYPT_KEY_LENGTHS_STRUCT auth_tag_lens; /* Supported tag lenghts */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info; /* AEAD elements*/

    bool is_progressing; /* true in between Init() and Final() */
    /* Note: the IV deliberately has a size of BLOCK_LEN, not IV_LEN. This is
     *   because the algorithm needs extra space for the counter at the end */
    unsigned char iv[BCRYPT_AES_GCM_BLOCK_LEN]; /* Space for IV */
    size_t tag_len; /* Actual tag length */
    unsigned char tag[BCRYPT_AES_GCM_MAX_TAG_LEN]; /* Space for AEAD tag */
    unsigned char mac_context[BCRYPT_AES_GCM_MAX_TAG_LEN]; /* intermediate MAC */
    /* Buffer to keep bytes around that still need to be processed
     * (for example when chaining blocks of irregular sizes) */
    size_t waiting_current; /* Number of bytes still waiting to be processed */
    unsigned char waiting[BCRYPT_AES_GCM_BLOCK_LEN];

    /* Incomplete array at the end to hold the opaque CNG key object */
    /* key_object has length key_object_len, unknown at compile time */
    /* (and suppress VS warning about it) */
    ULONG key_object_len;
#pragma warning(suppress : 4200)
    BYTE key_object[/*key_object_len*/];
} BCRYPT_CIPHER_CTX;

static int
cipher_key_object_length(int *length_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_cipher_alg;
    ULONG bytes_used;
    DWORD wlength;

    CMN_DBG_PRECOND_NOT_NULL(length_out);

    /* Get the algorithm provider needed to query the property */
    if (alg_provider_aes_get(&h_cipher_alg) != 1)
        goto done;

    /* Calculate the size of the buffer to hold the cipher object */
    cng_retval =
        BCryptGetProperty(h_cipher_alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&wlength,
                          sizeof(wlength), &bytes_used, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(cipher_key_object_length, cng_retval, BCryptGetProperty,
                        "Getting length of cipher object");
        goto done;
    }

    /* Success, fill the results */
    *length_out = wlength;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
bcrypt_cipher_initialize(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_aes_alg = NULL;
    DWORD data_result_size;
    BCRYPT_CIPHER_CTX *gcm_ctx;

    CMN_UNUSED(enc);

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Get the bcrypt algorithm handle */
    if (alg_provider_aes_get(&h_aes_alg) != 1)
        goto done;

    /* Get our context, which should be allocated before this method is invoked */
    gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(gcm_ctx);

    /* This flag is reset after Final() is invoked */
    gcm_ctx->is_progressing = true;

    if (key != NULL) {
        int key_len;
        int object_len;

        /* Get the length of the key according to ossl */
        key_len = EVP_CIPHER_CTX_key_length(ctx);
        if (key_len <= 0) {
            E_BCRYPT_osslerr(EVP_CIPHER_CTX_key_length, "Initializing cipher");
            goto done;
        }

        /* Query the lenght of the CNG key object */
        if (cipher_key_object_length(&object_len) != 1)
            goto done;
        gcm_ctx->key_object_len = object_len;

        /* generate the key from supplied input key bytes */
        cng_retval = BCryptGenerateSymmetricKey(h_aes_alg, &gcm_ctx->key_handle,
                                                gcm_ctx->key_object,
                                                gcm_ctx->key_object_len,
                                                (PBYTE)key, key_len, 0);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(bcrypt_cipher_initialize, cng_retval,
                            BCryptGenerateSymmetricKey,
                            "Generating AES key from given bytes");
            goto done;
        }
    }

    /* get the size of the authentication tag */
    cng_retval =
        BCryptGetProperty(h_aes_alg, BCRYPT_AUTH_TAG_LENGTH,
                          (PBYTE)&gcm_ctx->auth_tag_lens,
                          sizeof(gcm_ctx->auth_tag_lens), &data_result_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(bcrypt_cipher_initialize, cng_retval, BCryptGetProperty,
                        "Getting auth tag length");
        goto done;
    }
    /* Double check we have enough space */
    if (gcm_ctx->auth_tag_lens.dwMaxLength > sizeof(gcm_ctx->tag)) {
        E_BCRYPT_err(bcrypt_cipher_initialize, R_INTERNAL_ERROR,
                     "Insufficient space for the auth tag");
        goto done;
    }
    /* Initialize tag_len to be the maximum size */
    gcm_ctx->tag_len = gcm_ctx->auth_tag_lens.dwMaxLength;

    BCRYPT_INIT_AUTH_MODE_INFO(gcm_ctx->auth_info);
    /* gcm_ctx->auth_info.cbSize already filled by init function */
    /* gcm_ctx->auth_info.dwInfoVersion filled by init function */

    /* Fill IV and set pointers to it */
    if (iv != NULL) {
        memcpy(gcm_ctx->iv, iv, BCRYPT_AES_GCM_IV_LEN);
    }
    gcm_ctx->auth_info.cbNonce = BCRYPT_AES_GCM_IV_LEN;
    gcm_ctx->auth_info.pbNonce = gcm_ctx->iv;

    /* No need to set the AEAD tag pointers here, that will happen in Final() */

    /* Double check we have enough space for the MAC context */
    if (gcm_ctx->auth_tag_lens.dwMaxLength > sizeof(gcm_ctx->mac_context)) {
        E_BCRYPT_err(bcrypt_cipher_initialize, R_INTERNAL_ERROR,
                     "Insufficient space for the MAC context");
        goto done;
    }
    /* And set them to point to the buffers in the ctx */
    gcm_ctx->auth_info.cbMacContext = gcm_ctx->auth_tag_lens.dwMaxLength;
    gcm_ctx->auth_info.pbMacContext = gcm_ctx->mac_context;

    gcm_ctx->auth_info.cbAAD = 0;
    gcm_ctx->auth_info.cbData = 0;
    gcm_ctx->auth_info.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG;

    gcm_ctx->waiting_current = 0;

    result = 1;
done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
cipher_do_bcrypt(BCRYPT_CIPHER_CTX *gcm_ctx, unsigned char *out,
                 const unsigned char *in, size_t inl, bool is_encrypting,
                 bool is_gmac_only, bool is_final)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG data_result_size;

    if (is_final) {
        gcm_ctx->auth_info.dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    } else {
        gcm_ctx->auth_info.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    }
    /* GMAC requires the data to be in the auth_info struct */
    if (is_gmac_only) {
        /* AAD is actually the entire plaintext */
        gcm_ctx->auth_info.pbAuthData = (unsigned char *)in;
        gcm_ctx->auth_info.cbAuthData = (ULONG)inl;
        in = NULL;
        inl = 0;
    }
    /* Set the tag info */
    gcm_ctx->auth_info.cbTag = (ULONG)gcm_ctx->tag_len;
    gcm_ctx->auth_info.pbTag = gcm_ctx->tag;

    /* Do the thing with the right function */
    if (is_encrypting) {
        cng_retval =
            BCryptEncrypt(gcm_ctx->key_handle, (unsigned char *)in, (ULONG)inl,
                          &gcm_ctx->auth_info, gcm_ctx->iv, sizeof(gcm_ctx->iv),
                          out, (ULONG)inl, &data_result_size, 0);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(cipher_do_bcrypt, cng_retval, BCryptEncrypt,
                            "Encrypting with AES-GCM");
            goto done;
        }
    } else {
        cng_retval =
            BCryptDecrypt(gcm_ctx->key_handle, (unsigned char *)in, (ULONG)inl,
                          &gcm_ctx->auth_info, gcm_ctx->iv, sizeof(gcm_ctx->iv),
                          out, (ULONG)inl, &data_result_size, 0);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(cipher_do_bcrypt, cng_retval, BCryptDecrypt,
                            "Decrypting with AES-GCM");
            goto done;
        }
    }
    CMN_DBG_ASSERT(inl == data_result_size);
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
bcrypt_cipher_update(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl)
{
    CMN_DBG_API_ENTER;

    /* Due to the flag EVP_CIPH_FLAG_CUSTOM_CIPHER, result -1 means failure and
     * otherwise the result value is equal to the number of bytes processed */
    int result = -1;
    BCRYPT_CIPHER_CTX *gcm_ctx;
    unsigned char *cur_out = out;
    const unsigned char *cur_in = in;
    size_t cur_inl = inl;
    size_t bulk_inl;
    size_t count = 0;
    bool is_final;
    bool is_gmac_only;
    bool is_encrypting;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Get our context, which should be allocated before this method is invoked */
    gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    CMN_DBG_ASSERT_NOT_NULL(gcm_ctx);

    /* Can only invoke this in between Init() and Final() */
    if (!gcm_ctx->is_progressing) {
        E_BCRYPT_err(bcrypt_cipher_update, R_INCORRECT_USAGE,
                     "Can not invoke Update() before Init() or after Final()");
        goto done;
    }

    is_final = (in == NULL);
    is_gmac_only = (out == NULL);
    is_encrypting = EVP_CIPHER_CTX_encrypting(ctx);

    /* Step 1: If we are still chaining, analyse the waiting room */
    if (!is_final) {
        /* Check how many bytes have not yet been processed */
        bool is_full_block =
            (gcm_ctx->waiting_current > 0) &&
            (gcm_ctx->waiting_current + cur_inl >= sizeof(gcm_ctx->waiting));
        /* Check whether with this new chunk the block size has exceeded. */
        if (is_full_block) {
            size_t head_len;

            /* Fill up the block */
            head_len = sizeof(gcm_ctx->waiting) - gcm_ctx->waiting_current;
            CMN_memcpy(&gcm_ctx->waiting[gcm_ctx->waiting_current], cur_in,
                       head_len);

            /* Do the de|encrypting */
            if (cipher_do_bcrypt(gcm_ctx, cur_out, gcm_ctx->waiting,
                                 sizeof(gcm_ctx->waiting), is_encrypting,
                                 is_gmac_only, is_final) != 1)
                goto done;

            /* Advance the administration to reflect this action */
            cur_out = &cur_out[sizeof(gcm_ctx->waiting)];
            cur_in = &cur_in[head_len];
            cur_inl -= head_len;
            count += sizeof(gcm_ctx->waiting);
            gcm_ctx->waiting_current = 0;
        }
    }

    /* Step 2: Process as much of the remaining input as possible. */
    if (is_final) {
        /* Process any bytes in the waiting room */
        cur_in = gcm_ctx->waiting;
        cur_inl = gcm_ctx->waiting_current;
        bulk_inl = cur_inl;
        /* Reset the waiting room */
        gcm_ctx->waiting_current = 0;
    } else {
        /* If we are chaining, only multiples of blocks can be processed */
        bulk_inl = cur_inl - (cur_inl % BCRYPT_AES_GCM_BLOCK_LEN);
    }

    if ((bulk_inl > 0) || is_final) {
        /* Do a en|decryption in bulk */
        if (cipher_do_bcrypt(gcm_ctx, cur_out, cur_in, bulk_inl, is_encrypting,
                             is_gmac_only, is_final) != 1)
            goto done;

        /* Update admin to reflect the processing */
        cur_out = &cur_out[bulk_inl];
        cur_in = &cur_in[bulk_inl];
        cur_inl -= bulk_inl;
        count += bulk_inl;
    }

    /* Step 3: If anything is remaining, store it in the waiting room. */
    if (cur_inl > 0) {
        /* We should not exceed the waiting room here */
        CMN_DBG_ASSERT(gcm_ctx->waiting_current + cur_inl <
                       sizeof(gcm_ctx->waiting));
        /* This can not happen when finalizing */
        CMN_DBG_ASSERT(!is_final);
        /* Copy the remainder, to be processed next time */
        CMN_memcpy(&gcm_ctx->waiting[gcm_ctx->waiting_current], cur_in,
                   cur_inl);
        gcm_ctx->waiting_current += cur_inl;
        /* Do not increase count, since these bytes did not get written out */
    }

    /* Keep track whether or not we are done yet */
    gcm_ctx->is_progressing = !is_final;
    result = (int)count;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_cipher_finalize(EVP_CIPHER_CTX *ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    BCRYPT_CIPHER_CTX *gcm_ctx = NULL;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Get our context, which should be allocated before this method is invoked */
    gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (gcm_ctx == NULL) {
        E_BCRYPT_err(bcrypt_cipher_finalize, R_INTERNAL_ERROR,
                     "Got NULL pointer for cipher data");
        goto done;
    }

    if (gcm_ctx->key_handle != NULL) {
        cng_retval = BCryptDestroyKey(gcm_ctx->key_handle);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying AES-GCM key");
        }
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static bool
cipher_tag_len_valid(const BCRYPT_CIPHER_CTX *gcm_ctx, size_t tag_len)
{
    CMN_DBG_TRACE_ENTER;

    bool result;
    BCRYPT_KEY_LENGTHS_STRUCT lens;

    CMN_DBG_PRECOND_NOT_NULL(gcm_ctx);

    lens = gcm_ctx->auth_tag_lens;
    result = (lens.dwMinLength <= tag_len) && (tag_len <= lens.dwMaxLength) &&
             (0 == ((tag_len - lens.dwMinLength) % lens.dwIncrement));

    /* done: */
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
bcrypt_cipher_control(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    size_t len;
    BCRYPT_CIPHER_CTX *gcm_ctx;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Get our context, which should be allocated before this method is invoked */
    gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (gcm_ctx == NULL) {
        E_BCRYPT_err(bcrypt_cipher_finalize, R_INTERNAL_ERROR,
                     "Got NULL pointer for cipher data");
        goto done;
    }

    switch (type) {
    case EVP_CTRL_INIT:
        /* Nothing to do at this moment... */
        break;
    case EVP_CTRL_GCM_GET_TAG:
        if (EVP_CIPHER_CTX_encrypting(ctx) != 1) {
            E_BCRYPT_err(bcrypt_cipher_control, R_INCORRECT_USAGE,
                         "Tag can only be requested when encrypting");
            goto done;
        }
        if (gcm_ctx->is_progressing) {
            E_BCRYPT_err(bcrypt_cipher_control, R_INCORRECT_USAGE,
                         "Tag can only be requested after Final()");
            goto done;
        }
        len = arg;
        if (!cipher_tag_len_valid(gcm_ctx, len)) {
            E_BCRYPT_err(bcrypt_cipher_control, R_INCORRECT_USAGE,
                         "Tag requested with invalid length");
            goto done;
        }
        CMN_memcpy(ptr, gcm_ctx->tag, len);
        break;
    case EVP_CTRL_GCM_SET_TAG:
        if (EVP_CIPHER_CTX_encrypting(ctx) == 1) {
            E_BCRYPT_err(bcrypt_cipher_control, R_INCORRECT_USAGE,
                         "Tag can only be provided when decrypting");
            goto done;
        }
        len = arg;
        if (!cipher_tag_len_valid(gcm_ctx, len)) {
            E_BCRYPT_err(bcrypt_cipher_control, R_INCORRECT_USAGE,
                         "Tag provided with invalid length");
            goto done;
        }
        gcm_ctx->tag_len = len;
        CMN_memcpy(gcm_ctx->tag, ptr, len);
        break;
    case EVP_CTRL_GCM_SET_IVLEN:
        E_BCRYPT_err(bcrypt_cipher_control, R_NOT_IMPLEMENTED,
                     "Setting of IV length is not implemented");
        goto done;
    default:
        E_BCRYPT_err(bcrypt_cipher_control, R_PASSED_UNKNOWN_VALUE,
                     "Was passed an unknown control type");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* ------------------------------------------------------------- */
/* Function that exposes the cipher methods to the outside world */
/* ------------------------------------------------------------- */

/* Cipher methods for AES-GCM */
static int
cipher_aes_gcm_init(EVP_CIPHER *cipher)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    unsigned long flags;
    int len;
    int ctx_size;

    flags = EVP_CIPH_GCM_MODE | EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER |
            EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV |
            EVP_CIPH_FLAG_FIPS | EVP_CIPH_FLAG_CUSTOM_CIPHER;
    if (cipher_key_object_length(&len) != 1)
        goto done;
    ctx_size = offsetof(BCRYPT_CIPHER_CTX, key_object) + len;

    /* All functions always return 1 so no use to check them */
    EVP_CIPHER_meth_set_iv_length(cipher, BCRYPT_AES_GCM_IV_LEN);
    EVP_CIPHER_meth_set_flags(cipher, flags);
    EVP_CIPHER_meth_set_impl_ctx_size(cipher, ctx_size);
    EVP_CIPHER_meth_set_init(cipher, bcrypt_cipher_initialize);
    EVP_CIPHER_meth_set_do_cipher(cipher, bcrypt_cipher_update);
    EVP_CIPHER_meth_set_cleanup(cipher, bcrypt_cipher_finalize);
    EVP_CIPHER_meth_set_ctrl(cipher, bcrypt_cipher_control);

    result = 1;
done:
    CMN_DBG_TRACE_LEAVE;
    return result;
};

static EVP_CIPHER *S_aes_gcm_128 = NULL;
static EVP_CIPHER *S_aes_gcm_192 = NULL;
static EVP_CIPHER *S_aes_gcm_256 = NULL;

static int
cipher_aes_gcm_new(int nid, EVP_CIPHER **cipher_inout)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int blocksize;
    int keylen;
    EVP_CIPHER *cipher = NULL;

    CMN_DBG_PRECOND_NOT_NULL(cipher_inout);

    /* Do not overwrite existing cipher */
    if (*cipher_inout == NULL) {
        switch (nid) {
        case NID_aes_128_gcm:
            keylen = 128 / 8;
            blocksize = 1;
            break;
        case NID_aes_192_gcm:
            keylen = 192 / 8;
            blocksize = 1;
            break;
        case NID_aes_256_gcm:
            keylen = 256 / 8;
            blocksize = 1;
            break;
        default:
            E_BCRYPT_err(cipher_aes_gcm_new, R_NOT_IMPLEMENTED,
                         "Cipher requested for non-implemented nid");
            goto done;
        }

        cipher = EVP_CIPHER_meth_new(nid, blocksize, keylen);
        if (cipher == NULL) {
            E_BCRYPT_osslerr(EVP_CIPHER_meth_new, "Instantiating cipher");
            goto done;
        }

        if (cipher_aes_gcm_init(cipher) != 1)
            goto done;
        *cipher_inout = cipher;
    }
    result = 1;

done:
    if (result != 1) {
        EVP_CIPHER_meth_free(cipher);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_cipher_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    if (cipher_aes_gcm_new(NID_aes_128_gcm, &S_aes_gcm_128) != 1)
        goto done;
    if (cipher_aes_gcm_new(NID_aes_192_gcm, &S_aes_gcm_192) != 1)
        goto done;
    if (cipher_aes_gcm_new(NID_aes_256_gcm, &S_aes_gcm_256) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_cipher_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    EVP_CIPHER_meth_free(S_aes_gcm_128);
    EVP_CIPHER_meth_free(S_aes_gcm_192);
    EVP_CIPHER_meth_free(S_aes_gcm_256);

    S_aes_gcm_128 = NULL;
    S_aes_gcm_192 = NULL;
    S_aes_gcm_256 = NULL;

    result = 1;

    /* done: */
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------ */
/* Function for querying cipher methods       */
/* ------------------------------------------ */

int
e_bcrypt_cipher_get(ENGINE *engine, const EVP_CIPHER **cipher, const int **nids,
                    int nid)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    /* Supported ciphers */
    static int cipher_nids[] = {NID_aes_128_gcm, NID_aes_192_gcm,
                                NID_aes_256_gcm};

    CMN_UNUSED(engine);

    /* Exactly one of them has to be non-null */
    CMN_DBG_PRECOND((cipher == NULL) != (nids == NULL));

    if (cipher == NULL) {
        *nids = cipher_nids;
        /* returns the number of registered cipher algs */
        result = (sizeof(cipher_nids) / sizeof(*cipher_nids));
    } else {
        /* Helper variable for selecting the right pointer */
        const EVP_CIPHER *ret_cipher = NULL;

        switch (nid) {
        case NID_aes_128_gcm:
            ret_cipher = S_aes_gcm_128;
            break;
        case NID_aes_192_gcm:
            ret_cipher = S_aes_gcm_192;
            break;
        case NID_aes_256_gcm:
            ret_cipher = S_aes_gcm_256;
            break;
        default:
            E_BCRYPT_err(e_bcrypt_cipher_get, R_INCORRECT_USAGE,
                         "Requested non-existing cipher method");
            goto done;
        }
        *cipher = ret_cipher;
        result = 1;
    }

done:
    CMN_DBG_API_LEAVE;
    return result;
}
