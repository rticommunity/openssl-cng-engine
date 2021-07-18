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

#define CMN_THIS_FILE "src/e_bcrypt_err.c"

/* Interface */
#include "e_bcrypt_err.h"

/* Implementation */
#include "c_cmn.h"
#include "c_cmn_dbg.h"

/* OpenSSL headers */
#include <openssl/err.h>

/* Function error codes start at 100, to avoid clashes with
 * existing OpenSSL codes. */
#define F_ERR_START        (100)
#define F_ERR_FROM_ENUM(f) (F_ERR_START + f)
#define F_ERR(e, s)                                                            \
    {                                                                          \
        .error = e, .string = s                                                \
    }
#define F_ERR_LIBNAME(n) F_ERR(0, n)
#define F_ERR_SENTINEL   F_ERR(0, NULL)
#define F_ERR_INIT(f)    F_ERR(ERR_PACK(0, F_ERR_FROM_ENUM(F_##f), 0), #f)

/* The error data array is not const because the 0 lib values will be
 *   dynamically replaced with the next error library ID */

/* clang-format off */
static ERR_STRING_DATA EBCRYPT_str_functions[] =
{
    /* Special case: name of the library routines.
       This exact one has to be (and remain) the first element. */
    F_ERR_LIBNAME("BCrypt Engine routines"),

    /* e_bcrypt_cipher.c */
    F_ERR_INIT(alg_provider_aes_get),
    F_ERR_INIT(cipher_key_object_length),
    F_ERR_INIT(bcrypt_cipher_initialize),
    F_ERR_INIT(cipher_do_bcrypt),
    F_ERR_INIT(bcrypt_cipher_update),
    F_ERR_INIT(bcrypt_cipher_finalize),
    F_ERR_INIT(cipher_tag_len_valid),
    F_ERR_INIT(bcrypt_cipher_control),
    F_ERR_INIT(cipher_aes_gcm_init),
    F_ERR_INIT(cipher_aes_gcm_new),
    F_ERR_INIT(e_bcrypt_cipher_initialize),
    F_ERR_INIT(e_bcrypt_cipher_finalize),
    F_ERR_INIT(e_bcrypt_cipher_get),

    /* e_bcrypt_dh.c */
    F_ERR_INIT(alg_provider_dh_get),
    F_ERR_INIT(bcrypt_dh_compute_key),
    F_ERR_INIT(bcrypt_dh_generate_key),
    F_ERR_INIT(dh_bcrypt_release),
    F_ERR_INIT(dh_bcrypt_to_dh_ossl_private),
    F_ERR_INIT(dh_generate),
    F_ERR_INIT(dh_ossl_to_dh_bcrypt_private),
    F_ERR_INIT(dh_ossl_to_dh_bcrypt_public),
    F_ERR_INIT(e_bcrypt_dh_finalize),
    F_ERR_INIT(e_bcrypt_dh_get),
    F_ERR_INIT(e_bcrypt_dh_initialize),

    /* e_bcrypt_digest.c */
    F_ERR_INIT(alg_provider_sha1_get),
    F_ERR_INIT(alg_provider_hmac_sha1_get),
    F_ERR_INIT(alg_provider_sha256_get),
    F_ERR_INIT(alg_provider_hmac_sha256_get),
    F_ERR_INIT(alg_provider_sha384_get),
    F_ERR_INIT(alg_provider_hmac_sha384_get),
    F_ERR_INIT(alg_provider_sha512_get),
    F_ERR_INIT(alg_provider_hmac_sha512_get),
    F_ERR_INIT(bcrypt_digest_init),
    F_ERR_INIT(bcrypt_digest_update),
    F_ERR_INIT(bcrypt_digest_final),
    F_ERR_INIT(bcrypt_digest_copy),
    F_ERR_INIT(bcrypt_digest_cleanup),
    F_ERR_INIT(bcrypt_digest_control),
    F_ERR_INIT(digest_sha_init),
    F_ERR_INIT(e_bcrypt_digest_initialize),
    F_ERR_INIT(e_bcrypt_digest_finalize),
    F_ERR_INIT(e_bcrypt_digest_get),

    /* e_bcrypt_ec.c */
    F_ERR_INIT(alg_provider_ecdh_p256_get),
    F_ERR_INIT(alg_provider_ecdh_p384_get),
    F_ERR_INIT(alg_provider_ecdh_p521_get),
    F_ERR_INIT(alg_provider_ecdsa_p256_get),
    F_ERR_INIT(alg_provider_ecdsa_p384_get),
    F_ERR_INIT(alg_provider_ecdsa_p521_get),
    F_ERR_INIT(ecdsa_sig_bcrypt_to_ossl),
    F_ERR_INIT(ecdsa_sig_ossl_to_bcrypt),
    F_ERR_INIT(ec_ossl_to_ec_bcrypt),
    F_ERR_INIT(ec_ossl_to_ecdsa_bcrypt),
    F_ERR_INIT(ec_bcrypt_to_ec_ossl),
    F_ERR_INIT(ecpoint_ossl_to_ec_bcrypt),
    F_ERR_INIT(ecpoint_ossl_to_ecdh_bcrypt),
    F_ERR_INIT(ecpoint_ossl_to_ecdsa_bcrypt),
    F_ERR_INIT(ecdh_generate),
    F_ERR_INIT(ecdh_derive),
    F_ERR_INIT(ecdsa_sign_digest_sig),
    F_ERR_INIT(ecdsa_verify_signed_digest),
    F_ERR_INIT(ecdsa_verify_signed_digest_sig),
    F_ERR_INIT(bcrypt_ec_keygen),
    F_ERR_INIT(bcrypt_ec_compute_key),
    F_ERR_INIT(bcrypt_ec_sign),
    F_ERR_INIT(bcrypt_ec_sign_setup),
    F_ERR_INIT(bcrypt_ec_sign_sig),
    F_ERR_INIT(bcrypt_ec_verify),
    F_ERR_INIT(bcrypt_ec_verify_sig),
    F_ERR_INIT(e_bcrypt_ec_get),
    F_ERR_INIT(e_bcrypt_ec_initialize),
    F_ERR_INIT(e_bcrypt_ec_finalize),

    /* e_bcrypt_pkey.c */
    F_ERR_INIT(bcrypt_pkey_hmac_copy),
    F_ERR_INIT(bcrypt_pkey_hmac_signctx_init),
    F_ERR_INIT(bcrypt_pkey_hmac_signctx),
    F_ERR_INIT(bcrypt_pkey_hmac_ctrl),
    F_ERR_INIT(bcrypt_pkey_rsa_sign),
    F_ERR_INIT(bcrypt_pkey_rsa_verify),
    F_ERR_INIT(e_bcrypt_pkey_initialize),
    F_ERR_INIT(e_bcrypt_pkey_finalize),
    F_ERR_INIT(e_bcrypt_pkey_get),

    /* e_bcrypt_provider.c */
    F_ERR_INIT(alg_provider_open),

    /* e_bcrypt_rand.c */
    F_ERR_INIT(alg_provider_rng_get),
    F_ERR_INIT(bcrypt_rand_bytes),
    F_ERR_INIT(e_bcrypt_rand_initialize),
    F_ERR_INIT(e_bcrypt_rand_finalize),
    F_ERR_INIT(e_bcrypt_rand_get),

    /* e_bcrypt_rsa.c */
    F_ERR_INIT(alg_provider_rsa_get),
    F_ERR_INIT(bcrypt_rsa_finish),
    F_ERR_INIT(bcrypt_rsa_init),
    F_ERR_INIT(bcrypt_rsa_keygen),
    F_ERR_INIT(bcrypt_rsa_priv_dec),
    F_ERR_INIT(bcrypt_rsa_priv_enc),
    F_ERR_INIT(bcrypt_rsa_pss_sign_digest),
    F_ERR_INIT(bcrypt_rsa_pss_verify_digest),
    F_ERR_INIT(bcrypt_rsa_pub_dec),
    F_ERR_INIT(bcrypt_rsa_pub_enc),
    F_ERR_INIT(bcrypt_rsa_sign),
    F_ERR_INIT(bcrypt_rsa_verify),
    F_ERR_INIT(rsa_bcrypt_to_rsa_ossl_private),
    F_ERR_INIT(rsa_decrypt),
    F_ERR_INIT(rsa_encrypt),
    F_ERR_INIT(rsa_generate),
    F_ERR_INIT(rsa_md_type_to_algorithm),
    F_ERR_INIT(rsa_ossl_to_rsa_bcrypt_private),
    F_ERR_INIT(rsa_ossl_to_rsa_bcrypt_public),
    F_ERR_INIT(rsa_padding_type_to_flag),
    F_ERR_INIT(rsa_pss_saltlen_normalized),
    F_ERR_INIT(rsa_sign_digest),
    F_ERR_INIT(rsa_verify_digest),

    /* e_bcrypt_secret.c */
    F_ERR_INIT(secret_derive),

    /* Last element */
    F_ERR_SENTINEL
};
/* clang-format on */

/* The array not having the expected size results in C2466 */
/* One extra for the library name, one for the sentinel */
_STATIC_ASSERT(_countof(EBCRYPT_str_functions) == F_ERR_BCRYPT_COUNT + 2);

/* Reason error codes start at 100, to avoid clashes with
  * existing OpenSSL codes. */
#define R_ERR_START        (100)
#define R_ERR_FROM_ENUM(r) (R_ERR_START + r)
#define R_ERR(e, s)                                                            \
    {                                                                          \
        .error = e, .string = s                                                \
    }
#define R_ERR_SENTINEL    R_ERR(0, NULL)
#define R_ERR_INIT(r, d)  R_ERR(ERR_PACK(0, 0, R_ERR_FROM_ENUM(r)), d)
#define R_ERR_CODE_WIN(r) R_##r
#define R_ERR_INIT_WIN(r) R_ERR_INIT(R_ERR_CODE_WIN(r), #r " failed")

/* The error data array is not const because the 0 lib values will be
 *   dynamically replaced with the next error library ID */

/* clang-format off */
static ERR_STRING_DATA EBCRYPT_str_reasons[] =
{
    /* Engine-related reasons */
    R_ERR_INIT(R_INCORRECT_USAGE,      "Incorrect usage of the engine"),
    R_ERR_INIT(R_INTERNAL_ERROR,       "Internal error encountered"),
    R_ERR_INIT(R_MALLOC_FAILED,        "Failed to allocate memory"),
    R_ERR_INIT(R_NOT_IMPLEMENTED,      "Functionality not implemented (yet)"),
    R_ERR_INIT(R_NOT_SUPPORTED,        "Feature or parameter not supported"),
    R_ERR_INIT(R_PASSED_UNKNOWN_VALUE, "Was passed an unknown value"),

    /* Failed Windows functions */
    R_ERR_INIT_WIN(BCryptCreateHash),
    R_ERR_INIT_WIN(BCryptDecrypt),
    R_ERR_INIT_WIN(BCryptDeriveKey),
    R_ERR_INIT_WIN(BCryptDestroyHash),
    R_ERR_INIT_WIN(BCryptDestroyKey),
    R_ERR_INIT_WIN(BCryptDestroySecret),
    R_ERR_INIT_WIN(BCryptDuplicateHash),
    R_ERR_INIT_WIN(BCryptEncrypt),
    R_ERR_INIT_WIN(BCryptExportKey),
    R_ERR_INIT_WIN(BCryptFinalizeKeyPair),
    R_ERR_INIT_WIN(BCryptFinishHash),
    R_ERR_INIT_WIN(BCryptGenerateKeyPair),
    R_ERR_INIT_WIN(BCryptGenerateSymmetricKey),
    R_ERR_INIT_WIN(BCryptGenRandom),
    R_ERR_INIT_WIN(BCryptGetProperty),
    R_ERR_INIT_WIN(BCryptHashData),
    R_ERR_INIT_WIN(BCryptImportKeyPair),
    R_ERR_INIT_WIN(BCryptOpenAlgorithmProvider),
    R_ERR_INIT_WIN(BCryptSecretAgreement),
    R_ERR_INIT_WIN(BCryptSetProperty),
    R_ERR_INIT_WIN(BCryptSignHash),
    R_ERR_INIT_WIN(BCryptVerifySignature),
    R_ERR_INIT_WIN(InitOnceExecuteOnce),

    /* Last element */
    R_ERR_SENTINEL
};
/* clang-format on */

/* The array not having the expected size results in C2466 */
/* One extra for the sentinel */
_STATIC_ASSERT(_countof(EBCRYPT_str_reasons) == (R_ERR_BCRYPT_COUNT + 1));

/* Run this function once only */

static BOOL CALLBACK
err_lib_code_init(PINIT_ONCE initOnce, PVOID lib_code_out, /* int */
                  LPVOID *ptr /* unused */)
{
    CMN_DBG_TRACE_ENTER;

    BOOL result = FALSE;
    int lib_code;

    CMN_UNUSED(initOnce);
    CMN_UNUSED(ptr);

    CMN_DBG_ASSERT_NOT_NULL(lib_code_out);

    lib_code = ERR_get_next_error_library();
    if (lib_code == 0) {
        /* No error code available for this situation so debug only */
        CMN_DBG_ERROR("Can not get next error library");
        goto done;
    }

    /* Work around the fact that OpenSSL's error loading functions
     * do not seem to handle external libaries properly */
    CMN_DBG_ASSERT(EBCRYPT_str_functions[0].error == 0);
    EBCRYPT_str_functions[0].error = ERR_PACK(lib_code, 0, 0);

    ERR_load_strings(lib_code, EBCRYPT_str_functions);
    ERR_load_strings(lib_code, EBCRYPT_str_reasons);

    *((int *)lib_code_out) = lib_code;
    result = TRUE;
done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
err_bcrypt_lib_code_get(int *lib_code_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static int s_lib_code = 0;

    if (!InitOnceExecuteOnce(&s_once, err_lib_code_init, &s_lib_code, NULL)) {
        CMN_DBG_ERROR("err_lib_code_init failed with 0x%x", GetLastError());
        goto done;
    }

    if (s_lib_code == 0) {
        CMN_DBG_ERROR("Failed to get error library code");
        goto done;
    }

    *lib_code_out = s_lib_code;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
ERR_load_EBCRYPT_strings(void)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int lib_code;

    if (err_bcrypt_lib_code_get(&lib_code) != 1) {
        CMN_DBG_ERROR("Loading e_bcrypt error strings");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Not thread-safe */
int
ERR_unload_EBCRYPT_strings(void)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int tmp_res = 1;
    int lib_code;

    if (err_bcrypt_lib_code_get(&lib_code) != 1)
        goto done;
    if (lib_code == 0)
        goto done;

    if (ERR_unload_strings(lib_code, EBCRYPT_str_functions) != 1) {
        CMN_DBG_ERROR("Can not unload function error codes");
        tmp_res = 0;
    }
    if (ERR_unload_strings(lib_code, EBCRYPT_str_reasons) != 1) {
        CMN_DBG_ERROR("Can not unload reason error codes");
        tmp_res = 0;
    }

    result = tmp_res;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

void
ERR_BCRYPT_error(enum err_bcrypt_func_code func_code,
                 enum err_bcrypt_reason_code reason_code, const char *file_name,
                 int line_no)
{
    CMN_DBG_API_ENTER;

    int lib_code;

    if (err_bcrypt_lib_code_get(&lib_code) != 1)
        goto done;
    if (lib_code == 0)
        goto done;
    ERR_PUT_error(lib_code, F_ERR_FROM_ENUM(func_code),
                  R_ERR_FROM_ENUM(reason_code), file_name, line_no);

done:
    CMN_DBG_TRACE_LEAVE;
}

void
ERR_BCRYPT_winerror(enum err_bcrypt_func_code func_code,
                    enum err_bcrypt_reason_code reason_code, NTSTATUS retval,
                    const char *file_name, int line_no)
{
    CMN_DBG_API_ENTER;

    int lib_code;
    char buf[20] = {0}; /* Enough to hold retval in hex*/

    if (err_bcrypt_lib_code_get(&lib_code) != 1)
        goto done;
    if (lib_code == 0)
        goto done;

    _itoa_s(retval, buf, sizeof(buf), 16);
    ERR_put_error(lib_code, F_ERR_FROM_ENUM(func_code),
                  R_ERR_FROM_ENUM(reason_code), file_name, line_no);
    ERR_add_error_data(4, "retval = 0x", buf,
                       ", msg = ", c_cmn_win_status_string(retval));

done:
    CMN_DBG_TRACE_LEAVE;
}
