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

#pragma once

#include "c_cmn_win.h"
#include "c_cmn_dbg.h"
#include <openssl/err.h>

int
ERR_load_EBCRYPT_strings(void);

int
ERR_unload_EBCRYPT_strings(void);

/* Erorr function codes */
enum err_bcrypt_func_code {
    /* e_bcrypt_cipher.c */
    F_alg_provider_aes_get,
    F_cipher_key_object_length,
    F_bcrypt_cipher_initialize,
    F_cipher_do_bcrypt,
    F_bcrypt_cipher_update,
    F_bcrypt_cipher_finalize,
    F_cipher_tag_len_valid,
    F_bcrypt_cipher_control,
    F_cipher_aes_gcm_init,
    F_cipher_aes_gcm_new,
    F_e_bcrypt_cipher_initialize,
    F_e_bcrypt_cipher_finalize,
    F_e_bcrypt_cipher_get,

    /* e_bcrypt_dh.c */
    F_alg_provider_dh_get,
    F_bcrypt_dh_compute_key,
    F_bcrypt_dh_generate_key,
    F_dh_bcrypt_release,
    F_dh_bcrypt_to_dh_ossl_private,
    F_dh_generate,
    F_dh_ossl_to_dh_bcrypt_private,
    F_dh_ossl_to_dh_bcrypt_public,
    F_e_bcrypt_dh_finalize,
    F_e_bcrypt_dh_get,
    F_e_bcrypt_dh_initialize,

    /* e_bcrypt_digest.c */
    F_alg_provider_sha1_get,
    F_alg_provider_hmac_sha1_get,
    F_alg_provider_sha256_get,
    F_alg_provider_hmac_sha256_get,
    F_alg_provider_sha384_get,
    F_alg_provider_hmac_sha384_get,
    F_alg_provider_sha512_get,
    F_alg_provider_hmac_sha512_get,
    F_bcrypt_digest_init,
    F_bcrypt_digest_update,
    F_bcrypt_digest_final,
    F_bcrypt_digest_copy,
    F_bcrypt_digest_cleanup,
    F_bcrypt_digest_control,
    F_digest_sha_init,
    F_e_bcrypt_digest_initialize,
    F_e_bcrypt_digest_finalize,
    F_e_bcrypt_digest_get,

    /* e_bcrypt_ec.c */
    F_alg_provider_ecdh_p256_get,
    F_alg_provider_ecdh_p384_get,
    F_alg_provider_ecdh_p521_get,
    F_alg_provider_ecdsa_p256_get,
    F_alg_provider_ecdsa_p384_get,
    F_alg_provider_ecdsa_p521_get,
    F_ecdsa_sig_bcrypt_to_ossl,
    F_ecdsa_sig_ossl_to_bcrypt,
    F_ec_ossl_to_ec_bcrypt,
    F_ec_ossl_to_ecdsa_bcrypt,
    F_ec_bcrypt_to_ec_ossl,
    F_ecpoint_ossl_to_ec_bcrypt,
    F_ecpoint_ossl_to_ecdh_bcrypt,
    F_ecpoint_ossl_to_ecdsa_bcrypt,
    F_ecdh_generate,
    F_ecdh_derive,
    F_ecdsa_sign_digest_sig,
    F_ecdsa_verify_signed_digest,
    F_ecdsa_verify_signed_digest_sig,
    F_bcrypt_ec_keygen,
    F_bcrypt_ec_compute_key,
    F_bcrypt_ec_sign,
    F_bcrypt_ec_sign_setup,
    F_bcrypt_ec_sign_sig,
    F_bcrypt_ec_verify,
    F_bcrypt_ec_verify_sig,
    F_e_bcrypt_ec_get,
    F_e_bcrypt_ec_initialize,
    F_e_bcrypt_ec_finalize,

    /* e_bcrypt_pkey.c */
    F_bcrypt_pkey_hmac_copy,
    F_bcrypt_pkey_hmac_signctx_init,
    F_bcrypt_pkey_hmac_signctx,
    F_bcrypt_pkey_hmac_ctrl,
    F_e_bcrypt_pkey_initialize,
    F_e_bcrypt_pkey_finalize,
    F_e_bcrypt_pkey_get,

    /* e_bcrypt_provider.c */
    F_alg_provider_open,

    /* e_bcrypt_rand.c */
    F_alg_provider_rng_get,
    F_bcrypt_rand_bytes,
    F_e_bcrypt_rand_initialize,
    F_e_bcrypt_rand_finalize,
    F_e_bcrypt_rand_get,

    /* e_bcrypt_rsa.c */
    F_alg_provider_rsa_get,
    F_bcrypt_rsa_finish,
    F_bcrypt_rsa_init,
    F_bcrypt_rsa_keygen,
    F_bcrypt_rsa_priv_dec,
    F_bcrypt_rsa_priv_enc,
    F_bcrypt_rsa_pub_dec,
    F_bcrypt_rsa_pub_enc,
    F_bcrypt_rsa_sign,
    F_bcrypt_rsa_verify,
    F_rsa_bcrypt_to_rsa_ossl_private,
    F_rsa_decrypt,
    F_rsa_encrypt,
    F_rsa_generate,
    F_rsa_md_type_to_algorithm,
    F_rsa_ossl_to_rsa_bcrypt_private,
    F_rsa_ossl_to_rsa_bcrypt_public,
    F_rsa_padding_type_to_flag,
    F_rsa_sign_digest,
    F_rsa_verify_signed_digest,

    /* e_bcrypt_secret.c */
    F_secret_derive,

    /* Sentinel, keep at the end */
    F_ERR_BCRYPT_COUNT
};

/* Error reason codes */
#define R_WIN(f) R_##f
enum err_bcrypt_reason_code {
    /* Reasons for failure internal to this engine */
    R_INCORRECT_USAGE,
    R_INTERNAL_ERROR,
    R_NOT_IMPLEMENTED, /* as in: todo */
    R_NOT_SUPPORTED, /* as in: not scheduled to be supported (yet) */
    R_MALLOC_FAILED,
    R_PASSED_UNKNOWN_VALUE,

    /* Windows API functions that may fail */
    R_WIN(BCryptCreateHash),
    R_WIN(BCryptDecrypt),
    R_WIN(BCryptDeriveKey),
    R_WIN(BCryptDestroyHash),
    R_WIN(BCryptDestroyKey),
    R_WIN(BCryptDestroySecret),
    R_WIN(BCryptDuplicateHash),
    R_WIN(BCryptEncrypt),
    R_WIN(BCryptExportKey),
    R_WIN(BCryptFinalizeKeyPair),
    R_WIN(BCryptFinishHash),
    R_WIN(BCryptGenerateKeyPair),
    R_WIN(BCryptGenerateSymmetricKey),
    R_WIN(BCryptGenRandom),
    R_WIN(BCryptGetProperty),
    R_WIN(BCryptHashData),
    R_WIN(BCryptImportKeyPair),
    R_WIN(BCryptOpenAlgorithmProvider),
    R_WIN(BCryptSecretAgreement),
    R_WIN(BCryptSetProperty),
    R_WIN(BCryptSignHash),
    R_WIN(BCryptVerifySignature),
    R_WIN(InitOnceExecuteOnce),

    /* Sentinel, keep at the end */
    R_ERR_BCRYPT_COUNT
};
#undef R_WIN

void
ERR_BCRYPT_error(enum err_bcrypt_func_code func_code,
                 enum err_bcrypt_reason_code reason_code, const char *file_name,
                 int line_no);

void
ERR_BCRYPT_winerror(enum err_bcrypt_func_code func_code,
                    enum err_bcrypt_reason_code reason_code, NTSTATUS retval,
                    const char *file_name, int line_no);

/* For errors related to this engine
 * f = function name
 * r = reason code
 * d = description (string) of the error */
#define E_BCRYPT_err(f, r, d)                                                  \
    ERR_BCRYPT_error(F_##f, r, CMN_THIS_FILE, __LINE__);                       \
    CMN_DBG_ERROR("%s", d)

/* For errors invoking Windows API functions
 * f = calling function name
 * v = value returned by the failed call
 * w = called windows function name
 * d = description (string) of the error's context */
#define E_BCRYPT_winerr(f, v, w, d)                                            \
    do {                                                                       \
        NTSTATUS nt = v; /* Make the macro safe to use */                      \
        ERR_BCRYPT_winerror(F_##f, R_##w, nt, CMN_THIS_FILE, __LINE__);        \
        CMN_DBG_ERROR("Win API: %s failed (0x%x, \"%s\"): %s", #w, nt,         \
                      c_cmn_win_status_string(nt), d);                         \
    } while (0)

/* For warnings invoking Windows API functions
  * f = calling function name
  * v = value returned by the failed call
  * w = called windows function name
  * d = description (string) of the error's context */
#ifdef _DEBUG
#define E_BCRYPT_winwarn(v, w, d)                                              \
    do {                                                                       \
        NTSTATUS nt = v; /* Make the macro safe to use */                      \
        CMN_DBG_ERROR("Win API: %s failed (0x%x, \"%s\"): %s", #w, nt,         \
                      c_cmn_win_status_string(nt), d);                         \
    } while (0)
#endif
#ifdef NDEBUG
#define E_BCRYPT_winwarn(v, w, d) CMN_UNUSED(v)
#endif

/* For errors invoking OpenSSL functions
 * Note that we do not post the error with OpenSSL because the failed
 *   function is supposed to have done that already
 * o = called OpenSSL function name
 * d = description (string) of the error's context */
#define E_BCRYPT_osslerr(o, d)                                                 \
    CMN_DBG_ERROR("OpenSSL API: %s failed: %s", #o, d)
