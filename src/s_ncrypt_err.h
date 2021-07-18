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
ERR_load_SNCRYPT_strings(void);

int
ERR_unload_SNCRYPT_strings(void);

/* Erorr function codes */
enum err_ncrypt_func_code {
    /* s_ncrypt_ec.c */
    F_ec_key_data_dup,
    F_ec_key_data_free,
    F_ec_key_data_new,
    F_ec_key_get_data,
    F_ec_key_set_data,
    F_ec_ncrypt_private_to_ossl_public,
    F_ecdsa_sign_digest_sig,
    F_ex_index_get,
    F_ex_index_get_once,
    F_ncrypt_ec_key_free,
    F_ncrypt_ec_key_new,
    F_ncrypt_ec_key_sign,
    F_ncrypt_ec_key_sign_setup,
    F_ncrypt_ec_key_sign_sig,
    F_s_ncrypt_ec_finalize,
    F_s_ncrypt_ec_initialize,

    /* s_ncrypt_evp_pkey.c */
    F_ncrypt_evp_pkey_free,
    F_ncrypt_evp_pkey_new,

    /* s_ncrypt_loader.c */
    F_cng_blob_to_hexstr,
    F_cng_close_cert_store,
    F_cng_hexstr_to_blob,
    F_cng_info_name_from_store,
    F_cng_info_object_from_store,
    F_cng_load_next_name_info,
    F_cng_load_object_info,
    F_cng_open_cert_store,
    F_CRYPT_DATA_BLOB_finalize,
    F_ncrypt_close_key_store,
    F_ncrypt_cng_ctx_close,
    F_ncrypt_cng_ctx_ctrl,
    F_ncrypt_cng_ctx_eof,
    F_ncrypt_cng_ctx_error,
    F_ncrypt_cng_ctx_expect,
    F_ncrypt_cng_ctx_find,
    F_ncrypt_cng_ctx_load,
    F_ncrypt_cng_ctx_open,
    F_ncrypt_cng_loader_free,
    F_ncrypt_cng_loader_new,
    F_ncrypt_open_key_store,
    F_object_kind_from_alias,
    F_ossl_store_loader_ctx_finalize,
    F_s_ncrypt_loader_free,
    F_s_ncrypt_loader_new,
    F_storage_kind_from_alias,
    F_wprovider_name_from_alias,

    /* s_ncrypt_pkey.c */
    F_ncrypt_pkey_rsa_initialize,
    F_ncrypt_pkey_rsa_sign,
    F_rsa_pss_saltlen_normalized,
    F_s_ncrypt_pkey_finalize,
    F_s_ncrypt_pkey_get,
    F_s_ncrypt_pkey_initialize,

    /* s_ncrypt_rsa.c */
    F_ncrypt_rsa_key_sign,
    F_ncrypt_rsa_new,
    F_ncrypt_rsa_pss_sign_digest,
    F_rsa_md_type_to_algorithm,
    F_rsa_ncrypt_private_to_ossl_public,
    F_rsa_padding_type_to_flag,
    F_rsa_sign_digest,
    /* More to follow... */

    /* s_ncrypt_uri.c */
    F_do_lookup,
    F_ncrypt_uri_crack,
    F_ncrypt_uri_cracked_finalize,
    F_ncrypt_uri_lookup_query_value,
    F_ncrypt_uri_lookup_value,
    F_ncrypt_uri_uncrack,
    F_uri_duplicate_between,
    F_uri_find_next_dirsep,
    F_uri_is_dirsep,
    F_uri_is_empty,

    /* s_ncrypt_x509.c */
    F_add_x509_cert_to_store,
    F_add_x509_crl_to_store,
    F_ncrypt_x509_certificate_to_key,
    F_ncrypt_x509_free,
    F_ncrypt_x509_new,
    F_ncrypt_x509_verify_cert,

    /* Sentinel, keep at the end */
    F_ERR_NCRYPT_COUNT
};

/* Error reason codes */
#define R_WIN(f) R_##f
enum err_ncrypt_reason_code {
    /* Reasons for failure internal to this engine */
    R_INCORRECT_USAGE,
    R_INTERNAL_ERROR,
    R_NOT_IMPLEMENTED, /* as in: todo */
    R_NOT_SUPPORTED, /* as in: not scheduled to be supported (yet) */
    R_MALLOC_FAILED,
    R_PASSED_UNKNOWN_VALUE,

    /* Windows API functions that may fail */
    R_WIN(CertAddEncodedCertificateToStore),
    R_WIN(CertAddEncodedCRLToStore),
    R_WIN(CertCloseStore),
    R_WIN(CertEnumCertificatesInStore),
    R_WIN(CertFindCertificateInStore),
    R_WIN(CertFreeCertificateChain),
    R_WIN(CertFreeCertificateContext),
    R_WIN(CertFreeCRLContext),
    R_WIN(CertGetCertificateChain),
    R_WIN(CertGetCertificateContextProperty),
    R_WIN(CertGetNameStringA),
    R_WIN(CertOpenStore),
    R_WIN(CryptAcquireCertificatePrivateKey),
    R_WIN(CryptBinaryToStringA),
    R_WIN(CryptExportPublicKeyInfo),
    R_WIN(CryptStringToBinaryA),
    R_WIN(InitOnceExecuteOnce),
    R_WIN(NCryptFreeBuffer),
    R_WIN(NCryptFreeObject),
    R_WIN(NCryptOpenStorageProvider),
    R_WIN(NCryptSignHash),

    /* Sentinel, keep at the end */
    R_ERR_NCRYPT_COUNT
};
#undef R_WIN

void
ERR_NCRYPT_error(enum err_ncrypt_func_code func_code,
                 enum err_ncrypt_reason_code reason_code, const char *file_name,
                 int line_no);

void
ERR_NCRYPT_winerror(enum err_ncrypt_func_code func_code,
                    enum err_ncrypt_reason_code reason_code, NTSTATUS retval,
                    const char *file_name, int line_no);

/* For errors related to this engine
 * f = function name
 * r = reason code
 * d = description (string) of the error */
#define S_NCRYPT_err(f, r, d)                                                  \
    ERR_NCRYPT_error(F_##f, r, CMN_THIS_FILE, __LINE__);                       \
    CMN_DBG_ERROR("%s", d)

/* For errors invoking Windows API functions
 * f = calling function name
 * v = value returned by the failed call
 * w = called windows function name
 * d = description (string) of the error's context */
#define S_NCRYPT_winerr(f, v, w, d)                                            \
    do {                                                                       \
        NTSTATUS nt = v; /* Make the macro safe to use */                      \
        ERR_NCRYPT_winerror(F_##f, R_##w, nt, CMN_THIS_FILE, __LINE__);        \
        CMN_DBG_ERROR("Win API: %s failed (0x%x, \"%s\"): %s", #w, nt,         \
                      c_cmn_win_status_string(nt), d);                         \
    } while (0)

/* For warnings invoking Windows API functions
  * v = value returned by the failed call
  * w = called windows function name
  * d = description (string) of the error's context */
#ifdef _DEBUG
#define S_NCRYPT_winwarn(v, w, d)                                              \
    do {                                                                       \
        NTSTATUS nt = v; /* Make the macro safe to use */                      \
        CMN_DBG_ERROR("Win API: %s failed (0x%x, \"%s\"): %s", #w, nt,         \
                      c_cmn_win_status_string(nt), d);                         \
    } while (0)
#endif
#ifdef NDEBUG
#define S_NCRYPT_winwarn(v, w, d) CMN_UNUSED(v)
#endif

/* For errors invoking OpenSSL functions
 * Note that we do not post the error with OpenSSL because the failed
 *   function is supposed to have done that already
 * o = called OpenSSL function name
 * d = description (string) of the error's context */
#define S_NCRYPT_osslerr(o, d)                                                 \
    CMN_DBG_ERROR("OpenSSL API: %s failed: %s", #o, d)
