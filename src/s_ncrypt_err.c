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

#define CMN_THIS_FILE "src/s_ncrypt_err.c"

/* Interface */
#include "s_ncrypt_err.h"

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
static ERR_STRING_DATA SNCRYPT_str_functions[] = {
    /* Special case: name of the library routines.
       This exact one has to be (and remain) the first element. */
    F_ERR_LIBNAME("NCrypt Engine routines"),

    /* s_ncrypt_ec.c */
    F_ERR_INIT(ec_key_data_dup), F_ERR_INIT(ec_key_data_free),
    F_ERR_INIT(ec_key_data_new), F_ERR_INIT(ec_key_get_data),
    F_ERR_INIT(ec_key_set_data), F_ERR_INIT(ec_ncrypt_private_to_ossl_public),
    F_ERR_INIT(ecdsa_sign_digest_sig), F_ERR_INIT(ex_index_get),
    F_ERR_INIT(ex_index_get_once), F_ERR_INIT(ncrypt_ec_key_free),
    F_ERR_INIT(ncrypt_ec_key_new), F_ERR_INIT(ncrypt_ec_key_sign),
    F_ERR_INIT(ncrypt_ec_key_sign_setup), F_ERR_INIT(ncrypt_ec_key_sign_sig),
    F_ERR_INIT(s_ncrypt_ec_finalize), F_ERR_INIT(s_ncrypt_ec_initialize),

    /* s_ncrypt_evp_pkey.c */
    F_ERR_INIT(ncrypt_evp_pkey_free), F_ERR_INIT(ncrypt_evp_pkey_new),

    /* s_ncrypt_loader.c */
    F_ERR_INIT(cng_blob_to_hexstr), F_ERR_INIT(cng_close_cert_store),
    F_ERR_INIT(cng_hexstr_to_blob), F_ERR_INIT(cng_info_name_from_store),
    F_ERR_INIT(cng_info_object_from_store), F_ERR_INIT(cng_load_next_name_info),
    F_ERR_INIT(cng_load_object_info), F_ERR_INIT(cng_open_cert_store),
    F_ERR_INIT(CRYPT_DATA_BLOB_finalize), F_ERR_INIT(ncrypt_close_key_store),
    F_ERR_INIT(ncrypt_cng_ctx_close), F_ERR_INIT(ncrypt_cng_ctx_ctrl),
    F_ERR_INIT(ncrypt_cng_ctx_eof), F_ERR_INIT(ncrypt_cng_ctx_error),
    F_ERR_INIT(ncrypt_cng_ctx_expect), F_ERR_INIT(ncrypt_cng_ctx_find),
    F_ERR_INIT(ncrypt_cng_ctx_load), F_ERR_INIT(ncrypt_cng_ctx_open),
    F_ERR_INIT(ncrypt_cng_loader_free), F_ERR_INIT(ncrypt_cng_loader_new),
    F_ERR_INIT(ncrypt_open_key_store), F_ERR_INIT(object_kind_from_alias),
    F_ERR_INIT(ossl_store_loader_ctx_finalize),
    F_ERR_INIT(s_ncrypt_loader_free), F_ERR_INIT(s_ncrypt_loader_new),
    F_ERR_INIT(storage_kind_from_alias), F_ERR_INIT(wprovider_name_from_alias),

    /* s_ncrypt_pkey.c */
    F_ERR_INIT(ncrypt_pkey_rsa_initialize), F_ERR_INIT(ncrypt_pkey_rsa_sign),
    F_ERR_INIT(rsa_pss_saltlen_normalized), F_ERR_INIT(s_ncrypt_pkey_finalize),
    F_ERR_INIT(s_ncrypt_pkey_get), F_ERR_INIT(s_ncrypt_pkey_initialize),

    /* s_ncrypt_rsa.c */
    F_ERR_INIT(ncrypt_rsa_key_sign), F_ERR_INIT(ncrypt_rsa_new),
    F_ERR_INIT(ncrypt_rsa_pss_sign_digest),
    F_ERR_INIT(rsa_md_type_to_algorithm),
    F_ERR_INIT(rsa_ncrypt_private_to_ossl_public),
    F_ERR_INIT(rsa_padding_type_to_flag), F_ERR_INIT(rsa_sign_digest),

    /* s_ncrypt_uri.c */
    F_ERR_INIT(do_lookup), F_ERR_INIT(ncrypt_uri_crack),
    F_ERR_INIT(ncrypt_uri_cracked_finalize),
    F_ERR_INIT(ncrypt_uri_lookup_query_value),
    F_ERR_INIT(ncrypt_uri_lookup_value), F_ERR_INIT(ncrypt_uri_uncrack),
    F_ERR_INIT(uri_duplicate_between), F_ERR_INIT(uri_find_next_dirsep),
    F_ERR_INIT(uri_is_dirsep), F_ERR_INIT(uri_is_empty),

    /* s_ncrypt_x509.c */
    F_ERR_INIT(add_x509_cert_to_store), F_ERR_INIT(add_x509_crl_to_store),
    F_ERR_INIT(ncrypt_x509_certificate_to_key), F_ERR_INIT(ncrypt_x509_free),
    F_ERR_INIT(ncrypt_x509_new), F_ERR_INIT(ncrypt_x509_verify_cert),

    /* Last element */
    F_ERR_SENTINEL};

/* The array not having the expected size results in C2466 */
/* One extra for the library name, one for the sentinel */
_STATIC_ASSERT(_countof(SNCRYPT_str_functions) == F_ERR_NCRYPT_COUNT + 2);

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
static ERR_STRING_DATA SNCRYPT_str_reasons[] = {
    /* Engine-related reasons */
    R_ERR_INIT(R_INCORRECT_USAGE, "Incorrect usage of the engine"),
    R_ERR_INIT(R_INTERNAL_ERROR, "Internal error encountered, possibly a bug"),
    R_ERR_INIT(R_MALLOC_FAILED, "Failed to allocate memory"),
    R_ERR_INIT(R_NOT_IMPLEMENTED, "Functionality not implemented (yet)"),
    R_ERR_INIT(R_NOT_SUPPORTED, "Feature or parameter not supported"),
    R_ERR_INIT(R_PASSED_UNKNOWN_VALUE, "Was passed an unknown value"),

    /* Failed Windows functions */
    R_ERR_INIT_WIN(CertAddEncodedCertificateToStore),
    R_ERR_INIT_WIN(CertAddEncodedCRLToStore), R_ERR_INIT_WIN(CertCloseStore),
    R_ERR_INIT_WIN(CertEnumCertificatesInStore),
    R_ERR_INIT_WIN(CertFindCertificateInStore),
    R_ERR_INIT_WIN(CertFreeCertificateChain),
    R_ERR_INIT_WIN(CertFreeCertificateContext),
    R_ERR_INIT_WIN(CertFreeCRLContext), R_ERR_INIT_WIN(CertGetCertificateChain),
    R_ERR_INIT_WIN(CertGetCertificateContextProperty),
    R_ERR_INIT_WIN(CertGetNameStringA), R_ERR_INIT_WIN(CertOpenStore),
    R_ERR_INIT_WIN(CryptAcquireCertificatePrivateKey),
    R_ERR_INIT_WIN(CryptBinaryToStringA),
    R_ERR_INIT_WIN(CryptExportPublicKeyInfo),
    R_ERR_INIT_WIN(CryptStringToBinaryA), R_ERR_INIT_WIN(InitOnceExecuteOnce),
    R_ERR_INIT_WIN(NCryptFreeBuffer), R_ERR_INIT_WIN(NCryptFreeObject),
    R_ERR_INIT_WIN(NCryptOpenStorageProvider), R_ERR_INIT_WIN(NCryptSignHash),

    /* Last element */
    R_ERR_SENTINEL};

/* The array not having the expected size results in C2466 */
/* One extra for the sentinel */
_STATIC_ASSERT(_countof(SNCRYPT_str_reasons) == (R_ERR_NCRYPT_COUNT + 1));

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
    CMN_DBG_ASSERT(SNCRYPT_str_functions[0].error == 0);
    SNCRYPT_str_functions[0].error = ERR_PACK(lib_code, 0, 0);

    ERR_load_strings(lib_code, SNCRYPT_str_functions);
    ERR_load_strings(lib_code, SNCRYPT_str_reasons);

    *((int *)lib_code_out) = lib_code;
    result = TRUE;
done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
err_ncrypt_lib_code_get(int *lib_code_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static int s_lib_code = 0;

    if (!InitOnceExecuteOnce(&s_once, err_lib_code_init, &s_lib_code, NULL)) {
        DWORD last_error = GetLastError();
        /* Debug warning only because we can not yet use the error mechanism */
        S_NCRYPT_winwarn(last_error, InitOnceExecuteOnce,
                         "Initializing error codes");
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
ERR_load_SNCRYPT_strings(void)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int lib_code;

    if (err_ncrypt_lib_code_get(&lib_code) != 1) {
        CMN_DBG_ERROR("Failed to load s_ncrypt error strings");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Not thread-safe */
int
ERR_unload_SNCRYPT_strings(void)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int tmp_res = 1;
    int lib_code;

    if (err_ncrypt_lib_code_get(&lib_code) != 1)
        goto done;

    /* Already unloaded before? */
    if (lib_code != 0) {
        if (ERR_unload_strings(lib_code, SNCRYPT_str_functions) != 1) {
            S_NCRYPT_osslerr(ERR_unload_strings,
                             "Unloading function error strings");
            tmp_res = 0;
        }
        if (ERR_unload_strings(lib_code, SNCRYPT_str_reasons) != 1) {
            S_NCRYPT_osslerr(ERR_unload_strings,
                             "Unloading reason error strings");
            tmp_res = 0;
        }
    }
    result = tmp_res;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

void
ERR_NCRYPT_error(enum err_ncrypt_func_code func_code,
                 enum err_ncrypt_reason_code reason_code, const char *file_name,
                 int line_no)
{
    CMN_DBG_API_ENTER;

    int lib_code;

    /* Prepare and detect issues */
    if (err_ncrypt_lib_code_get(&lib_code) != 1)
        goto done;
    if (lib_code == 0)
        goto done;

    /* Put the actual error */
    ERR_PUT_error(lib_code, F_ERR_FROM_ENUM(func_code),
                  R_ERR_FROM_ENUM(reason_code), file_name, line_no);

done:
    CMN_DBG_TRACE_LEAVE;
}

void
ERR_NCRYPT_winerror(enum err_ncrypt_func_code func_code,
                    enum err_ncrypt_reason_code reason_code, NTSTATUS retval,
                    const char *file_name, int line_no)
{
    CMN_DBG_API_ENTER;

    int lib_code;
    char buf[20] = {0}; /* Enough to hold retval in hex*/

    /* Prepare and check for issues */
    if (err_ncrypt_lib_code_get(&lib_code) != 1)
        goto done;
    if (lib_code == 0)
        goto done;

    /* Put the actual error, with some additional information */
    _itoa_s(retval, buf, sizeof(buf), 16);
    ERR_put_error(lib_code, F_ERR_FROM_ENUM(func_code),
                  R_ERR_FROM_ENUM(reason_code), file_name, line_no);
    ERR_add_error_data(4, "retval = 0x", buf,
                       ", msg = ", c_cmn_win_status_string(retval));

done:
    CMN_DBG_TRACE_LEAVE;
}
