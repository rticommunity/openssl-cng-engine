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

#define CMN_THIS_FILE "src/s_ncrypt_rsa_key.c"

/* Interface */
#include "s_ncrypt_rsa_lcl.h"
#include "s_ncrypt_rsa.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt_err.h"
#include "s_ncrypt_x509_lcl.h" /* For finding the certificate */

/* OpenSSL */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* Standard includes */
#include <stdbool.h>

/* ------------------------ *
 * - RSA exdata functions - *
 * ------------------------ */

/* Private structure containing CNG details associated with this key */
struct ncrypt_rsa_key_data {
    NCRYPT_KEY_HANDLE key_handle;
};

#if 0

static void
rsa_key_data_new(
    void *parent,
    void *ptr,
    CRYPTO_EX_DATA *ad,
    int idx,
    long argl,
    void *argp)
{
    CMN_DBG_TRACE_ENTER;

    CMN_UNUSED(ad);

    CMN_DBG_ASSERT_NOT_NULL(parent); /* The newly allocated object */
    CMN_DBG_ASSERT(NULL == ptr); /* Current ex_data not inited yet */
    /* Checking whether the mechanism works as expected */
    CMN_DBG_ASSERT(idx == S_ex_index); 
    CMN_DBG_ASSERT(argl == S_argl);
    CMN_DBG_ASSERT(argp == S_argp);

    /* Nothing to be done at this point yet because the
       key needs to be created first. In stead, stuff happens via set_ex_data */

done:
    CMN_DBG_TRACE_LEAVE;
    return;
}
#endif

static void
rsa_key_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                  long argl, void *argp)
{
    CMN_DBG_TRACE_ENTER;

    SECURITY_STATUS ncrypt_retval;
    struct ncrypt_rsa_key_data *data = ptr;

    CMN_UNUSED(parent);
    CMN_UNUSED(ad);
    CMN_UNUSED(idx);
    CMN_UNUSED(argl);
    CMN_UNUSED(argp);

    if (data == NULL)
        goto done;

    ncrypt_retval = NCryptFreeObject(data->key_handle);
    if (NT_FAILED(ncrypt_retval)) {
        S_NCRYPT_winwarn(ncrypt_retval, NCryptFreeObject,
                         "Freeing RSA key handle");
    }

    CMN_free(data);

done:
    CMN_DBG_TRACE_LEAVE;
    return;
}

#if 0

static int
rsa_key_data_dup(
    CRYPTO_EX_DATA *to,
    const CRYPTO_EX_DATA *from,
    void *from_d,
    int idx,
    long argl,
    void *argp)
{
    int result = 0;
    struct ncrypt_rsa_key_data **data_ptr = (struct ncrypt_rsa_key_data **)from_d;

    if (*data_ptr != NULL) {
        struct ncrypt_rsa_key_data *data = CMN_malloc(sizeof(*data));
        if (data == NULL) {
            S_NCRYPT_osslerr(cng_rsa_key_data_dup, R_MALLOC_FAILED,
                "Constructing RSA key data");
            goto done;
        }

        /* TODO Copy contents */
        
        **data_ptr = data;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

#endif

/* Run this function once only */

static BOOL CALLBACK
ex_index_new(PINIT_ONCE initOnce, PVOID ex_index_out, /* int */
             LPVOID *ptr /* unused */)
{
    CMN_DBG_TRACE_ENTER;

    BOOL result = FALSE;
    int ex_index;

    CMN_UNUSED(initOnce);
    CMN_UNUSED(ptr);
    CMN_DBG_ASSERT_NOT_NULL(ex_index_out);

    /* This probably needs to be improved to implement dup and free */
    ex_index =
        RSA_get_ex_new_index(0, NULL, /* rsa_key_data_new */ NULL,
                             /* rsa_key_data_dup */ NULL, rsa_key_data_free);

    *((int *)ex_index_out) = ex_index;
    result = TRUE;

    /* done: */
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ex_index_get(int *ex_index_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static int s_ex_index = 0;

    if (!InitOnceExecuteOnce(&s_once, ex_index_new, &s_ex_index, NULL)) {
        DWORD last_err = GetLastError();
        S_NCRYPT_winerr(ex_index_get, last_err, InitOnceExecuteOnce,
                        "Executing once the RSA ex_index initialization");
        goto done;
    }

    *ex_index_out = s_ex_index;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
rsa_key_set_data(RSA *rsa_key, struct ncrypt_rsa_key_data *data)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int index;

    if (ex_index_get(&index) != 1)
        goto done;

    if (RSA_set_ex_data(rsa_key, index, data) != 1) {
        S_NCRYPT_osslerr(RSA_set_ex_data, "Setting RSA key data");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

struct ncrypt_rsa_key_data *
rsa_key_get_data(const RSA *rsa_key)
{
    CMN_DBG_TRACE_ENTER;

    struct ncrypt_rsa_key_data *result = NULL;
    struct ncrypt_rsa_key_data *data;
    int index;

    if (1 != ex_index_get(&index))
        goto done;

    data = RSA_get_ex_data(rsa_key, index);
    if (data == NULL) {
        S_NCRYPT_osslerr(RSA_get_ex_data, "Getting ex data for RSA");
        goto done;
    }

    result = data;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------- */
/* - CNG / OSSL helper functions - */
/* ------------------------------- */

static int
rsa_padding_type_to_flag(int padding_type, ULONG *flag_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_ASSERT_NOT_NULL(flag_out);

    switch (padding_type) {
    case RSA_NO_PADDING:
        *flag_out = BCRYPT_PAD_NONE;
        break;
    case RSA_PKCS1_PADDING:
        *flag_out = BCRYPT_PAD_PKCS1;
        break;
    case RSA_PKCS1_PSS_PADDING:
        *flag_out = BCRYPT_PAD_PSS;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        *flag_out = BCRYPT_PAD_OAEP;
        break;
    default:
        S_NCRYPT_err(rsa_padding_type_to_flag, R_INCORRECT_USAGE,
                     "Identifying flag for padding type");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
rsa_md_type_to_algorithm(int md_type, LPCWSTR *algorithm_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_ASSERT_NOT_NULL(algorithm_out);

    switch (md_type) {
    case NID_sha1:
        *algorithm_out = BCRYPT_SHA1_ALGORITHM;
        break;
    case NID_sha256:
        *algorithm_out = BCRYPT_SHA256_ALGORITHM;
        break;
    case NID_sha384:
        *algorithm_out = BCRYPT_SHA384_ALGORITHM;
        break;
    case NID_sha512:
        *algorithm_out = BCRYPT_SHA512_ALGORITHM;
        break;
    default:
        S_NCRYPT_err(rsa_md_type_to_algorithm, R_INCORRECT_USAGE,
                     "Identifying algorithm name for MD type");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static bool
rsa_ncrypt_private_to_ossl_public(NCRYPT_KEY_HANDLE priv_key, RSA **rsa_key_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;

    PCERT_PUBLIC_KEY_INFO key_info = NULL;
    RSA *rsa_key = NULL;
    DWORD len;
    DWORD actual_len;
    int key_nid;
    const unsigned char *obj_bytes;
    long obj_length;

    CMN_DBG_ASSERT(priv_key != NCRYPT_NULL);
    CMN_DBG_ASSERT_NOT_NULL(rsa_key_out);

    len = 0;
    if (!CryptExportPublicKeyInfo(priv_key, 0, X509_ASN_ENCODING, NULL, &len)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(rsa_ncrypt_private_to_ossl_public, last_error,
                        CryptExportPublicKeyInfo,
                        "Getting RSA key length from certificate");
        goto done;
    }

    key_info = CMN_malloc(len);
    if (key_info == NULL) {
        S_NCRYPT_err(rsa_ncrypt_private_to_ossl_public, R_MALLOC_FAILED,
                     "Allocating for CNG RSA public key object");
        goto done;
    }

    actual_len = len;
    if (!CryptExportPublicKeyInfo(priv_key, 0, X509_ASN_ENCODING, key_info,
                                  &actual_len)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(rsa_ncrypt_private_to_ossl_public, last_error,
                        CryptExportPublicKeyInfo,
                        "Exporting public RSA key from certificate");
        goto done;
    }
    CMN_DBG_ASSERT(actual_len <= len);

    key_nid = OBJ_txt2nid(key_info->Algorithm.pszObjId);
    if (key_nid != NID_rsaEncryption) {
        S_NCRYPT_osslerr(OBJ_txt2nid, "Getting NID for RSA algorithm ID");
        goto done;
    }

    /* Convert the CNG public key into its OpenSSL representation */
    obj_bytes = key_info->PublicKey.pbData;
    obj_length = key_info->PublicKey.cbData;
    if (d2i_RSAPublicKey(&rsa_key, &obj_bytes, obj_length) == NULL) {
        S_NCRYPT_osslerr(d2i_RSAPublicKey, "Deserializing RSA public key");
        goto done;
    }

    *rsa_key_out = rsa_key;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        RSA_free(rsa_key);
    }
    CMN_free(key_info);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------- */
/* - RSA Key methods related to signing - */
/* ------------------------------------- */

static int
ncrypt_rsa_key_sign(int md_type, const unsigned char *m, unsigned int m_length,
                    unsigned char *sigret, unsigned int *siglen_out,
                    const RSA *rsa_key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    struct ncrypt_rsa_key_data *key_data;
    NCRYPT_KEY_HANDLE h_private_key;
    SECURITY_STATUS cng_retval;
    ULONG cng_sig_len;
    LPCWSTR md_alg;
    ULONG padding_flag;
    PVOID padding_info;
    BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
#ifdef N_RSA_HAS_PSS
    BCRYPT_PSS_PADDING_INFO pss_info;
    const RSA_PSS_PARAMS *pss_params;
#endif

    /* Convert OpenSSL digest type to the BCrypt equivalent */
    if (rsa_md_type_to_algorithm(md_type, &md_alg) != 1)
        goto done;

#ifdef N_RSA_HAS_PSS
    /* Get PSS params, if available */
    pss_params = RSA_get0_pss_params(rsa_key);
    if (pss_params != NULL) {
        /* Note: this currently never happens in OpenSSL because its
         *   sign/verify implementation is broken */
        uint64_t salt_length;
        if (ASN1_INTEGER_get_uint64(&salt_length, pss_params->saltLength) !=
            1) {
            S_NCRYPT_osslerr(ASN1_INTEGER_get_uint64, "Converting salt length");
            goto done;
        }
        if (rsa_padding_type_to_flag(RSA_PKCS1_PSS_PADDING, &padding_flag) != 1)
            goto done;
        pss_info.pszAlgId = md_alg;
        pss_info.cbSalt = (ULONG)salt_length;
        padding_info = &pss_info;
    } else {
        /* No PSS, so plain PKCS1 */
        if (rsa_padding_type_to_flag(RSA_PKCS1_PADDING, &padding_flag) != 1)
            goto done;
        pkcs1_info.pszAlgId = md_alg;
        padding_info = &pkcs1_info;
    }
#else
    /* No PSS, so plain PKCS1 */
    if (rsa_padding_type_to_flag(RSA_PKCS1_PADDING, &padding_flag) != 1)
        goto done;
    pkcs1_info.pszAlgId = md_alg;
    padding_info = &pkcs1_info;
#endif
    key_data = rsa_key_get_data(rsa_key);
    h_private_key = key_data->key_handle;

    /* Query for the required length to verified it is not more than avaiable */
    cng_retval = NCryptSignHash(h_private_key, padding_info, (PBYTE)m, m_length,
                                NULL, 0, &cng_sig_len, padding_flag);
    if (FAILED(cng_retval)) {
        S_NCRYPT_winerr(ncrypt_rsa_key_sign, cng_retval, NCryptSignHash,
                        "Getting required length for signature object");
        goto done;
    }

    /* Do the signing */
    cng_retval =
        NCryptSignHash(h_private_key, padding_info, (PBYTE)m, m_length, sigret,
                       cng_sig_len, &cng_sig_len, padding_flag);
    if (FAILED(cng_retval)) {
        S_NCRYPT_winerr(ncrypt_rsa_key_sign, cng_retval, NCryptSignHash,
                        "Signing hash");
        goto done;
    }

    *siglen_out = cng_sig_len;
    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Public RSA Key functions */

static int
rsa_key_method_get(RSA_METHOD **method_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    static RSA_METHOD *s_method = NULL;

    CMN_DBG_PRECOND_NOT_NULL(method_out);

    if (s_method == NULL) {
        const RSA_METHOD *default_method;

        /* The default method is our starting point */
        default_method = RSA_get_default_method();
        if (default_method == NULL) {
            S_NCRYPT_osslerr(RSA_get_default_method,
                             "Obtaining default RSA KEY method");
            goto done;
        }

        /* Duplicate it for our use */
        s_method = RSA_meth_dup(default_method);
        if (s_method == NULL) {
            S_NCRYPT_osslerr(RSA_meth_dup,
                             "Duplicating default RSA KEY method");
            goto done;
        }
    }

    *method_out = s_method;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

RSA *
ncrypt_rsa_new(PCCERT_CONTEXT cert_ctx)
{
    CMN_DBG_TRACE_ENTER;

    RSA *result = NULL;
    RSA *rsa_key = NULL;
    RSA_METHOD *method;
    struct ncrypt_rsa_key_data *data;
    NCRYPT_KEY_HANDLE private_key_handle;

    /* Get private key handle from certificate */
    if (!ncrypt_x509_certificate_to_key(cert_ctx, &private_key_handle))
        goto done;

    /* Get EC point and curve from private key handle */
    if (!rsa_ncrypt_private_to_ossl_public(private_key_handle, &rsa_key))
        goto done;

    /* Use our methods, not the default ones */
    if (rsa_key_method_get(&method) != 1)
        goto done;
    if (RSA_set_method(rsa_key, method) != 1) {
        S_NCRYPT_osslerr(RSA_set_method,
                         "Setting ncrypt key method for RSA key");
        goto done;
    }

    /* Associate data with the key */
    data = CMN_malloc(sizeof(*data));
    if (data == NULL) {
        S_NCRYPT_err(ncrypt_ec_key_new, R_MALLOC_FAILED,
                     "Allocating RSA key data");
        goto done;
    }

    /* Store private key as handle */
    data->key_handle = private_key_handle;
    if (rsa_key_set_data(rsa_key, data) != 1)
        goto done;

    /* Success */
    result = rsa_key;

done:
    if (result == NULL) {
        RSA_free(rsa_key);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
ncrypt_rsa_free(RSA *rsa_key)
{
    CMN_DBG_TRACE_ENTER;

    CMN_DBG_PRECOND_NOT_NULL(rsa_key);

    RSA_free(rsa_key);

    CMN_DBG_TRACE_LEAVE;
    return;
}

/* ------------------------------------------ */
/* - Initialize and finalize the RSA module - */
/* ------------------------------------------ */

int
s_ncrypt_rsa_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    RSA_METHOD *method;

    if (rsa_key_method_get(&method) != 1)
        goto done;

    if (RSA_meth_set_sign(method, ncrypt_rsa_key_sign) != 1) {
        S_NCRYPT_osslerr(RSA_meth_set_sign, "Initializing RSA module");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
s_ncrypt_rsa_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    RSA_METHOD *method;

    if (rsa_key_method_get(&method) != 1)
        goto done;

    RSA_meth_free(method);

done:
    CMN_DBG_TRACE_LEAVE;
}
