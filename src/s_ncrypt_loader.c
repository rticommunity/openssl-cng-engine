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

#define CMN_THIS_FILE "src/s_ncrypt_loader.c"

/* Interface */
#include "s_ncrypt_loader.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt.h"
#include "s_ncrypt_err.h"
#include "s_ncrypt_uri_lcl.h"
#include "s_ncrypt_evp_pkey_lcl.h"
#include "s_ncrypt_x509_lcl.h"

/* URI-related helpers, defined at the bottom of the file */
static bool
wprovider_name_from_alias(const char *provider_alias,
                          WCHAR **wprovider_name_out);
static bool
storage_kind_from_alias(const char *storage_kind_alias,
                        ncrypt_storage_kind *storage_kind_out);
static bool
object_kind_from_alias(const char *object_kind_alias,
                       ncrypt_object_kind *object_kind_out);

/* --------------------------------------- */
/* - CNG-aware helper funtions and types - */
/* --------------------------------------- */

#define CRYPT_DATA_BLOB_INITIALIZER                                            \
    {                                                                          \
        .cbData = 0, .pbData = NULL                                            \
    }

/* Only call this function on structs that were initialized with the
 * above initializer */
static void
CRYPT_DATA_BLOB_finalize(CRYPT_DATA_BLOB *blob_inout)
{
    if (blob_inout != NULL) {
        CMN_free(blob_inout->pbData);
        *blob_inout = (CRYPT_DATA_BLOB)CRYPT_DATA_BLOB_INITIALIZER;
    }
}

/* Converting a blob to a hex string */
static bool
cng_blob_to_hexstr(CRYPT_DATA_BLOB blob, char **hexstr_out)
{
    bool result = false;
    char *hexstr = NULL;
    DWORD length;
    DWORD actual_length;

    CMN_DBG_ASSERT_NOT_NULL(hexstr_out);

    /* Query how many characters this string will consist of (including the
     * nul terminator) */
    if (!CryptBinaryToString(blob.pbData, blob.cbData,
                             CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL,
                             &length)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_blob_to_hexstr, last_error, CryptBinaryToStringA,
                        "Getting hexstring length from binary");
        goto done;
    }
    /* Allocate the bytes to hold it all, including the nul-terminator */
    hexstr = CMN_malloc(length);
    if (hexstr == NULL) {
        S_NCRYPT_err(cng_blob_to_hexstr, R_MALLOC_FAILED,
                     "Allocating hexstring");
        goto done;
    }
    /* Get the string and verify the assumptions around the length */
    actual_length = length;
    if (!CryptBinaryToString(blob.pbData, blob.cbData,
                             CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, hexstr,
                             &actual_length)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_blob_to_hexstr, last_error, CryptBinaryToStringA,
                        "Getting hexstring length from binary");
        goto done;
    }
    /* This time, the nul terminator is not counted in actual_length */
    CMN_DBG_ASSERT((actual_length + 1) == length);

    *hexstr_out = hexstr;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        CMN_free(hexstr);
    }
    return result;
}

/* Converting a hexstring to a blob */
static bool
cng_hexstr_to_blob(const char *hexstr, CRYPT_DATA_BLOB *blob_out)
{
    bool result = false;
    CRYPT_DATA_BLOB blob = CRYPT_DATA_BLOB_INITIALIZER;
    DWORD length;

    if (!CryptStringToBinary(hexstr, 0 /* nul-term. */, CRYPT_STRING_HEX_ANY,
                             NULL /* get length */, &length, NULL, NULL)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_hexstr_to_blob, last_error, CryptStringToBinaryA,
                        "Getting hexstring length from binary");
        goto done;
    }

    blob.cbData = length;
    blob.pbData = CMN_malloc(blob.cbData);
    if (blob.pbData == NULL) {
        S_NCRYPT_err(cng_hexstr_to_blob, R_MALLOC_FAILED,
                     "Allocating blob bytes");
        goto done;
    }

    if (!CryptStringToBinary(hexstr, 0 /* nul-term. */, CRYPT_STRING_HEX_ANY,
                             blob.pbData, &blob.cbData, NULL, NULL)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_hexstr_to_blob, last_error, CryptStringToBinaryA,
                        "Converting hexstring to binary");
        goto done;
    }
    CMN_DBG_ASSERT(blob.cbData == length);

    *blob_out = blob;
    result = true;
done:
    /* Roll back if needed */
    if (!result) {
        CRYPT_DATA_BLOB_finalize(&blob);
    }
    return result;
}

/* State info for the CNG cert store */

struct cng_cert_store_st {
    /* Handle to the certificate store */
    HCERTSTORE store;
    /* An internal state maintained for enumerating over certs */
    PCCERT_CONTEXT cert_ctx;
    /* An internal state maintained for enumerating over crls */
    PCCRL_CONTEXT crl_ctx;
};
#define cng_cert_store_INITIALIZER                                             \
    {                                                                          \
        .store = NULL, .cert_ctx = NULL, .crl_ctx = NULL,                      \
    }

/* Helper function to do the CNG stuff for closing a certstore*/
static void
cng_close_cert_store(struct cng_cert_store_st *cert_store_inout)
{
    CMN_DBG_TRACE_ENTER;

    if (cert_store_inout != NULL) {
        if (cert_store_inout->crl_ctx != NULL) {
            if (!CertFreeCRLContext(cert_store_inout->crl_ctx)) {
                DWORD last_error = GetLastError();
                S_NCRYPT_winwarn(last_error, CertFreeCRLContext,
                                 "Freeing CRL context");
            }
        }
        if (cert_store_inout->cert_ctx != NULL) {
            if (!CertFreeCertificateContext(cert_store_inout->cert_ctx)) {
                DWORD last_error = GetLastError();
                S_NCRYPT_winwarn(last_error, CertFreeCertificateContext,
                                 "Freeing certificate context");
            }
        }
        if (cert_store_inout->store != NULL) {
            if (!CertCloseStore(cert_store_inout->store, 0)) {
                DWORD last_error = GetLastError();
                S_NCRYPT_winwarn(last_error, CertCloseStore,
                                 "Closing cert store");
            }
        }

        *cert_store_inout =
            (struct cng_cert_store_st)cng_cert_store_INITIALIZER;
    }

    CMN_DBG_TRACE_LEAVE;
}

/* Helper function to do the CNG stuff for opening a certstore*/
static bool
cng_open_cert_store(ncrypt_storage_kind storage_kind, const char *store_name,
                    struct cng_cert_store_st *cert_store_out)
{
    bool result = false;
    DWORD flags;
    struct cng_cert_store_st store = cng_cert_store_INITIALIZER;

    CMN_DBG_ASSERT_NOT_NULL(store_name);
    CMN_DBG_ASSERT_NOT_NULL(cert_store_out);

    flags = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG |
            CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG;
    switch (storage_kind) {
    case NCRYPT_STORAGE_KIND_LOCAL_MACHINE:
        flags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
        break;
    case NCRYPT_STORAGE_KIND_CURRENT_USER:
        flags |= CERT_SYSTEM_STORE_CURRENT_USER;
        break;
    case NCRYPT_STORAGE_KIND_UNKNOWN:
        S_NCRYPT_err(cng_open_cert_store, R_PASSED_UNKNOWN_VALUE,
                     "Improper storage kind");
        goto done;
        break;
    }

    /* Open the certificate store */
    store.store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0,
                                (HCRYPTPROV_LEGACY)NULL, flags, store_name);
    if (store.store == NULL) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_open_cert_store, last_error, CertOpenStore,
                        "Opening cert store");
        CMN_DBG_ERROR("unable to open certificate store \"%s\"", store_name);
        goto done;
    }

    *cert_store_out = store;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        cng_close_cert_store(&store);
    }
    return result;
}

#define CMN_SHA1_BYTES (20)
static OSSL_STORE_INFO *
cng_info_name_from_store(const char *storage_kind_alias, const char *store_name,
                         PCCERT_CONTEXT ctx)
{
    CMN_DBG_TRACE_ENTER;

    OSSL_STORE_INFO *result = NULL;
    OSSL_STORE_INFO *info = NULL;

    CRYPT_DATA_BLOB hash_blob = CRYPT_DATA_BLOB_INITIALIZER;
    DWORD length;
    DWORD type_param;
    DWORD retval;
    char *thumbprint = NULL;
    char *uri = NULL;
    char *description = NULL;

    CMN_DBG_PRECOND_NOT_NULL(storage_kind_alias);
    CMN_DBG_PRECOND_NOT_NULL(store_name);
    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Determine thumbprint (SHA-1 hash) of cert */
    if (!CertGetCertificateContextProperty(ctx, CERT_HASH_PROP_ID, NULL,
                                           &length)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_info_name_from_store, last_error,
                        CertGetCertificateContextProperty,
                        "Getting certificate thumbprint length");
        goto done;
    }
    hash_blob.cbData = length;
    hash_blob.pbData = CMN_malloc(hash_blob.cbData);
    if (hash_blob.pbData == NULL) {
        S_NCRYPT_err(cng_info_name_from_store, R_MALLOC_FAILED,
                     "Allocating memory for hash object");
        goto done;
    }
    if (!CertGetCertificateContextProperty(
            ctx, CERT_HASH_PROP_ID, hash_blob.pbData, &hash_blob.cbData)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(cng_info_name_from_store, last_error,
                        CertGetCertificateContextProperty,
                        "Getting certificate thumbprint");
        goto done;
    }
    CMN_DBG_ASSERT(length == hash_blob.cbData);

    /* Convert the hash blob into a character string */
    if (!cng_blob_to_hexstr(hash_blob, &thumbprint))
        goto done;

    /* Convert into a URI */
    if (!ncrypt_uri_uncrack(storage_kind_alias, store_name, thumbprint, &uri))
        goto done;

    /* This consumes uri */
    info = OSSL_STORE_INFO_new_NAME(uri);
    if (info == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_INFO_new_NAME,
                         "Creating new STORE_INFO structure");
        goto done;
    }

    /* Get length of the subject name */
    type_param = CERT_X500_NAME_STR;
    /* According to the documentation, this functions always returns 1 or larger */
    length =
        CertGetNameString(ctx, CERT_NAME_RDN_TYPE, 0, &type_param, NULL, 0);
    CMN_DBG_ASSERT(0 < length);
    description = CMN_malloc(length);
    if (description == NULL) {
        S_NCRYPT_err(cng_info_name_from_store, R_MALLOC_FAILED,
                     "Allocating for certificate RDN name");
        goto done;
    }
    retval = CertGetNameString(ctx, CERT_NAME_RDN_TYPE, 0, &type_param,
                               description, length);
    CMN_DBG_ASSERT(length == retval);

    /* This consumes description */
    if (OSSL_STORE_INFO_set0_NAME_description(info, description) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_INFO_set0_NAME_description,
                         "Setting the description of the STORE INFO");
        goto done;
    }

    result = info;

done:
    /* Roll back if needed*/
    if (result == NULL) {
        OSSL_STORE_INFO_free(info);
        CMN_free(description);
        CMN_free(uri);
    }
    CMN_free(thumbprint);
    CRYPT_DATA_BLOB_finalize(&hash_blob);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Enumerate to next object and return an associated INFO of type NAME */
static bool
cng_load_next_name_info(struct cng_cert_store_st *cert_store_inout,
                        const char *storage_kind_alias, const char *store_name,
                        ncrypt_object_kind kind_needed,
                        OSSL_STORE_INFO **info_out, bool *is_eof_out,
                        bool *had_error_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    OSSL_STORE_INFO *info = NULL;
    bool is_eof = false;
    bool had_error = false;
    PCCERT_CONTEXT cert_ctx = NULL;

    CMN_DBG_PRECOND_NOT_NULL(cert_store_inout);
    CMN_DBG_PRECOND_NOT_NULL(storage_kind_alias);
    CMN_DBG_PRECOND_NOT_NULL(store_name);
    CMN_DBG_PRECOND_NOT_NULL(info_out);
    CMN_DBG_PRECOND_NOT_NULL(is_eof_out);
    CMN_DBG_PRECOND_NOT_NULL(had_error_out);

    switch (kind_needed) {
    case NCRYPT_OBJECT_KIND_CERT:
        cert_ctx = CertEnumCertificatesInStore(cert_store_inout->store,
                                               cert_store_inout->cert_ctx);
        if (cert_ctx == NULL) {
            /* Did an error occur, or was eof reached? */
            DWORD last_error = GetLastError();
            if (last_error == CRYPT_E_NOT_FOUND) {
                is_eof = true;
            } else {
                S_NCRYPT_winwarn(last_error, CertEnumCertificatesInStore,
                                 "Walking over certs in store");
                had_error = true;
            }
        }
        break;
    case NCRYPT_OBJECT_KIND_PKEY:
        cert_ctx = CertFindCertificateInStore(
            cert_store_inout->store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_HAS_PRIVATE_KEY, NULL, cert_store_inout->cert_ctx);
        if (cert_ctx == NULL) {
            /* Did an error occur, or was eof reached? */
            DWORD last_error = GetLastError();
            if (last_error == CRYPT_E_NOT_FOUND) {
                is_eof = true;
            } else {
                S_NCRYPT_winwarn(last_error, CertFindCertificateInStore,
                                 "Finding certificate in store");
                had_error = true;
            }
        }
        break;
    case NCRYPT_OBJECT_KIND_CRL:
        S_NCRYPT_err(cng_load_next_name_info, R_NOT_SUPPORTED,
                     "Loading CRL object kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_PARAMS:
        S_NCRYPT_err(cng_load_next_name_info, R_NOT_SUPPORTED,
                     "Loading Params object kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_NAME:
        S_NCRYPT_err(cng_load_next_name_info, R_INTERNAL_ERROR,
                     "Unexpectedly asked to load object of Name kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_UNKNOWN:
        S_NCRYPT_err(cng_load_next_name_info, R_INTERNAL_ERROR,
                     "Asked to load object of unknown kind");
        goto done;
        break;
    }

    /* Does it make sense to move on? */
    if (!is_eof && !had_error) {
        /* Found a new cert, translate it into an INFO_NAME */
        info =
            cng_info_name_from_store(storage_kind_alias, store_name, cert_ctx);
        had_error = (info == NULL);
    }

    *info_out = info;
    *is_eof_out = is_eof;
    *had_error_out = had_error;
    result = true;

done:
    cert_store_inout->cert_ctx = cert_ctx;
    if (!result) {
        OSSL_STORE_INFO_free(info);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static OSSL_STORE_INFO *
cng_info_object_from_store(PCCERT_CONTEXT ctx, ncrypt_object_kind kind_needed)
{
    CMN_DBG_TRACE_ENTER;

    OSSL_STORE_INFO *result = NULL;
    OSSL_STORE_INFO *info = NULL;
    X509 *ossl_cert = NULL;
    EVP_PKEY *ossl_pkey = NULL;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* For now, only keys and certs supported */
    CMN_DBG_PRECOND((kind_needed == NCRYPT_OBJECT_KIND_CERT) ||
                    (kind_needed == NCRYPT_OBJECT_KIND_PKEY));

    switch (kind_needed) {
    case NCRYPT_OBJECT_KIND_CERT:
        ossl_cert = ncrypt_x509_new(ctx);
        if (ossl_cert == NULL)
            goto done;
        info = OSSL_STORE_INFO_new_CERT(ossl_cert);
        if (info == NULL) {
            S_NCRYPT_osslerr(OSSL_STORE_INFO_new_CERT,
                             "Creating new STORE INFO structure for cert");
            goto done;
        }
        break;
    case NCRYPT_OBJECT_KIND_PKEY:
        ossl_pkey = ncrypt_evp_pkey_new(ctx);
        if (ossl_pkey == NULL)
            goto done;
        info = OSSL_STORE_INFO_new_PKEY(ossl_pkey);
        if (info == NULL) {
            S_NCRYPT_osslerr(OSSL_STORE_INFO_new_PKEY,
                             "Creating new STORE INFO struct for PKEY");
            goto done;
        }
        break;
    case NCRYPT_OBJECT_KIND_CRL:
        S_NCRYPT_err(cng_info_object_from_store, R_NOT_SUPPORTED,
                     "Loading CRL object kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_PARAMS:
        S_NCRYPT_err(cng_info_object_from_store, R_NOT_SUPPORTED,
                     "Loading Params object kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_NAME:
        S_NCRYPT_err(cng_info_object_from_store, R_INTERNAL_ERROR,
                     "Unexpectedly asked to load object of Name kind");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_UNKNOWN:
        S_NCRYPT_err(cng_info_object_from_store, R_INTERNAL_ERROR,
                     "Asked to load object of unknown kind");
        goto done;
        break;
    }

    result = info;

done:
    /* Roll back if needed */
    if (result == NULL) {
        X509_free(ossl_cert);
        EVP_PKEY_free(ossl_pkey);
        OSSL_STORE_INFO_free(info);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static bool
cng_load_object_info(struct cng_cert_store_st *cert_store_inout,
                     const char *object_id, ncrypt_object_kind kind_needed,
                     OSSL_STORE_INFO **info_out, bool *is_eof_out,
                     bool *had_error_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    OSSL_STORE_INFO *info = NULL;
    bool is_eof = false;
    bool had_error = false;
    PCCERT_CONTEXT cert_ctx = NULL;
    CRYPT_DATA_BLOB hash_blob = CRYPT_DATA_BLOB_INITIALIZER;

    /* Find next cert by hash */
    CMN_DBG_PRECOND_NOT_NULL(cert_store_inout);
    CMN_DBG_PRECOND_NOT_NULL(info_out);
    CMN_DBG_PRECOND_NOT_NULL(is_eof_out);
    CMN_DBG_PRECOND_NOT_NULL(had_error_out);

    /* For now, only keys and certs supported */
    CMN_DBG_PRECOND((kind_needed == NCRYPT_OBJECT_KIND_CERT) ||
                    (kind_needed == NCRYPT_OBJECT_KIND_PKEY));

    /* The identifiers represents a hash (in the shape of a hexstring) */
    if (!cng_hexstr_to_blob(object_id, &hash_blob))
        goto done;
    /* Identifier is not malformed, look for a cert */
    cert_ctx = CertFindCertificateInStore(
        cert_store_inout->store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SHA1_HASH, &hash_blob, cert_store_inout->cert_ctx);
    if (cert_ctx == NULL) {
        /* Did an error occur, or was eof reached? */
        DWORD last_error = GetLastError();
        if (last_error == CRYPT_E_NOT_FOUND) {
            is_eof = true;
        } else {
            CMN_DBG_ERROR("Error 0x%x finding store object", last_error);
            had_error = true;
        }
    }

    if (!is_eof && !had_error) {
        info = cng_info_object_from_store(cert_ctx, kind_needed);
        if (info == NULL)
            goto done;
    }

    *info_out = info;
    *is_eof_out = is_eof;
    *had_error_out = had_error;
    result = true;

done:
    cert_store_inout->cert_ctx = cert_ctx;
    CRYPT_DATA_BLOB_finalize(&hash_blob);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

#if 0
/* Helper function to do the CNG stuff for opening a keystore*/
/* Currently not used, but keep it around for the future when an actual
 * key store mechanism is implemented */

struct ncrypt_key_store_st {
    NCRYPT_PROV_HANDLE provider;
    PVOID ctx;
};
#define ncrypt_key_store_INITIALIZER                                           \
    {                                                                          \
        .provider = (NCRYPT_PROV_HANDLE)NULL, .ctx = NULL                      \
    }


static void
ncrypt_close_key_store(
    struct ncrypt_key_store_st *store_inout)
{
    CMN_DBG_TRACE_ENTER;

    SECURITY_STATUS cng_retval;

    CMN_DBG_PRECOND_NOT_NULL(store_inout);

    if (store_inout->ctx != NULL) {
        cng_retval = NCryptFreeBuffer(store_inout->ctx);
        if (!NT_SUCCESS(cng_retval)) {
            S_NCRYPT_winerr(ncrypt_close_key_store, cng_retval,
                NCryptFreeBuffer, "Closing key store");
        }
        store_inout->ctx = NULL;
    }

    if (store_inout->provider != (NCRYPT_PROV_HANDLE)NULL) {
        cng_retval = NCryptFreeObject(store_inout->provider);
        if (!NT_SUCCESS(cng_retval)) {
            S_NCRYPT_winerr(ncrypt_close_key_store, cng_retval,
                NCryptFreeObject, "Closing store provider");
        }
        store_inout->provider = (NCRYPT_PROV_HANDLE)NULL;
    }
//done:
    CMN_DBG_TRACE_LEAVE;
}


static bool
ncrypt_open_key_store(
    const char *provider_alias,
    struct ncrypt_key_store_st *store_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    SECURITY_STATUS cng_retval;
    struct ncrypt_key_store_st store = ncrypt_key_store_INITIALIZER;
    WCHAR *provider_name = NULL;

    CMN_DBG_ASSERT_NOT_NULL(provider_alias);
    CMN_DBG_ASSERT_NOT_NULL(store_out);

    /* Get the actual provider name from the alias -- this has to be WCHAR * */
    if (!wprovider_name_from_alias(provider_alias, &provider_name)) goto done;

    /* Open the ckey store */
    cng_retval = NCryptOpenStorageProvider(&store.provider, provider_name, 0);
    if (!NT_SUCCESS(cng_retval)) {
        S_NCRYPT_winerr(ncrypt_open_key_store, cng_retval,
            NCryptOpenStorageProvider, "Opening key store");
    }

    *store_out = store;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        ncrypt_close_key_store(&store);
    }
    CMN_free(provider_name);

    CMN_DBG_TRACE_LEAVE;
    return result;
}
#endif

/* ------------------------------------- */
/* - No CNG awareness below this point - */
/* ------------------------------------- */

struct ossl_store_loader_ctx_st {
    struct ncrypt_uri_cracked_st uri;
    /* Object kind expected (if any, may be unknown) */
    ncrypt_object_kind object_kind_expected;
    /* True if enum or find has completed */
    bool is_eof;
    /* True if error has occurred during last load invocation */
    bool had_error;
    /* Store handles, pointers and states */
    struct cng_cert_store_st cert_store;
};
#define OSSL_STORE_LOADER_CTX_INITIALIZER                                      \
    {                                                                          \
        .uri = ncrypt_uri_cracked_INITIALIZER,                                 \
        .object_kind_expected = NCRYPT_OBJECT_KIND_UNKNOWN, .is_eof = false,   \
        .had_error = false, .cert_store = cng_cert_store_INITIALIZER           \
    }

/* Only call this function on structs that were initialized with the
 * above initializer */
static void
ossl_store_loader_ctx_finalize(OSSL_STORE_LOADER_CTX *ctx_inout)
{
    if (ctx_inout != NULL) {
        cng_close_cert_store(&ctx_inout->cert_store);
        ncrypt_uri_cracked_finalize(ctx_inout->uri);
        *ctx_inout = (OSSL_STORE_LOADER_CTX)OSSL_STORE_LOADER_CTX_INITIALIZER;
    }
}

/* ------------------------------------------ */
/* - Implementations of the store functions - */
/* ------------------------------------------ */

static OSSL_STORE_LOADER_CTX *
ncrypt_cng_ctx_open(const OSSL_STORE_LOADER *self, const char *uri,
                    const UI_METHOD *ui_method, void *ui_data)
{
    CMN_DBG_API_ENTER;

    OSSL_STORE_LOADER_CTX *result = NULL;
    struct ossl_store_loader_ctx_st ctx = OSSL_STORE_LOADER_CTX_INITIALIZER;
    ncrypt_storage_kind storage_kind;

    CMN_UNUSED(self);
    CMN_UNUSED(ui_method);
    CMN_UNUSED(ui_data);
    CMN_DBG_PRECOND_NOT_NULL(uri);

    /* Lookup alias value for object kind in URI and convert it to enum */
    if (!ncrypt_uri_crack(uri, &ctx.uri))
        goto done;

    /* Convert storage kind to enum */
    if (!storage_kind_from_alias(ctx.uri.storage_kind_alias, &storage_kind))
        goto done;

    /* With the elements from the URI, open the cert store */
    if (!cng_open_cert_store(storage_kind, ctx.uri.store_name, &ctx.cert_store))
        goto done;

    /* Create and initialize result ctx */
    result = CMN_malloc(sizeof(*result));
    if (result == NULL) {
        S_NCRYPT_err(ncrypt_cng_ctx_open, R_MALLOC_FAILED,
                     "Creating store ctx while opening");
        goto done;
    }

    *result = ctx;

done:
    /* Roll back if needed */
    if (result == NULL) {
        ossl_store_loader_ctx_finalize(&ctx);
    }

    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_cng_ctx_ctrl(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    switch (cmd) {
    case NCRYPT_CMD_VERIFY_CERT: {
        /*  */
        X509_STORE_CTX *x509_store_ctx = va_arg(args, X509_STORE_CTX *);
        int *result_out = va_arg(args, int *);
        if (!ncrypt_x509_verify_cert(ctx->cert_store.store, x509_store_ctx,
                                     result_out))
            goto done;
        break;
    }
    default:
        break;
    }

    result = 1;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_cng_ctx_expect(OSSL_STORE_LOADER_CTX *ctx, int expected)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    switch (expected) {
    case OSSL_STORE_INFO_CERT:
        ctx->object_kind_expected = NCRYPT_OBJECT_KIND_CERT;
        break;
    case OSSL_STORE_INFO_CRL:
        ctx->object_kind_expected = NCRYPT_OBJECT_KIND_CRL;
        break;
    case OSSL_STORE_INFO_PKEY:
        ctx->object_kind_expected = NCRYPT_OBJECT_KIND_PKEY;
        break;
    case OSSL_STORE_INFO_PARAMS:
        ctx->object_kind_expected = NCRYPT_OBJECT_KIND_PARAMS;
        break;
    }

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

/* Not implemented yet */
static int
ncrypt_cng_ctx_find(OSSL_STORE_LOADER_CTX *ctx, OSSL_STORE_SEARCH *criteria)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int search_type;

    CMN_UNUSED(ctx);

    search_type = OSSL_STORE_SEARCH_get_type(criteria);
    /* Currently none supported */
    switch (search_type) {
    case OSSL_STORE_SEARCH_BY_NAME:
        S_NCRYPT_err(ncrypt_cng_ctx_find, R_NOT_IMPLEMENTED,
                     "Searching in store by name");
        goto done;
        break;
    case OSSL_STORE_SEARCH_BY_ISSUER_SERIAL:
        S_NCRYPT_err(ncrypt_cng_ctx_find, R_NOT_IMPLEMENTED,
                     "Searching in store by issuer serial no");
        goto done;
        break;
    case OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT:
        S_NCRYPT_err(ncrypt_cng_ctx_find, R_NOT_IMPLEMENTED,
                     "Searching in store by key fingerprint");
        goto done;
        break;
    case OSSL_STORE_SEARCH_BY_ALIAS:
        S_NCRYPT_err(ncrypt_cng_ctx_find, R_NOT_IMPLEMENTED,
                     "Searching in store by alias");
        goto done;
        break;
    default:
        S_NCRYPT_err(ncrypt_cng_ctx_find, R_PASSED_UNKNOWN_VALUE,
                     "Searching in store using unknown search type");
        goto done;
        break;
    }

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static OSSL_STORE_INFO *
ncrypt_cng_ctx_load(OSSL_STORE_LOADER_CTX *ctx, const UI_METHOD *ui_method,
                    void *ui_data)
{
    CMN_DBG_API_ENTER;

    OSSL_STORE_INFO *result = NULL;
    OSSL_STORE_INFO *info = NULL;
    ncrypt_object_kind kind_queried;
    ncrypt_object_kind kind_needed;

    CMN_UNUSED(ui_method);
    CMN_UNUSED(ui_data);
    CMN_DBG_PRECOND_NOT_NULL(ctx);

    /* Reading beyond eof is considered an error */
    if (ctx->is_eof) {
        ctx->had_error = true;
        goto done;
    }

    /* Clear the error flag for this read */
    ctx->had_error = false;

    if (!object_kind_from_alias(ctx->uri.object_kind, &kind_queried))
        goto done;

    if (kind_queried == ctx->object_kind_expected) {
        /* No problem if queried and expected are the same */
        kind_needed = ctx->object_kind_expected;
    } else if (kind_queried == NCRYPT_OBJECT_KIND_UNKNOWN) {
        /* No object kind given in query, so has been given via expected */
        kind_needed = ctx->object_kind_expected;
    } else if (ctx->object_kind_expected == NCRYPT_OBJECT_KIND_UNKNOWN) {
        /* No object kind given via expected, so has been given in query */
        kind_needed = kind_queried;
    } else {
        /* Uh oh, queried and expected are of a different kind -> empty set */
        ctx->is_eof = true;
        goto done;
    }

    /* If kind needed is unknown at this point, it will default to certs */
    if (kind_needed == NCRYPT_OBJECT_KIND_UNKNOWN) {
        kind_needed = NCRYPT_OBJECT_KIND_CERT;
    }

    switch (kind_needed) {
    case NCRYPT_OBJECT_KIND_PKEY:
    case NCRYPT_OBJECT_KIND_CERT:
        if (ctx->uri.object_id == NULL) {
            /* Walking over all certs or keys */
            if (!cng_load_next_name_info(&ctx->cert_store,
                                         ctx->uri.storage_kind_alias,
                                         ctx->uri.store_name, kind_needed,
                                         &info, &ctx->is_eof, &ctx->had_error))
                goto done;
        } else {
            /* Find a specific cert or key */
            if (!cng_load_object_info(&ctx->cert_store, ctx->uri.object_id,
                                      kind_needed, &info, &ctx->is_eof,
                                      &ctx->had_error))
                goto done;
        }
        break;
    case NCRYPT_OBJECT_KIND_PARAMS:
        S_NCRYPT_err(ncrypt_cng_ctx_load, R_NOT_IMPLEMENTED,
                     "Loading key parameters info object");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_CRL:
        S_NCRYPT_err(ncrypt_cng_ctx_load, R_NOT_IMPLEMENTED,
                     "Loading CRL info object");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_NAME:
        S_NCRYPT_err(ncrypt_cng_ctx_load, R_INCORRECT_USAGE,
                     "Loading name info object");
        goto done;
        break;
    case NCRYPT_OBJECT_KIND_UNKNOWN:
        S_NCRYPT_err(ncrypt_cng_ctx_load, R_PASSED_UNKNOWN_VALUE,
                     "Loading unknown kind of info object");
        goto done;
        break;
    }

    result = info;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_cng_ctx_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    result = (ctx->is_eof ? 1 : 0);

    CMN_DBG_API_LEAVE;
    return result;
}

/* 1 means and error has occurred; 0 otherwise */
static int
ncrypt_cng_ctx_error(OSSL_STORE_LOADER_CTX *ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    result = (ctx->had_error ? 1 : 0);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_cng_ctx_close(OSSL_STORE_LOADER_CTX *ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(ctx);

    ossl_store_loader_ctx_finalize(ctx);
    CMN_free(ctx);

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

/* -------------------- *
 * - Public functions - *
 * -------------------- */

OSSL_STORE_LOADER *
ncrypt_cng_loader_new(ENGINE *engine)
{
    CMN_DBG_TRACE_ENTER;

    OSSL_STORE_LOADER *result = NULL;
    OSSL_STORE_LOADER *loader;

    loader = OSSL_STORE_LOADER_new(engine, NCRYPT_SCHEME);
    if (loader == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_new,
                         "Constructing STORE LOADER structure");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_open(loader, ncrypt_cng_ctx_open) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_open,
                         "Setting the open function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_ctrl(loader, ncrypt_cng_ctx_ctrl) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_ctrl,
                         "Setting the ctrl function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_expect(loader, ncrypt_cng_ctx_expect) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_expect,
                         "Setting the expect function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_find(loader, ncrypt_cng_ctx_find) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_find,
                         "Setting the find function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_load(loader, ncrypt_cng_ctx_load) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_load,
                         "Setting the load function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_eof(loader, ncrypt_cng_ctx_eof) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_eof,
                         "Setting the eof function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_error(loader, ncrypt_cng_ctx_error) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_error,
                         "Setting the error function of the STORE LOADER");
        goto done;
    }

    if (OSSL_STORE_LOADER_set_close(loader, ncrypt_cng_ctx_close) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_set_close,
                         "Setting the close function of the STORE LOADER");
        goto done;
    }

    result = loader;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
ncrypt_cng_loader_free(OSSL_STORE_LOADER *self, ENGINE *engine)
{
    CMN_DBG_TRACE_ENTER;

    CMN_UNUSED(engine);
    CMN_DBG_PRECOND_NOT_NULL(self);

    OSSL_STORE_LOADER_free(self);
    goto done;

done:
    CMN_DBG_TRACE_LEAVE;
    return;
}

/* ------------------------------------ *
 * - URI related conversion functions - *
 * ------------------------------------ */

static bool
storage_kind_from_alias(const char *storage_kind_alias,
                        ncrypt_storage_kind *storage_kind)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    ncrypt_storage_kind kind;

    CMN_DBG_PRECOND_NOT_NULL(storage_kind);

    if (storage_kind_alias == NULL) {
        S_NCRYPT_err(storage_kind_from_alias, R_INCORRECT_USAGE,
                     "Undefined (NULL) storage kind alias");
        goto done;
    }

    if (strcmp(storage_kind_alias, NCRYPT_STORAGE_KIND_VAL_CURRENT_USER) == 0) {
        kind = NCRYPT_STORAGE_KIND_CURRENT_USER;
        goto kind_found;
    }

    if (strcmp(storage_kind_alias, NCRYPT_STORAGE_KIND_VAL_LOCAL_MACHINE) ==
        0) {
        kind = NCRYPT_STORAGE_KIND_LOCAL_MACHINE;
        goto kind_found;
    }

    S_NCRYPT_err(storage_kind_from_alias, R_INCORRECT_USAGE,
                 "Converting unknown alias to storage kind");
    CMN_DBG_ERROR("Unknown storage kind alias \"%s\"", storage_kind_alias);
    goto done;

kind_found:
    *storage_kind = kind;
    result = true;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Converts a symbolic (string) namd for an object kind into its enum.
 * Returns true if the name is a known alias, or NULL (which will result
 * in object kind UNKNOWN). False otherwise. */
static bool
object_kind_from_alias(const char *object_kind_alias,
                       ncrypt_object_kind *object_kind_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    ncrypt_object_kind kind;

    CMN_DBG_PRECOND_NOT_NULL(object_kind_out);

    if (object_kind_alias == NULL) {
        kind = NCRYPT_OBJECT_KIND_UNKNOWN;
        goto kind_found;
    }

    if (strcmp(object_kind_alias, NCRYPT_OBJECT_KIND_VAL_PKEY) == 0) {
        kind = NCRYPT_OBJECT_KIND_PKEY;
        goto kind_found;
    }

    if (strcmp(object_kind_alias, NCRYPT_OBJECT_KIND_VAL_PARAMS) == 0) {
        kind = NCRYPT_OBJECT_KIND_PARAMS;
        goto kind_found;
    }

    if (strcmp(object_kind_alias, NCRYPT_OBJECT_KIND_VAL_CERT) == 0) {
        kind = NCRYPT_OBJECT_KIND_CERT;
        goto kind_found;
    }

    if (strcmp(object_kind_alias, NCRYPT_OBJECT_KIND_VAL_CRL) == 0) {
        kind = NCRYPT_OBJECT_KIND_CRL;
        goto kind_found;
    }

    /* Note that there is no alias for NAME */

    S_NCRYPT_err(storage_kind_from_alias, R_INCORRECT_USAGE,
                 "Converting unknown alias to object kind");
    CMN_DBG_ERROR("Unknown object kind alias \"%s\"", object_kind_alias);
    goto done;

kind_found:
    *object_kind_out = kind;
    result = true;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------------- */
/* Public functions: constructor and destructor      */
/* ------------------------------------------------- */

/* Constructor */
OSSL_STORE_LOADER *
s_ncrypt_loader_new(ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    OSSL_STORE_LOADER *result = NULL;
    OSSL_STORE_LOADER *loader;

    /* Create the loader for the cng scheme */
    loader = ncrypt_cng_loader_new(engine);
    if (loader == NULL)
        goto done;

    /* Register the loader for the cng scheme */
    if (OSSL_STORE_register_loader(loader) != 1) {
        S_NCRYPT_osslerr(OSSL_STORE_register_loader,
                         "Registering newly created loader");
        goto done;
    }

    result = loader;

done:
    CMN_DBG_API_LEAVE;
    return result;
}

/* Destructor */
void
s_ncrypt_loader_free(OSSL_STORE_LOADER *self, ENGINE *engine)
{
    CMN_DBG_API_ENTER;

    OSSL_STORE_LOADER *loader;
    const char *scheme;

    CMN_DBG_PRECOND_NOT_NULL(self);

    CMN_DBG_ASSERT(engine == OSSL_STORE_LOADER_get0_engine(self));

    scheme = OSSL_STORE_LOADER_get0_scheme(self);
    if (scheme == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_LOADER_get0_scheme,
                         "Getting scheme to unregister");
        goto done;
    }
    loader = OSSL_STORE_unregister_loader(scheme);
    if (loader == NULL) {
        S_NCRYPT_osslerr(OSSL_STORE_unregister_loader, "Unregistering loader");
        goto done;
    }
    CMN_DBG_ASSERT(loader == self);

    ncrypt_cng_loader_free(self, engine);

done:
    CMN_DBG_API_LEAVE;
}
