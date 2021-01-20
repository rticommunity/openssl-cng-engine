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

#define CMN_THIS_FILE "src/s_ncrypt_x509.c"

/* Interface */
#include "s_ncrypt_x509_lcl.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt_ec_lcl.h"
#include "s_ncrypt_err.h"

/* OpenSSL */
#include <openssl/x509.h>

X509 *
ncrypt_x509_new(PCCERT_CONTEXT cert_ctx)
{
    CMN_DBG_TRACE_ENTER;

    X509 *result = NULL;
    X509 *x509_cert;
    unsigned char *cert_encoded;

    CMN_DBG_PRECOND_NOT_NULL(cert_ctx);

    /* Convert CNG cert to OpenSSL cert */
    cert_encoded = cert_ctx->pbCertEncoded;
    x509_cert = d2i_X509(NULL, &cert_encoded, cert_ctx->cbCertEncoded);
    if (x509_cert == NULL) {
        S_NCRYPT_osslerr(d2i_X509, "Converting CNG cert ot ossl cert");
        goto done;
    }

    result = x509_cert;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
ncrypt_x509_free(X509 *x509_cert)
{
    CMN_DBG_TRACE_ENTER;

    CMN_DBG_PRECOND_NOT_NULL(x509_cert);

    X509_free(x509_cert);

    CMN_DBG_TRACE_LEAVE;
}

bool
ncrypt_x509_certificate_to_key(PCCERT_CONTEXT cert_ctx,
                               NCRYPT_KEY_HANDLE *private_key_handle /* out */)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE prov_or_key_handle =
        (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)NULL;
    NCRYPT_KEY_HANDLE priv_key = (NCRYPT_KEY_HANDLE)NULL;
    DWORD key_flags;
    DWORD key_spec;
    BOOL key_free_required = false;

    CMN_DBG_PRECOND_NOT_NULL(cert_ctx);
    CMN_DBG_PRECOND(NCRYPT_NULL != private_key_handle);

    prov_or_key_handle = (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)NULL;

    key_flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
    /* Try to get the private key */
    if (!CryptAcquireCertificatePrivateKey(cert_ctx, key_flags, NULL,
                                           &prov_or_key_handle, &key_spec,
                                           &key_free_required)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(ncrypt_x509_certificate_to_key, last_error,
                        CryptAcquireCertificatePrivateKey,
                        "Acquiring private key from certificate");
        goto done;
    }
    if (key_spec != CERT_NCRYPT_KEY_SPEC) {
        CMN_DBG_ERROR("private key is not a CNG key");
        goto done;
    }
    priv_key = prov_or_key_handle;

    *private_key_handle = priv_key;
    result = true;

done:
    /* Roll back if needed */
    if (!result && key_free_required) {
        SECURITY_STATUS stat = NCryptFreeObject(prov_or_key_handle);
        if (NT_FAILED(stat)) {
            S_NCRYPT_winwarn(stat, NCryptFreeObject, "Freeing key handle");
        }
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static bool
add_x509_crl_to_store(HCERTSTORE cert_store, X509_CRL *crl)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    int buffer_size;
    BYTE *buffer = NULL;
    BYTE *ptr;
    int convert_size;

    buffer_size = i2d_X509_CRL(crl, NULL);
    if (buffer_size <= 0) {
        S_NCRYPT_osslerr(i2d_X509_CRL, "Getting size of converted X509 CRL");
        goto done;
    }

    buffer = CMN_malloc(buffer_size);
    if (buffer == NULL) {
        S_NCRYPT_err(add_x509_crl_to_store, R_MALLOC_FAILED,
                     "Allocating for CRL struct");
        goto done;
    }
    ptr = buffer;
    convert_size = i2d_X509_CRL(crl, &ptr);
    if (convert_size <= 0) {
        S_NCRYPT_osslerr(i2d_X509_CRL, "Converting X509 CRL");
        goto done;
    }
    CMN_DBG_ASSERT(convert_size == buffer_size);

    if (!CertAddEncodedCRLToStore(cert_store, X509_ASN_ENCODING, buffer,
                                  buffer_size, CERT_STORE_ADD_ALWAYS, NULL)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(add_x509_crl_to_store, last_error,
                        CertAddEncodedCertificateToStore,
                        "Adding X509 to store");
        goto done;
    }

    result = true;

done:
    CMN_free(buffer);
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static bool
add_x509_cert_to_store(HCERTSTORE cert_store, X509 *cert,
                       PCCERT_CONTEXT *ppcert /* optional out */)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    int buffer_size;
    BYTE *buffer = NULL;
    BYTE *ptr;
    int convert_size;

    buffer_size = i2d_X509(cert, NULL);
    if (buffer_size <= 0) {
        S_NCRYPT_osslerr(i2d_X509, "Getting size of cert struct");
        goto done;
    }

    buffer = CMN_malloc(buffer_size);
    if (buffer == NULL) {
        S_NCRYPT_err(add_x509_cert_to_store, R_MALLOC_FAILED,
                     "Allocating for X509 structure");
        goto done;
    }
    ptr = buffer;
    convert_size = i2d_X509(cert, &ptr);
    if (convert_size <= 0) {
        S_NCRYPT_osslerr(i2d_X509, "Serializing X509 cert struct");
        goto done;
    }
    CMN_DBG_ASSERT(convert_size == buffer_size);

    if (!CertAddEncodedCertificateToStore(cert_store, X509_ASN_ENCODING, buffer,
                                          buffer_size, CERT_STORE_ADD_ALWAYS,
                                          ppcert)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(add_x509_cert_to_store, last_error,
                        CertAddEncodedCertificateToStore,
                        "Converting X509 certificate");
        goto done;
    }

    result = true;

done:
    CMN_free(buffer);
    CMN_DBG_TRACE_LEAVE;
    return result;
}

bool
ncrypt_x509_verify_cert(HCERTSTORE store_handle, X509_STORE_CTX *x509_store_ctx,
                        int *result_out)
{
    CMN_DBG_TRACE_ENTER;

    X509 *the_cert;
    X509_STORE *x509_store;
    STACK_OF(X509_OBJECT) * objs;
    int objs_len;
    HCERTSTORE cert_store = NULL;
    PCCERT_CONTEXT first_cert_ctx = NULL;
    PCCERT_CHAIN_CONTEXT chain_ctx = NULL;
    CERT_CHAIN_PARA chain_para;
    DWORD chain_flags;
    DWORD cert_flags;
    int verify_result;

    bool result = false;

    CMN_UNUSED(store_handle);

    CMN_DBG_PRECOND_NOT_NULL(x509_store_ctx);
    CMN_DBG_PRECOND_NOT_NULL(result_out);

    /* Overall approach: create an in-memory CNG cert store,
        loop over all ossl certificates in the store_ctx
        and add all of them to the cert store. Then
        build the cert chain from the in-memory cert store */

    /* CNG memory cert store */
    cert_flags = CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG;
    cert_store =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NCRYPT_NULL, cert_flags, NULL);
    if (cert_store == NULL) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(ncrypt_x509_verify_cert, last_error, CertOpenStore,
                        "Verifying cert with store");
        goto done;
    }

    /* Get the certificate that needs to be checked */
    the_cert = X509_STORE_CTX_get0_cert(x509_store_ctx);
    if (the_cert == NULL) {
        S_NCRYPT_osslerr(X509_STORE_CTX_get0_cert, "Verifying cert with store");
        goto done;
    }
    if (!add_x509_cert_to_store(cert_store, the_cert, &first_cert_ctx))
        goto done;

    /* Get all objects from store */
    x509_store = X509_STORE_CTX_get0_store(x509_store_ctx);
    if (x509_store == NULL) {
        S_NCRYPT_osslerr(X509_STORE_CTX_get0_store,
                         "Verifying cert with store");
        goto done;
    }
    /* Get all objects from store and place them in the windows CERTSTORE */
    objs = X509_STORE_get0_objects(x509_store);
    if (objs == NULL) {
        S_NCRYPT_osslerr(X509_STORE_get0_objects, "Verifying cert with store");
        goto done;
    }
    /* Loop over , convert them to binary representation and
       add them to the cert store */
    objs_len = sk_X509_OBJECT_num(objs);
    for (int i = 0; i < objs_len; i++) {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        X509_LOOKUP_TYPE lu_type = X509_OBJECT_get_type(obj);
        switch (lu_type) {
        case X509_LU_X509: {
            X509 *cert = X509_OBJECT_get0_X509(obj);
            if (!add_x509_cert_to_store(cert_store, cert, NULL))
                goto done;
            break;
        }
        case X509_LU_CRL: {
            X509_CRL *crl = X509_OBJECT_get0_X509_CRL(obj);
            if (!add_x509_crl_to_store(cert_store, crl))
                goto done;
            break;
        }
        case X509_LU_NONE:
            S_NCRYPT_err(
                ncrypt_x509_verify_cert, R_PASSED_UNKNOWN_VALUE,
                "Unknown x509 object kind while verifying cert with store");
            goto done;
            break;
        }
        CMN_DBG_ASSERT_NOT_NULL(first_cert_ctx);
    }

    /* Try to build a verified chain */
    /* TODO:explore strong signing stuff later */
    memset(&chain_para, 0, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);
    /* TODO: set the proper verification flags, including for CRL */
    chain_flags = 0;
    /* Standard chain engines are HCCE_CURRENT_USER and HCCE_LOCAL_MACHINE */
    /* TODO: make chain engine configurable */
    if (!CertGetCertificateChain(HCCE_LOCAL_MACHINE, first_cert_ctx, NULL,
                                 cert_store, &chain_para, chain_flags, NULL,
                                 &chain_ctx)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(ncrypt_x509_verify_cert, last_error,
                        CertGetCertificateChain,
                        "Obtaining cert chain for verification");
        goto done;
    }
    CMN_DBG_ASSERT_NOT_NULL(chain_ctx);
    if (chain_ctx != NULL) {
        verify_result = (chain_ctx->TrustStatus.dwErrorStatus != 0 ? 0 : 1);
    } else {
        S_NCRYPT_err(ncrypt_x509_verify_cert, R_INTERNAL_ERROR,
                     "Verifying cert chain from store");
        goto done;
    }

    *result_out = verify_result;
    result = true;

done:
    if (chain_ctx != NULL) {
        CertFreeCertificateChain(chain_ctx);
    }
    if (first_cert_ctx != NULL) {
        if (!CertFreeCertificateContext(first_cert_ctx)) {
            DWORD last_error = GetLastError();
            S_NCRYPT_winwarn(last_error, CertFreeCertificateContext,
                             "Verifying cert with store");
        }
    }
    if (cert_store != NULL) {
        if (!CertCloseStore(cert_store, CERT_CLOSE_STORE_CHECK_FLAG)) {
            DWORD last_error = GetLastError();
            S_NCRYPT_winwarn(last_error, CertCloseStore,
                             "Verifying cert with store");
        }
    }
    CMN_DBG_TRACE_LEAVE;
    return result;
}
