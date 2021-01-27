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

#define CMN_THIS_FILE "src/s_ncrypt_ec_key.c"

/* Interface */
#include "s_ncrypt_ec_lcl.h"
#include "s_ncrypt_ec.h"

/* Implementation */
#include "c_cmn.h"
#include "s_ncrypt_err.h"
#include "s_ncrypt_x509_lcl.h" /* For finding the certificate */

/* OpenSSL */
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h> /* for the nids */

/* Standard includes */
#include <stdbool.h>

/* --------------------------- *
 * - EC KEY exdata functions - *
 * --------------------------- */

/* Private structure containing CNG details associated with this key */
struct ncrypt_ec_key_data {
    NCRYPT_KEY_HANDLE key_handle;
};

#if 0

static void
ec_key_data_new(
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
ec_key_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                 long argl, void *argp)
{
    CMN_DBG_TRACE_ENTER;

    SECURITY_STATUS ncrypt_retval;
    struct ncrypt_ec_key_data *data = ptr;

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
                         "Freeing EC key handle");
    }

    CMN_free(data);

done:
    CMN_DBG_TRACE_LEAVE;
    return;
}

#if 0

static int
ec_key_data_dup(
    CRYPTO_EX_DATA *to,
    const CRYPTO_EX_DATA *from,
    void *from_d,
    int idx,
    long argl,
    void *argp)
{
    int result = 0;
    struct ncrypt_ec_key_data **data_ptr = (struct ncrypt_ec_key_data **)from_d;

    if (*data_ptr != NULL) {
        struct ncrypt_ec_key_data *data;
        if (NULL == (data = CMN_malloc(sizeof(*data)))) {
            S_NCRYPT_err(ec_key_data_dup, "Allocating duplicate key")
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
        EC_KEY_get_ex_new_index(0, NULL, /* ec_key_data_new */ NULL,
                                /* ec_key_data_dup */ NULL, ec_key_data_free);

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
                        "Executing once the EC ex_index initialization");
        goto done;
    }

    *ex_index_out = s_ex_index;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ec_key_set_data(EC_KEY *ec_key, struct ncrypt_ec_key_data *data)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int index;
    int retval;

    if (ex_index_get(&index) != 1)
        goto done;

    retval = EC_KEY_set_ex_data(ec_key, index, data);
    if (retval != 1) {
        S_NCRYPT_osslerr(EC_KEY_set_ex_data, "Setting ex data for EC");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

struct ncrypt_ec_key_data *
ec_key_get_data(EC_KEY *ec_key)
{
    CMN_DBG_TRACE_ENTER;

    struct ncrypt_ec_key_data *result = NULL;
    struct ncrypt_ec_key_data *data;
    int index;

    if (ex_index_get(&index) != 1)
        goto done;

    data = EC_KEY_get_ex_data(ec_key, index);
    if (data == NULL) {
        S_NCRYPT_osslerr(EC_KEY_get_ex_data, "Getting ex data for EC");
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

static bool
ec_ncrypt_private_to_ossl_public(NCRYPT_KEY_HANDLE priv_key,
                                 EC_KEY **ec_key_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    int curve_nid;

    ASN1_OBJECT *obj_id = NULL;
    PCERT_PUBLIC_KEY_INFO key_info = NULL;
    DWORD len;
    DWORD actual_len;
    int key_nid;
    const unsigned char *obj_bytes;
    long obj_length;

    CMN_DBG_ASSERT(NCRYPT_NULL != priv_key);
    CMN_DBG_ASSERT_NOT_NULL(ec_key_out);

    len = 0;
    if (!CryptExportPublicKeyInfo(priv_key, 0, X509_ASN_ENCODING, NULL, &len)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(ec_ncrypt_private_to_ossl_public, last_error,
                        CryptExportPublicKeyInfo,
                        "Getting EC key length from certificate");
        goto done;
    }

    key_info = CMN_malloc(len);
    if (key_info == NULL) {
        S_NCRYPT_err(ec_ncrypt_private_to_ossl_public, R_MALLOC_FAILED,
                     "Allocating for CNG EC public key object");
        goto done;
    }

    actual_len = len;
    if (!CryptExportPublicKeyInfo(priv_key, 0, X509_ASN_ENCODING, key_info,
                                  &actual_len)) {
        DWORD last_error = GetLastError();
        S_NCRYPT_winerr(ec_ncrypt_private_to_ossl_public, last_error,
                        CryptExportPublicKeyInfo,
                        "Exporting public key from certificate");
        goto done;
    }
    CMN_DBG_ASSERT(actual_len <= len);

    key_nid = OBJ_txt2nid(key_info->Algorithm.pszObjId);
    if (key_nid != NID_X9_62_id_ecPublicKey) {
        S_NCRYPT_osslerr(OBJ_txt2nid, "Getting NID for EC algorithm ID");
        goto done;
    }

    /* Convert the key parameters into the associated curve nid */
    obj_bytes = key_info->Algorithm.Parameters.pbData;
    obj_length = key_info->Algorithm.Parameters.cbData;
    if (d2i_ASN1_OBJECT(&obj_id, &obj_bytes, obj_length) == NULL) {
        S_NCRYPT_osslerr(d2i_ASN1_OBJECT, "Converting key parameters");
        goto done;
    }
    curve_nid = OBJ_obj2nid(obj_id);

    /* Currently only these curve nids are supported */
    if ((curve_nid != NID_X9_62_prime256v1) && (curve_nid != NID_secp384r1) &&
        (curve_nid != NID_secp521r1)) {
#ifndef NDEBUG
        char obj_name[80];
        if (OBJ_obj2txt(obj_name, sizeof(obj_name), obj_id, 1) == 1) {
            CMN_DBG_ERROR("Unexpected curve nid %d, parameters object id is %s",
                          curve_nid, obj_name);
        } else {
            CMN_DBG_ERROR("Unexpected curve nid %d", curve_nid);
        }
#endif /*NDEBUG */
        S_NCRYPT_err(ec_ncrypt_private_to_ossl_public, R_NOT_SUPPORTED,
                     "Curve NID not recognized");
        goto done;
    }

    group = EC_GROUP_new_by_curve_name(curve_nid);
    if (group == NULL) {
        S_NCRYPT_osslerr(EC_GROUP_new_by_curve_name,
                         "Getting group from curve");
        goto done;
    }

    /* Create the point and finally deserialize the blob into it */
    point = EC_POINT_new(group);
    if (point == NULL) {
        S_NCRYPT_osslerr(EC_POINT_new, "Creating new EC POINT");
        goto done;
    }

    if (EC_POINT_oct2point(group, point, key_info->PublicKey.pbData,
                           key_info->PublicKey.cbData, NULL) != 1) {
        S_NCRYPT_osslerr(EC_POINT_oct2point, "Converting EC point to bytes");
        goto done;
    }

    /* Instantiate OpenSSL EC KEY accordingly */
    ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (ec_key == NULL) {
        S_NCRYPT_osslerr(EC_KEY_new_by_curve_name, "Creating new EC key");
        goto done;
    }

    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        S_NCRYPT_osslerr(EC_KEY_set_public_key,
                         "Setting EC point as public key");
        goto done;
    }

    *ec_key_out = ec_key;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        EC_KEY_free(ec_key);
    }
    EC_POINT_free(point);
    EC_GROUP_free(group);
    ASN1_OBJECT_free(obj_id);
    CMN_free(key_info);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Signing */

static int
ecdsa_sign_digest_sig(ECDSA_SIG *sig, /* in/out */
                      NCRYPT_KEY_HANDLE h_private_key,
                      const unsigned char *digest, int digest_len)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    SECURITY_STATUS cng_retval;
    PUCHAR cng_sig = NULL;
    ULONG cng_sig_len;
    ULONG result_len;
    int bn_len;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;

    /* Query for the required length */
    cng_retval = NCryptSignHash(h_private_key, NULL, (PBYTE)digest, digest_len,
                                NULL, 0, &result_len, 0 /* no padding */);
    if (FAILED(cng_retval)) {
        S_NCRYPT_winerr(ecdsa_sign_digest_sig, cng_retval, NCryptSignHash,
                        "Getting required length for signature object");
        goto done;
    }

    /* Allocate space for CNG signature */
    cng_sig_len = result_len;
    cng_sig = CMN_malloc(cng_sig_len);
    if (cng_sig == NULL) {
        S_NCRYPT_err(ecdsa_sign_digest_sig, R_MALLOC_FAILED,
                     "Allocating signature object");
        goto done;
    }

    /* Do the signing */
    cng_retval = NCryptSignHash(h_private_key, NULL, (PBYTE)digest, digest_len,
                                cng_sig, cng_sig_len, &result_len, 0);
    if (FAILED(cng_retval)) {
        S_NCRYPT_winerr(ecdsa_sign_digest_sig, cng_retval, NCryptSignHash,
                        "Signing hash");
        goto done;
    }
    CMN_DBG_ASSERT(result_len == cng_sig_len);

    /* Convert CNG bytes to OSSL bignum for r */
    bn_len = cng_sig_len / 2;
    r = BN_bin2bn(&cng_sig[0 * bn_len], bn_len, NULL);
    if (r == NULL) {
        S_NCRYPT_osslerr(BN_bin2bn, "Converting r-component of signature");
        goto done;
    }

    /* Convert CNG bytes to OSSL bignum for s */
    s = BN_bin2bn(&cng_sig[1 * bn_len], bn_len, NULL);
    if (s == NULL) {
        S_NCRYPT_osslerr(BN_bin2bn, "Converting s-component of signature");
        goto done;
    }

    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        S_NCRYPT_osslerr(ECDSA_SIG_set0,
                         "Setting r and s components of signature");
        goto done;
    }

    result = 1;

done:
    if (result != 1) {
        BN_free(r);
        BN_free(s);
    }
    CMN_free(cng_sig);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------- */
/* - EC Key methods related to signing - */
/* ------------------------------------- */

static int
ncrypt_ec_key_sign(int type, const unsigned char *digest, int digest_len,
                   unsigned char *sig_out, unsigned int *sig_len_out,
                   const BIGNUM *inv, const BIGNUM *rp, EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int retval;
    ECDSA_SIG *sig = NULL;
    unsigned char *sig_ptr;
    struct ncrypt_ec_key_data *key_data;

    CMN_UNUSED(type);
    CMN_UNUSED(inv);
    CMN_UNUSED(rp);

    /* Allocate temporary struct to hold signature */
    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        S_NCRYPT_osslerr(ECDSA_SIG_new, "Allocating ECDSA signature structure");
        goto done;
    }

    /* Obtain signature of digest */
    key_data = ec_key_get_data(ec_key);
    if (ecdsa_sign_digest_sig(sig, key_data->key_handle, digest, digest_len) !=
        1)
        goto done;

    /* Serialize temporary struct into out parameters */
    sig_ptr = sig_out;
    retval = i2d_ECDSA_SIG(sig, &sig_ptr);
    if (retval < 0) {
        S_NCRYPT_osslerr(i2d_ECDSA_SIG, "Serializing ECDSA signature");
        goto done;
    }

    *sig_len_out = retval;
    result = 1;

done:
    ECDSA_SIG_free(sig);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
ncrypt_ec_key_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kinvp,
                         BIGNUM **rp)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(ec_key);
    CMN_UNUSED(ctx_in);
    CMN_UNUSED(kinvp);
    CMN_UNUSED(rp);

    /* Nothing for now */

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

static ECDSA_SIG *
ncrypt_ec_key_sign_sig(const unsigned char *digest, int digest_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    ECDSA_SIG *result = NULL;
    ECDSA_SIG *sig = NULL;
    struct ncrypt_ec_key_data *key_data;

    CMN_UNUSED(in_kinv);
    CMN_UNUSED(in_r);

    CMN_DBG_PRECOND_NOT_NULL(digest);
    CMN_DBG_PRECOND_NOT_NULL(ec_key);

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        S_NCRYPT_osslerr(ECDSA_SIG_new, "Allocating ECDSA signature structure");
        goto done;
    }

    /* Obtain signature of digest */
    key_data = ec_key_get_data(ec_key);
    if (ecdsa_sign_digest_sig(sig, key_data->key_handle, digest, digest_len) !=
        1)
        goto done;

    result = sig;

done:
    if (result == NULL) {
        ECDSA_SIG_free(sig);
    }

    CMN_DBG_API_LEAVE;
    return result;
}

/* Public EC Key functions */

static int
ec_key_method_get(EC_KEY_METHOD **method_out, bool release)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    static EC_KEY_METHOD *s_method = NULL;

    CMN_DBG_PRECOND_NOT_NULL(method_out);

    if ((s_method == NULL) && !release) {
        const EC_KEY_METHOD *default_method;

        /* The default method is our starting point */
        default_method = EC_KEY_get_default_method();
        if (default_method == NULL) {
            S_NCRYPT_osslerr(EC_KEY_get_default_method,
                             "Obtaining default EC KEY method");
            goto done;
        }

        /* Duplicate it for our use */
        s_method = EC_KEY_METHOD_new(default_method);
        if (s_method == NULL) {
            S_NCRYPT_osslerr(EC_KEY_METHOD_new,
                             "Duplicating default EC KEY method");
            goto done;
        }
    }

    *method_out = s_method;

    if (release)
        s_method = NULL;

    result = 1;

done:

    CMN_DBG_TRACE_LEAVE;
    return result;
}

EC_KEY *
ncrypt_ec_key_new(PCCERT_CONTEXT cert_ctx)
{
    CMN_DBG_TRACE_ENTER;

    EC_KEY *result = NULL;
    EC_KEY *ec_key;
    struct ncrypt_ec_key_data *data;
    NCRYPT_KEY_HANDLE private_key_handle;
    EC_KEY_METHOD *method;
    EC_POINT *pub_point = NULL;

    /* Get private key handle from certificate */
    if (!ncrypt_x509_certificate_to_key(cert_ctx, &private_key_handle))
        goto done;
    CMN_DBG_ASSERT(NCRYPT_NULL != private_key_handle);

    /* Get EC point and curve from private key handle */
    if (!ec_ncrypt_private_to_ossl_public(private_key_handle, &ec_key))
        goto done;

    /* Use our methods, not the default ones */
    if (ec_key_method_get(&method, false) != 1)
        goto done;
    if (EC_KEY_set_method(ec_key, method) != 1) {
        S_NCRYPT_osslerr(EC_KEY_set_method,
                         "Setting ncrypt key method for EC key");
        goto done;
    }

    /* Associate data with the key */
    data = CMN_malloc(sizeof(*data));
    if (data == NULL) {
        S_NCRYPT_err(ncrypt_ec_key_new, R_MALLOC_FAILED,
                     "Allocating EC key data");
        goto done;
    }

    /* Store private key as handle */
    data->key_handle = private_key_handle;
    if (ec_key_set_data(ec_key, data) != 1)
        goto done;

    result = ec_key;

done:
    EC_POINT_free(pub_point);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
ncrypt_ec_key_free(EC_KEY *ec_key)
{
    CMN_DBG_TRACE_ENTER;

    CMN_DBG_PRECOND_NOT_NULL(ec_key);

    EC_KEY_free(ec_key);

    CMN_DBG_TRACE_LEAVE;
    return;
}

/* ----------------------------------------- */
/* - Initialize and finalize the EC module - */
/* ----------------------------------------- */

int
s_ncrypt_ec_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EC_KEY_METHOD *method;

    if (ec_key_method_get(&method, false) != 1)
        goto done;

    /* Modify the signing functions, don't touch the rest */
    EC_KEY_METHOD_set_sign(method, ncrypt_ec_key_sign, ncrypt_ec_key_sign_setup,
                           ncrypt_ec_key_sign_sig);

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

void
s_ncrypt_ec_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    EC_KEY_METHOD *method;

    if (ec_key_method_get(&method, true) != 1)
        goto done;

    EC_KEY_METHOD_free(method);

done:
    CMN_DBG_TRACE_LEAVE;
}
