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

#define CMN_THIS_FILE "src/e_bcrypt_ec.c"

/* Interface */
#include "e_bcrypt_ec.h"

/* Implementation */
#include "e_bcrypt_err.h"
#include "e_bcrypt_provider.h"
#include "e_bcrypt_secret.h"

/* Common header files */
#include "c_cmn.h"

/* OpenSSL headers */
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

/* Providers for ECDH and ECDSA, for P-256, P-384 and P-521 */

static int
alg_provider_ecdh_p256_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDH_P256_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdh_p256_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDH P-256 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_ecdh_p384_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDH_P384_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdh_p384_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDH P-384 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_ecdh_p521_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDH_P521_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdh_p521_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDH P-521 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_ecdsa_p256_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDSA_P256_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdsa_p256_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDSA P-256 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_ecdsa_p384_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDSA_P384_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdsa_p384_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDSA P-384 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
alg_provider_ecdsa_p521_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_ECDSA_P521_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_ecdsa_p521_get, last_error,
                        InitOnceExecuteOnce,
                        "ECDSA P-521 one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------------------------------- */
/* Static helper functions to implement the EC key methods */
/* ------------------------------------------------------- */

/* Convert a CNG blob into an ECDSA_SIG structure. */
static int
ecdsa_sig_bcrypt_to_ossl(ECDSA_SIG *ossl_signature, /* out */
                         const unsigned char *cng_signature,
                         int cng_signature_len)
{
    int result = 0;

    BIGNUM *r;
    BIGNUM *s;
    int bn_len;

    /* Convert bytes to bignums */
    bn_len = cng_signature_len / 2;
    r = BN_bin2bn(&cng_signature[0 * bn_len], bn_len, NULL);
    if (r == NULL) {
        E_BCRYPT_osslerr(BN_bin2bn, "Converting signed bytes "
                                    "into r-portion of signature ");
        goto done;
    }

    s = BN_bin2bn(&cng_signature[1 * bn_len], bn_len, NULL);
    if (s == NULL) {
        E_BCRYPT_osslerr(BN_bin2bn, "Converting signed bytes "
                                    "into s-portion of signature");
        goto done;
    }

    if (ECDSA_SIG_set0(ossl_signature, r, s) != 1) {
        E_BCRYPT_osslerr(ECDSA_SIG_set0, "Setting r and s portions");
        goto done;
    }
    result = 1;

done:
    return result;
}

/* Convert an ECDSA structure into CNG's blob format. */
/* Note: the cng_signature_len parameter does not indicate
 *   the amount of allocated bytes in cng_signature,
 *   but the exact length of the CNG signature. The
 *   function will insert leading zeroes if needed. */
static int
ecdsa_sig_ossl_to_bcrypt(unsigned char *cng_signature, /* inout */
                         int cng_signature_len, const ECDSA_SIG *ossl_signature)
{
    int result = 0;
    int ossl_retval;

    DWORD signature_length;
    DWORD signature_element_length;
    PUCHAR signature_blob = NULL;
    ULONG signature_blob_size;
    PUCHAR signature_bytes;
    int leading_zeroes;

    signature_length = cng_signature_len;
    signature_element_length = signature_length / 2;
    signature_blob_size = signature_length;
    signature_blob = cng_signature;
    CMN_memset(signature_blob, 0, signature_blob_size);
    signature_bytes = &(signature_blob[0 * signature_element_length]);
    /* Note: BN_bn2bin returns an array of octets withouth leading zeroes.
    CNG requires the leading zeroblob_es, so they have to be constructed.
    This is done by increasing the starting pointer of the result,
    which works in combination with the memset to 0 a few lines back */
    leading_zeroes = signature_element_length -
                     BN_num_bytes(ECDSA_SIG_get0_r(ossl_signature));
    if (leading_zeroes < 0) {
        E_BCRYPT_err(ecdsa_sig_ossl_to_bcrypt, R_INTERNAL_ERROR,
                     "Negative number of leading zeroes for r");
        goto done;
    }
    ossl_retval = BN_bn2bin(ECDSA_SIG_get0_r(ossl_signature),
                            &signature_bytes[leading_zeroes]);
    if ((DWORD)ossl_retval != (signature_element_length - leading_zeroes)) {
        E_BCRYPT_err(ecdsa_sig_ossl_to_bcrypt, R_INTERNAL_ERROR,
                     "Signature's r componenent has unexpected length");
        goto done;
    }

    signature_bytes = &(signature_blob[1 * signature_element_length]);
    leading_zeroes = signature_element_length -
                     BN_num_bytes(ECDSA_SIG_get0_s(ossl_signature));
    if (leading_zeroes < 0) {
        E_BCRYPT_err(ecdsa_sig_ossl_to_bcrypt, R_INTERNAL_ERROR,
                     "Negative number of leading zeroes for s");
        goto done;
    }
    ossl_retval = BN_bn2bin(ECDSA_SIG_get0_s(ossl_signature),
                            &signature_bytes[leading_zeroes]);
    if ((DWORD)ossl_retval != (signature_element_length - leading_zeroes)) {
        E_BCRYPT_err(ecdsa_sig_ossl_to_bcrypt, R_INTERNAL_ERROR,
                     "Signature's r componenent has unexpected length");
        goto done;
    }
    result = 1;
done:
    return result;
}

/* Import BCrypt key from OpenSSL generic private EC key */
static int
ec_ossl_to_ec_bcrypt(BCRYPT_ALG_HANDLE h_ec_alg, ULONG private_magic,
                     BCRYPT_KEY_HANDLE *h_key_out, const EC_KEY *ec_key)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int ossl_retval;
    NTSTATUS cng_retval;

    BCRYPT_ECCKEY_BLOB *b_private_key = NULL;
    BYTE *private_key_blob = NULL;
    int private_key_blob_size;
    BYTE *private_key_bytes;
    const EC_GROUP *group;
    const EC_POINT *private_key_point;
    const BIGNUM *order;
    BIGNUM *private_x = NULL;
    BIGNUM *private_y = NULL;
    const BIGNUM *private_d = NULL;
    int key_size;
    int leading_zeroes;

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Getting EC group from key");
        goto done;
    }
    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_order, "Getting EC group\'s order");
        goto done;
    }
    key_size = BN_num_bytes(order);

    private_x = BN_new();
    if (private_x == NULL) {
        E_BCRYPT_osslerr(BN_new, "Creating EC private key x portion");
        goto done;
    }
    private_y = BN_new();
    if (private_y == NULL) {
        E_BCRYPT_osslerr(BN_new, "Creating EC private key y portion");
        goto done;
    }

    /* Construct CNG blob from OpenSSL private key */
    private_d = EC_KEY_get0_private_key(ec_key);
    if (private_d == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_private_key,
                         "Getting private portion of EC key");
        goto done;
    }
    private_key_point = EC_KEY_get0_public_key(ec_key);
    if (private_key_point == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_public_key,
                         "Geting public portion of EC key");
        goto done;
    }
    ossl_retval = EC_POINT_get_affine_coordinates_GFp(
        group, private_key_point, private_x, private_y, NULL);
    if (ossl_retval != 1) {
        E_BCRYPT_osslerr(EC_POINT_get_affine_coordinates_GFp,
                         "Getting coordinates of EC point");
        goto done;
    }

    private_key_blob_size = sizeof(*b_private_key) + 3 * key_size;
    private_key_blob = CMN_malloc(private_key_blob_size);
    if (private_key_blob == NULL) {
        E_BCRYPT_err(ec_ossl_to_ec_bcrypt, R_MALLOC_FAILED,
                     "Creating CNG private key blob");
        goto done;
    }
    CMN_memset(private_key_blob, 0, private_key_blob_size);
    b_private_key = (BCRYPT_ECCKEY_BLOB *)private_key_blob;
    b_private_key->dwMagic = private_magic;
    b_private_key->cbKey = key_size;
    private_key_bytes = &(private_key_blob[sizeof(*b_private_key)]);
    /* Note: BN_bn2bin returns an array of octets withouth leading zeroes.
    CNG requires the leading zeroes, so they have to be constructed.
    This is done by increasing the starting pointer of the result,
    which works in combination with the memset to 0 a few lines back */
    leading_zeroes = key_size - BN_num_bytes(private_x);
    if (leading_zeroes < 0) {
        E_BCRYPT_err(
            ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
            "Negative number of leading zeroes for EC key x component");
        goto done;
    }
    ossl_retval = BN_bn2bin(private_x, &private_key_bytes[leading_zeroes]);
    if (ossl_retval != (key_size - leading_zeroes)) {
        E_BCRYPT_err(ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
                     "EC key x component has unexpected length");
        goto done;
    }
    private_key_bytes = &(private_key_bytes[key_size]);
    leading_zeroes = key_size - BN_num_bytes(private_y);
    if (leading_zeroes < 0) {
        E_BCRYPT_err(
            ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
            "Negative number of leading zeroes for EC key y component");
        goto done;
    }
    ossl_retval = BN_bn2bin(private_y, &private_key_bytes[leading_zeroes]);
    if (ossl_retval != (key_size - leading_zeroes)) {
        E_BCRYPT_err(ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
                     "EC key y component has unexpected length");
        goto done;
    }
    private_key_bytes = &(private_key_bytes[key_size]);
    leading_zeroes = key_size - BN_num_bytes(private_d);
    if (leading_zeroes < 0) {
        E_BCRYPT_err(
            ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
            "Negative number of leading zeroes for EC key d component");
        goto done;
    }
    ossl_retval = BN_bn2bin(private_d, &private_key_bytes[leading_zeroes]);
    if (ossl_retval != (key_size - leading_zeroes)) {
        E_BCRYPT_err(ec_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
                     "EC key d component has unexpected length");
        goto done;
    }

    /* Import private key from constructed blob */
    cng_retval =
        BCryptImportKeyPair(h_ec_alg, NULL, BCRYPT_ECCPRIVATE_BLOB, h_key_out,
                            private_key_blob, private_key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ec_ossl_to_ec_bcrypt, cng_retval, BCryptImportKeyPair,
                        "Converting OpenSSL EC keypair to CNG keypair");
        goto done;
    }

    result = 1;

done:
    CMN_free(private_key_blob);
    BN_free(private_y);
    BN_free(private_x);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Import BCrypt ECDSA key from OpenSSL private EC key */
static int
ec_ossl_to_ecdsa_bcrypt(BCRYPT_KEY_HANDLE *cng_key, /* out */
                        const EC_KEY *ec_key)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    const EC_GROUP *group;
    int curve_name;
    ULONG magic;
    BCRYPT_ALG_HANDLE h_ecdsa_alg;

    curve_name = EC_GROUP_get_curve_name(group);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdsa_p256_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdsa_p384_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdsa_p521_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(ec_ossl_to_ecdsa_bcrypt, R_PASSED_UNKNOWN_VALUE,
                     "Converting to CNG ECDSA key");
        goto done;
    }

    /* Convert into key */
    if (ec_ossl_to_ec_bcrypt(h_ecdsa_alg, magic, cng_key, ec_key) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Export BCrypt key to OpenSSL private EC key */
/* Note: ec_key is already instantiated with the right (expected) group, 
     just needs to be filled with the values */
static int
ec_bcrypt_to_ec_ossl(EC_KEY *ec_key, /* out */
                     BCRYPT_KEY_HANDLE h_ec_key, ULONG private_magic)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;

    PUCHAR private_key_blob = NULL;
    DWORD private_key_blob_size;
    DWORD actual_blob_size;

    const BCRYPT_ECCKEY_BLOB *b_private_key;
    const BIGNUM *order;
    const EC_GROUP *group;
    int key_size;

    const BYTE *private_key_bytes;
    EC_POINT *key_point = NULL;
    BIGNUM *private_d = NULL;
    BIGNUM *point_x = NULL;
    BIGNUM *point_y = NULL;

    /* Export key from CNG */
    /* First get the memory size required for the export */
    cng_retval = BCryptExportKey(h_ec_key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL,
                                 0, &private_key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ec_bcrypt_to_ec_ossl, cng_retval, BCryptExportKey,
                        "Getting size of CNG EC keypair");
        goto done;
    }

    /* Allocate the required memory */
    private_key_blob = CMN_malloc(private_key_blob_size);
    if (private_key_blob == NULL) {
        E_BCRYPT_err(ec_bcrypt_to_ec_ossl, R_MALLOC_FAILED,
                     "Creating CNG private EC key blob");
        goto done;
    }

    /* Do the actual export */
    cng_retval = BCryptExportKey(h_ec_key, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 private_key_blob, private_key_blob_size,
                                 &actual_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ec_bcrypt_to_ec_ossl, cng_retval, BCryptExportKey,
                        "Converting CNG EC keypair to OpenSSL keypair");
        goto done;
    }
    CMN_DBG_ASSERT_NOT_NULL(private_key_blob);
    CMN_DBG_ASSERT(private_key_blob_size == actual_blob_size);

    /* Get its contents */
    b_private_key = (const BCRYPT_ECCKEY_BLOB *)private_key_blob;
    if (b_private_key->dwMagic != private_magic) {
        E_BCRYPT_err(ec_bcrypt_to_ec_ossl, R_PASSED_UNKNOWN_VALUE,
                     "Received unexpected magic value when exporting EC key");
        goto done;
    }
    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Getting group from EC key");
        goto done;
    }
    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        E_BCRYPT_osslerr(EC_GROUP_get0_order, "Getting order from EC group");
        goto done;
    }
    key_size = BN_num_bytes(order);
    CMN_DBG_ASSERT((int)b_private_key->cbKey == key_size);

    /* Convert from binary to BNs */
    private_key_bytes = &(private_key_blob[sizeof(*b_private_key)]);
    point_x = BN_bin2bn(&private_key_bytes[0], key_size, NULL);
    if (point_x == NULL) {
        E_BCRYPT_osslerr(BN_bin2bn, "Converting CNG key x blob bytes");
        goto done;
    }
    point_y = BN_bin2bn(&private_key_bytes[key_size], key_size, NULL);
    if (point_y == NULL) {
        E_BCRYPT_osslerr(BN_bin2bn, "Converting CNG key y blob bytes");
        goto done;
    }
    private_d = BN_bin2bn(&private_key_bytes[2 * key_size], key_size, NULL);
    if (private_d == NULL) {
        E_BCRYPT_osslerr(BN_bin2bn, "Converting CNG key d blob bytes");
        goto done;
    }

    /* Use BNs to create point and private key */
    key_point = EC_POINT_new(group);
    if (key_point == NULL) {
        E_BCRYPT_osslerr(EC_POINT_new, "Creating EC point");
        goto done;
    }
    if (EC_POINT_set_affine_coordinates_GFp(group, key_point, point_x, point_y,
                                            NULL) != 1) {
        E_BCRYPT_osslerr(EC_POINT_set_affine_coordinates_GFp,
                         "Setting affine coordinates for EC key point");
        goto done;
    }
    if (EC_KEY_set_public_key(ec_key, key_point) != 1) {
        E_BCRYPT_osslerr(EC_KEY_set_public_key, "Setting EC public key");
        goto done;
    }
    if (EC_KEY_set_private_key(ec_key, private_d) != 1) {
        E_BCRYPT_osslerr(EC_KEY_set_private_key, "Setting EC private key");
        goto done;
    }

    result = 1;

done:
    BN_free(private_d);
    BN_free(point_y);
    BN_free(point_x);
    EC_POINT_free(key_point);
    CMN_free(private_key_blob);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Import BCrypt key from OpenSSL public EC key */
static int
ecpoint_ossl_to_ec_bcrypt(BCRYPT_ALG_HANDLE h_ec_alg, ULONG public_magic,
                          BCRYPT_KEY_HANDLE *cng_key, /* out */
                          const EC_GROUP *ecgroup, const EC_POINT *ecpoint)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int ossl_retval;
    NTSTATUS cng_retval;
    BCRYPT_ECCKEY_BLOB *b_key = NULL;
    BYTE *key_blob = NULL;
    int key_blob_size;
    BYTE *key_bytes = NULL;
    int key_size;
    int leading_zeroes;

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if ((x == NULL) || (y == NULL)) {
        E_BCRYPT_osslerr(BN_new, "Creating BN for EC point conversion");
        goto done;
    }

    if (EC_POINT_get_affine_coordinates_GFp(ecgroup, ecpoint, x, y, NULL) !=
        1) {
        E_BCRYPT_osslerr(EC_POINT_get_affine_coordinates_GFp,
                         "Getting affine coordinates from EC key point");
        goto done;
    }
    key_size = (EC_GROUP_order_bits(ecgroup) + 7) / 8;

    /* Construct CNG blob from OpenSSL public key
     *
     * BCRYPT_ECCKEY_BLOB
     * BYTE X[cbKey]
     * BYTE Y[cbKey]
     */
    key_blob_size = sizeof(*b_key) + 2 * key_size;
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(ecpoint_ossl_to_ec_bcrypt, R_MALLOC_FAILED,
                     "Converting EC point to CNG");
        goto done;
    }
    CMN_memset(key_blob, 0, key_blob_size);

    b_key = (BCRYPT_ECCKEY_BLOB *)key_blob;
    b_key->dwMagic = public_magic;
    b_key->cbKey = key_size;
    key_bytes = &(key_blob[sizeof(*b_key)]);
    leading_zeroes = key_size - BN_num_bytes(x);
    if (leading_zeroes < 0) {
        E_BCRYPT_err(
            ecpoint_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
            "Negative number of leading zeroes for EC key x component");
        goto done;
    }
    ossl_retval = BN_bn2bin(x, &key_bytes[leading_zeroes]);
    if (ossl_retval != (key_size - leading_zeroes)) {
        E_BCRYPT_err(ecpoint_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
                     "EC key x component has unexpected length");
        goto done;
    }
    key_bytes = &(key_bytes[key_size]);
    leading_zeroes = key_size - BN_num_bytes(y);
    if (leading_zeroes < 0) {
        E_BCRYPT_err(
            ecpoint_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
            "Negative number of leading zeroes for EC key y component");
        goto done;
    }
    ossl_retval = BN_bn2bin(y, &key_bytes[leading_zeroes]);
    if (ossl_retval != (key_size - leading_zeroes)) {
        E_BCRYPT_err(ecpoint_ossl_to_ec_bcrypt, R_INTERNAL_ERROR,
                     "EC key y component has unexpected length");
        goto done;
    }

    /* Import public key from constructed blob */
    cng_retval = BCryptImportKeyPair(h_ec_alg, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                     cng_key, key_blob, key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecpoint_ossl_to_ec_bcrypt, cng_retval,
                        BCryptImportKeyPair, "Import EC public key into CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);
    BN_free(y);
    BN_free(x);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ecpoint_ossl_to_ecdh_bcrypt(BCRYPT_KEY_HANDLE *cng_key, /* out */
                            const EC_GROUP *ecgroup, const EC_POINT *ecpoint)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int curve_name;
    BCRYPT_ALG_HANDLE h_ecdh_alg = NULL;
    ULONG magic;

    curve_name = EC_GROUP_get_curve_name(ecgroup);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdh_p256_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdh_p384_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdh_p521_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(ecpoint_ossl_to_ecdh_bcrypt, R_PASSED_UNKNOWN_VALUE,
                     "Converting to CNG ECDH public key");
        goto done;
    }

    if (ecpoint_ossl_to_ec_bcrypt(h_ecdh_alg, magic, cng_key, ecgroup,
                                  ecpoint) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ecpoint_ossl_to_ecdsa_bcrypt(BCRYPT_KEY_HANDLE *cng_key, /* out */
                             const EC_GROUP *ecgroup, const EC_POINT *ecpoint)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int curve_name;
    BCRYPT_ALG_HANDLE h_ecdsa_alg = NULL;
    ULONG magic;

    curve_name = EC_GROUP_get_curve_name(ecgroup);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdsa_p256_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdsa_p384_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdsa_p521_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(ecpoint_ossl_to_ecdsa_bcrypt, R_PASSED_UNKNOWN_VALUE,
                     "Converting to CNG ECDSA key");
        goto done;
    }

    /* Get CNG algorithm handle */
    if (ecpoint_ossl_to_ec_bcrypt(h_ecdsa_alg, magic, cng_key, ecgroup,
                                  ecpoint) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* -------------------------------------------------- */
/* Functions that implement the engine's ECDH methods */
/* -------------------------------------------------- */

static int
ecdh_generate(const EC_GROUP *ec_group,
              BCRYPT_KEY_HANDLE *h_generated_key /* out */)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int curve_name;
    int degree;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_ecdh_alg;
    BCRYPT_KEY_HANDLE h_key = NULL;

    /* Get ECDH CNG algorithm handle */
    curve_name = EC_GROUP_get_curve_name(ec_group);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdh_p256_get(&h_ecdh_alg) != 1)
            goto done;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdh_p384_get(&h_ecdh_alg) != 1)
            goto done;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdh_p521_get(&h_ecdh_alg) != 1)
            goto done;
        break;
    default:
        E_BCRYPT_err(ecdh_generate, R_PASSED_UNKNOWN_VALUE,
                     "Generating ECDH key");
        goto done;
    }

    degree = EC_GROUP_get_degree(ec_group);
    if (degree == 0) {
        E_BCRYPT_osslerr(EC_GROUP_get_degree, "Generating ECDH key");
        goto done;
    }

    /* Invoke key generation */
    cng_retval = BCryptGenerateKeyPair(h_ecdh_alg, &h_key, degree, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdh_generate, cng_retval, BCryptGenerateKeyPair,
                        "Generating CNG ECDH key pair");
        goto done;
    }
    /* Commit to CNG */
    cng_retval = BCryptFinalizeKeyPair(h_key, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdh_generate, cng_retval, BCryptFinalizeKeyPair,
                        "Committing generated CNG ECDH key");
        goto done;
    }

    *h_generated_key = h_key;
    result = 1;

done:
    if ((result != 1) && (h_key != NULL)) {
        cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG ECDH key");
        }
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* --------------------------------------------------- */
/* Functions that implement the engine's ECDSA methods */
/* --------------------------------------------------- */

/* Signing */

static int
ecdsa_sign_digest_sig(ECDSA_SIG *sig_inout, EC_KEY *ec_key,
                      const unsigned char *digest, int digest_len)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    const EC_GROUP *group;
    int curve_name;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_ecdsa_alg;
    BCRYPT_KEY_HANDLE h_key = NULL;
    ULONG magic;
    PUCHAR cng_sig = NULL;
    ULONG cng_sig_len;
    ULONG result_len;

    /* Get ECDSA CNG algorithm handle */
    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Signing with EC key");
        goto done;
    }
    curve_name = EC_GROUP_get_curve_name(group);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdsa_p256_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdsa_p384_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdsa_p521_get(&h_ecdsa_alg) != 1)
            goto done;
        magic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(ecdsa_sign_digest_sig, R_PASSED_UNKNOWN_VALUE,
                     "Signing digest with ECDSA");
        goto done;
    }

    /* Convert into key */
    if (ec_ossl_to_ec_bcrypt(h_ecdsa_alg, magic, &h_key, ec_key) != 1)
        goto done;

    /* Calculate the required length */
    cng_retval = BCryptSignHash(h_key, NULL, (PUCHAR)digest, digest_len, NULL,
                                0, &cng_sig_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdsa_sign_digest_sig, cng_retval, BCryptSignHash,
                        "Getting length of ECDSA signature");
        goto done;
    }

    /* Allocate memory for temporary CNG signature */
    cng_sig = CMN_malloc(cng_sig_len);
    if (cng_sig == NULL) {
        E_BCRYPT_err(ecdsa_sign_digest_sig, R_MALLOC_FAILED,
                     "Allocating ECDSA signature");
        goto done;
    }

    /* Do the signing */
    result_len = cng_sig_len;
    cng_retval = BCryptSignHash(h_key, NULL, (PUCHAR)digest, digest_len,
                                cng_sig, cng_sig_len, &result_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdsa_sign_digest_sig, cng_retval, BCryptSignHash,
                        "Signing hash with ECDSA key");
        goto done;
    }
    /* CMN_DBG_ASSERT(result_len == cng_sig_len); */
    if (ecdsa_sig_bcrypt_to_ossl(sig_inout, cng_sig, cng_sig_len) != 1)
        goto done;

    result = 1;

done:
    CMN_free(cng_sig);
    if (h_key != NULL) {
        cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG ECDSA key");
        }
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/*Verification */

static int
ecdsa_verify_signed_digest(BCRYPT_KEY_HANDLE h_key, const unsigned char *digest,
                           int digest_len, const unsigned char *signature,
                           unsigned int signature_len)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    ECDSA_SIG *ossl_sig = NULL;
    const unsigned char *sig_ptr;
    unsigned char *cng_sig = NULL;
    NTSTATUS cng_retval;
    ULONG cng_sig_len;
    ULONG bytes_written;

    sig_ptr = signature;
    ossl_sig = d2i_ECDSA_SIG(NULL, &sig_ptr, signature_len);
    if (ossl_sig == NULL) {
        E_BCRYPT_osslerr(d2i_ECDSA_SIG, "Verifying signed digest");
        goto done;
    }

    /* Query for CNG signature length */
    bytes_written = sizeof(cng_sig_len);
    cng_retval =
        BCryptGetProperty(h_key, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&cng_sig_len,
                          sizeof(cng_sig_len), &bytes_written, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdsa_verify_signed_digest, cng_retval,
                        BCryptGetProperty, "Getting ECDSA signature length");
        goto done;
    }

    /* Allocate temporary buffer for the CNG version of the signature */
    cng_sig = CMN_malloc(cng_sig_len);
    if (cng_sig == NULL) {
        E_BCRYPT_err(ecdsa_verify_signed_digest, R_MALLOC_FAILED,
                     "Allocating CNG ECDSA signature");
        goto done;
    }
    /* Convert signature from OpenSSL to CNG format */
    if (ecdsa_sig_ossl_to_bcrypt(cng_sig, cng_sig_len, ossl_sig) != 1)
        goto done;

    cng_retval = BCryptVerifySignature(h_key, NULL, (PUCHAR)digest, digest_len,
                                       (PUCHAR)cng_sig, cng_sig_len, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdsa_verify_signed_digest, cng_retval,
                        BCryptVerifySignature,
                        "Verifying signature with ECDSA key");
        goto done;
    }

    result = 1;

done:
    CMN_free(cng_sig);
    ECDSA_SIG_free(ossl_sig);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
ecdsa_verify_signed_digest_sig(BCRYPT_KEY_HANDLE h_key,
                               const unsigned char *digest, int digest_len,
                               const ECDSA_SIG *signature)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG result_length;
    PUCHAR cng_sig = NULL;
    ULONG cng_sig_len;

    cng_retval =
        BCryptGetProperty(h_key, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&cng_sig_len,
                          sizeof(cng_sig_len), &result_length, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(ecdsa_verify_signed_digest_sig, cng_retval,
                        BCryptGetProperty, "Getting ECDSA signature length");
        goto done;
    }

    /* TODO: Allocate signature_blob */
    cng_sig = CMN_malloc(cng_sig_len);
    if (cng_sig == NULL) {
        E_BCRYPT_err(ecdsa_verify_signed_digest_sig, R_MALLOC_FAILED,
                     "Allocating CNG ECDSA signature");
        goto done;
    }

    /* Convert the signature struct into a signature blob */
    if (ecdsa_sig_ossl_to_bcrypt(cng_sig, cng_sig_len, signature) != 1)
        goto done;

    /* Conversion of signature done, now invoke the verify method */
    if (ecdsa_verify_signed_digest(h_key, digest, digest_len, cng_sig,
                                   cng_sig_len) != 1)
        goto done;

    result = 1;

done:
    CMN_free(cng_sig);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ------------------------------- */
/* Actual engine function pointers */
/* ------------------------------- */

static int
bcrypt_ec_keygen(EC_KEY *key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    const EC_GROUP *ec_group;
    int curve_name;
    NTSTATUS cng_retval;
    ULONG magic;
    BCRYPT_KEY_HANDLE h_generated_key = NULL;

    CMN_DBG_PRECOND_NOT_NULL(key);

    ec_group = EC_KEY_get0_group(key);
    if (ec_group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Getting group from EC KEY");
        goto done;
    };
    curve_name = EC_GROUP_get_curve_name(ec_group);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        break;
    case NID_secp384r1:
        magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        break;
    case NID_secp521r1:
        magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(bcrypt_ec_keygen, R_PASSED_UNKNOWN_VALUE,
                     "Generating ECDH key");
        goto done;
    }

    if (ecdh_generate(ec_group, &h_generated_key) != 1)
        goto done;
    if (ec_bcrypt_to_ec_ossl(key, h_generated_key, magic) != 1)
        goto done;

    result = 1;

done:
    if (h_generated_key != NULL) {
        cng_retval = BCryptDestroyKey(h_generated_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG ECDH key");
        }
    }

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_ec_compute_key(unsigned char **key, size_t *outlen,
                      const EC_POINT *remotekey, const EC_KEY *localkey)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int curve_name;
    const EC_GROUP *group;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_ecdh_alg = NULL;
    BCRYPT_KEY_HANDLE h_my_private_key = NULL;
    BCRYPT_KEY_HANDLE h_other_public_key = NULL;
    ULONG magic;
    PUCHAR cng_key;
    ULONG cng_outlen;

    CMN_DBG_PRECOND_NOT_NULL(key);
    CMN_DBG_PRECOND_NOT_NULL(outlen);
    CMN_DBG_PRECOND_NOT_NULL(remotekey);
    CMN_DBG_PRECOND_NOT_NULL(localkey);

    /* Get ECDH CNG algorithm handle */
    group = EC_KEY_get0_group(localkey);
    if (group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Signing with EC key");
        goto done;
    }
    curve_name = EC_GROUP_get_curve_name(group);
    switch (curve_name) {
    case NID_X9_62_prime256v1:
        if (alg_provider_ecdh_p256_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        break;
    case NID_secp384r1:
        if (alg_provider_ecdh_p384_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        break;
    case NID_secp521r1:
        if (alg_provider_ecdh_p521_get(&h_ecdh_alg) != 1)
            goto done;
        magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        break;
    default:
        E_BCRYPT_err(bcrypt_ec_compute_key, R_PASSED_UNKNOWN_VALUE,
                     "Converting to CNG ECDH key");
        goto done;
    }

    /* Convert local (private) key to BCrypt */
    if (ec_ossl_to_ec_bcrypt(h_ecdh_alg, magic, &h_my_private_key, localkey) !=
        1)
        goto done;

    /* Convert remote (public) key to BCrypt */
    if (ecpoint_ossl_to_ecdh_bcrypt(&h_other_public_key, group, remotekey) != 1)
        goto done;

        /* Determine shared secret */
#if B_NO_RAW_SECRET
    if (secret_derive(h_my_private_key, h_other_public_key, magic, &cng_key,
                      &cng_outlen) != 1)
        goto done;
#else
    if (secret_derive(h_my_private_key, h_other_public_key, &cng_key,
                      &cng_outlen) != 1)
        goto done;
#endif

    *key = cng_key;
    *outlen = cng_outlen;
    result = 1;

done:
    if (h_my_private_key != NULL) {
        cng_retval = BCryptDestroyKey(h_my_private_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG ECDH private key");
        }
    }
    if (h_other_public_key != NULL) {
        cng_retval = BCryptDestroyKey(h_other_public_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG ECDH public key");
        }
    }

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_ec_sign(int type, const unsigned char *digest, int digest_len,
               unsigned char *signature, unsigned int *signature_len,
               const BIGNUM *inv, const BIGNUM *rp, EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int retval;
    ECDSA_SIG *ossl_sig = NULL;
    unsigned char *sig_ptr;

    CMN_UNUSED(type);
    CMN_UNUSED(inv);
    CMN_UNUSED(rp);

    /* Allocate temporary struct to hold signature */
    ossl_sig = ECDSA_SIG_new();
    if (ossl_sig == NULL) {
        E_BCRYPT_osslerr(ECDSA_SIG_new, "Creating ECDSA signature");
        goto done;
    }

    /* Obtain signature of digest */
    if (ecdsa_sign_digest_sig(ossl_sig, ec_key, digest, digest_len) != 1)
        goto done;

    /* Serialize temporary struct into out parameters */
    sig_ptr = signature;
    retval = i2d_ECDSA_SIG(ossl_sig, &sig_ptr);
    if (retval < 0) {
        E_BCRYPT_osslerr(i2d_ECDSA_SIG, "Serializing ECDSA signature");
        goto done;
    }

    *signature_len = retval;
    result = 1;

done:
    ECDSA_SIG_free(ossl_sig);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_ec_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(ec_key);
    CMN_UNUSED(ctx_in);
    CMN_UNUSED(kinvp);
    CMN_UNUSED(rp);

    result = 1;

    CMN_DBG_API_LEAVE;
    return result;
}

static ECDSA_SIG *
bcrypt_ec_sign_sig(const unsigned char *digest, int digest_len,
                   const BIGNUM *inv, const BIGNUM *rp, EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    ECDSA_SIG *result = NULL;
    ECDSA_SIG *ossl_sig = NULL;

    CMN_UNUSED(inv);
    CMN_UNUSED(rp);

    /* Allocate temporary struct to hold signature */
    ossl_sig = ECDSA_SIG_new();
    if (ossl_sig == NULL) {
        E_BCRYPT_osslerr(ECDSA_SIG_new, "Creating ECDSA signature");
        goto done;
    }
    /* Obtain signature of digest */
    if (ecdsa_sign_digest_sig(result, ec_key, digest, digest_len) != 1)
        goto done;

    result = ossl_sig;

done:
    /* Roll back if needed */
    if (result == NULL) {
        ECDSA_SIG_free(ossl_sig);
    }

    CMN_DBG_API_LEAVE;
    return result;
}

/* Verification */

static int
bcrypt_ec_verify(int type, const unsigned char *digest, int digest_len,
                 const unsigned char *signature, int signature_len,
                 EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_point = NULL;
    NTSTATUS cng_retval;
    BCRYPT_KEY_HANDLE h_key = NULL;

    CMN_UNUSED(type);

    ec_group = EC_KEY_get0_group(ec_key);
    if (ec_group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Getting group from EC KEY");
        goto done;
    }
    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_public_key,
                         "Getting public part of EC key");
        goto done;
    }

    /* Convert point on elliptic curve from OpenSSL to CNG format */
    if (ecpoint_ossl_to_ecdsa_bcrypt(&h_key, ec_group, ec_point) != 1)
        goto done;

    /* Verify the digest using the public key just extracted */
    if (ecdsa_verify_signed_digest(h_key, digest, digest_len, signature,
                                   signature_len) != 1)
        goto done;

    result = 1;

done:
    if (h_key != NULL) {
        cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG EC key");
        }
    }

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_ec_verify_sig(const unsigned char *digest, int digest_len,
                     const ECDSA_SIG *signature, EC_KEY *ec_key)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_point = NULL;
    NTSTATUS cng_retval;
    BCRYPT_KEY_HANDLE h_key = NULL;

    ec_group = EC_KEY_get0_group(ec_key);
    if (ec_group == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_group, "Getting group from EC KEY");
        goto done;
    }
    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        E_BCRYPT_osslerr(EC_KEY_get0_public_key,
                         "Getting public part of EC key");
        goto done;
    }

    /* Convert point on elliptic curve from OpenSSL to CNG format */
    if (ecpoint_ossl_to_ecdsa_bcrypt(&h_key, ec_group, ec_point) != 1)
        goto done;

    /* Verify the digest using the public key just extracted */
    if (ecdsa_verify_signed_digest_sig(h_key, digest, digest_len, signature) !=
        1)
        goto done;

    result = 1;
done:
    if (h_key != NULL) {
        cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG EC key");
        }
    }

    CMN_DBG_API_LEAVE;
    return result;
}

/* ------------------------------------------------------------- */
/* Function that exposes the EC KEY methods to the outside world */
/* ------------------------------------------------------------- */

static EC_KEY_METHOD *S_key_method = NULL;

const EC_KEY_METHOD *
e_bcrypt_ec_get(void)
{
    CMN_DBG_TRACE_ENTER;

    /* Nothing */

    CMN_DBG_TRACE_LEAVE;
    return S_key_method;
}

int
e_bcrypt_ec_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    EC_KEY_METHOD *method = NULL;

    CMN_DBG_ASSERT(S_key_method == NULL);

    method = EC_KEY_METHOD_new(NULL);
    if (method == NULL) {
        E_BCRYPT_osslerr(EC_KEY_METHOD_new, "Creating EC KEY method struct");
        goto done;
    }

    /* Function to generate EC key */
    EC_KEY_METHOD_set_keygen(method, bcrypt_ec_keygen);

    /* Function to compute ECDH shared secret */
    EC_KEY_METHOD_set_compute_key(method, bcrypt_ec_compute_key);

    /* Functions to do the ECDSA signing */
    EC_KEY_METHOD_set_sign(method, bcrypt_ec_sign, bcrypt_ec_sign_setup,
                           bcrypt_ec_sign_sig);

    /* Functions to do the ECDSA verification */
    EC_KEY_METHOD_set_verify(method, bcrypt_ec_verify, bcrypt_ec_verify_sig);

    S_key_method = method;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_ec_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(S_key_method);

    EC_KEY_METHOD_free(S_key_method);
    S_key_method = NULL;

    result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}
