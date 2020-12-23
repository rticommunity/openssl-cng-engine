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

#define CMN_THIS_FILE "src/e_bcrypt_rsa.c"

/* Interface */
#include "e_bcrypt_rsa.h"

/* Implementation */
#include "e_bcrypt_err.h"
#include "e_bcrypt_provider.h"

/* Common header files */
#include "c_cmn.h"

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

static int
alg_provider_rsa_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_RSA_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_rsa_get, last_error, InitOnceExecuteOnce,
                        "RSA one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* -------------------------------------------------------- */
/* Static helper functions to implement the RSA key methods */
/* -------------------------------------------------------- */

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
        E_BCRYPT_err(rsa_padding_type_to_flag, R_INCORRECT_USAGE,
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
        E_BCRYPT_err(rsa_md_type_to_algorithm, R_INCORRECT_USAGE,
                     "Identifying algorithm name for MD type");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Key conversion functions */

/* Any key converted to a BCrypt key can be released with this function */
static void
rsa_bcrypt_release(BCRYPT_KEY_HANDLE h_key)
{
    CMN_DBG_TRACE_ENTER;

    if (h_key != NULL) {
        NTSTATUS cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG RSA key");
        }
    }

    CMN_DBG_TRACE_LEAVE;
}

/* Export BCrypt RSA key to OpenSSL private RSA key */
static int
rsa_bcrypt_to_rsa_ossl_private(RSA *rsa_inout, BCRYPT_KEY_HANDLE h_rsa_key)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;

    PUCHAR key_blob = NULL;
    DWORD key_blob_size;
    DWORD actual_blob_size;

    const BCRYPT_RSAKEY_BLOB *b_key;
    const BYTE *exp_bytes;
    const BYTE *mod_bytes;
    const BYTE *prime1_bytes;
    const BYTE *prime2_bytes;
    int exp_size;
    int mod_size;
    int prime1_size;
    int prime2_size;
    BIGNUM *exponent = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *prime1 = NULL;
    BIGNUM *prime2 = NULL;
    BIGNUM *private_key = NULL;
    BN_CTX *ctx = NULL;

    /* Export key from CNG */
    /* First get the memory size required for the export */
    cng_retval = BCryptExportKey(h_rsa_key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL,
                                 0, &key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_bcrypt_to_rsa_ossl_private, cng_retval,
                        BCryptExportKey, "Getting size of CNG RSA keypair");
        goto done;
    }

    /* Allocate the required memory */
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_MALLOC_FAILED,
                     "Creating CNG private RSA key blob");
        goto done;
    }

    /* Do the actual export */
    cng_retval = BCryptExportKey(h_rsa_key, NULL, BCRYPT_RSAPRIVATE_BLOB,
                                 key_blob, key_blob_size, &actual_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_bcrypt_to_rsa_ossl_private, cng_retval,
                        BCryptExportKey,
                        "Converting CNG RSA keypair to OpenSSL keypair");
        goto done;
    }
    CMN_DBG_ASSERT_NOT_NULL(key_blob);
    CMN_DBG_ASSERT(key_blob_size == actual_blob_size);

    /* Get its contents */
    b_key = (const BCRYPT_RSAKEY_BLOB *)key_blob;
    if (b_key->Magic != BCRYPT_RSAPRIVATE_MAGIC) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_PASSED_UNKNOWN_VALUE,
                     "Received unexpected magic value when exporting RSA key");
        goto done;
    }

    /* Construct OpenSSL key from CNG blob
     *
     * BCRYPT_RSAKEY_BLOB
     * PublicExponent[cbPublicExp]
     * Modulus[cbModulus]
     * Prime1[cbPrime1]
     * Prime2[cbPrime2]
     */

    exp_size = b_key->cbPublicExp;
    mod_size = b_key->cbModulus;
    prime1_size = b_key->cbPrime1;
    prime2_size = b_key->cbPrime2;

    exp_bytes = &(key_blob[sizeof(*b_key)]);
    exponent = BN_bin2bn(exp_bytes, exp_size, NULL);
    if (exponent == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_INTERNAL_ERROR,
                     "Converting RSA exponent");
        goto done;
    }
    mod_bytes = &(exp_bytes[exp_size]);
    modulus = BN_bin2bn(mod_bytes, mod_size, NULL);
    if (modulus == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_INTERNAL_ERROR,
                     "Converting RSA modulus");
        goto done;
    }
    prime1_bytes = &(mod_bytes[mod_size]);
    prime1 = BN_bin2bn(prime1_bytes, prime1_size, NULL);
    if (prime1 == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_INTERNAL_ERROR,
                     "Converting RSA prime1");
        goto done;
    }
    prime2_bytes = &(prime1_bytes[prime1_size]);
    prime2 = BN_bin2bn(prime2_bytes, prime2_size, NULL);
    if (prime2 == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_INTERNAL_ERROR,
                     "Converting RSA prime2");
        goto done;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_MALLOC_FAILED,
                     "Constructing BN context");
        goto done;
    }

    private_key = BN_new();
    if (private_key == NULL) {
        E_BCRYPT_err(rsa_bcrypt_to_rsa_ossl_private, R_MALLOC_FAILED,
                     "Constructing BIGNUM");
        goto done;
    }

    if (BN_mod_mul(private_key, prime1, prime2, modulus, ctx) != 1) {
        E_BCRYPT_osslerr(BN_mod_mul, "Multiplying primes");
        goto done;
    }

    if (RSA_set0_key(rsa_inout, modulus, exponent, private_key) != 1) {
        E_BCRYPT_osslerr(RSA_set0_key, "Setting RSA key");
        goto done;
    }

    if (RSA_set0_factors(rsa_inout, prime1, prime2) != 1) {
        E_BCRYPT_osslerr(RSA_set0_factors, "Setting RSA factors");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);
    BN_CTX_free(ctx);
    if (result != 1) {
        BN_free(private_key);
        BN_free(prime2);
        BN_free(prime1);
        BN_free(modulus);
        BN_free(exponent);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
rsa_ossl_to_rsa_bcrypt_public(BCRYPT_KEY_HANDLE *h_key_out, const RSA *rsa)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int retval;
    BYTE *key_blob = NULL; /* to be allocated */
    BCRYPT_RSAKEY_BLOB *b_key;
    int key_blob_size;
    const BIGNUM *modulus;
    const BIGNUM *exponent;
    int mod_size;
    int exp_size;
    int key_size_bits;
    BYTE *mod_bytes;
    BYTE *exp_bytes;
    BCRYPT_ALG_HANDLE h_alg;
    NTSTATUS cng_retval;

    RSA_get0_key(rsa, &modulus, &exponent, NULL);
    mod_size = BN_num_bytes(modulus);
    exp_size = BN_num_bytes(exponent);
    key_size_bits = BN_num_bits(modulus);

    /* Construct CNG blob from OpenSSL public key
     *
     * BCRYPT_RSAKEY_BLOB
     * PublicExponent[cbPublicExp]
     * Modulus[cbModulus]
     */
    key_blob_size = sizeof(*b_key) + mod_size + exp_size;
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(ecpoint_ossl_to_ec_bcrypt, R_MALLOC_FAILED,
                     "Converting EC point to CNG");
        goto done;
    }
    CMN_memset(key_blob, 0, key_blob_size);

    b_key = (BCRYPT_RSAKEY_BLOB *)key_blob;
    b_key->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    b_key->BitLength = key_size_bits;
    b_key->cbPublicExp = exp_size;
    b_key->cbModulus = mod_size;
    b_key->cbPrime1 = 0;
    b_key->cbPrime2 = 0;

    exp_bytes = &(key_blob[sizeof(*b_key)]);
    retval = BN_bn2bin(exponent, exp_bytes);
    if (retval != exp_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_public, R_INTERNAL_ERROR,
                     "RSA exponent has unexpected length");
        goto done;
    }
    mod_bytes = &(exp_bytes[exp_size]);
    retval = BN_bn2bin(modulus, mod_bytes);
    if (retval != mod_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_public, R_INTERNAL_ERROR,
                     "RSA modulus has unexpected length");
        goto done;
    }

    /* Get CNG algorithm handle */
    if (alg_provider_rsa_get(&h_alg) != 1)
        goto done;

    /* Import public key from constructed blob */
    cng_retval = BCryptImportKeyPair(h_alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                     h_key_out, key_blob, key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_ossl_to_rsa_bcrypt_public, cng_retval,
                        BCryptImportKeyPair,
                        "Importing RSA public key into CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
rsa_ossl_to_rsa_bcrypt_private(BCRYPT_KEY_HANDLE *h_key_out, const RSA *rsa)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int retval;
    BYTE *key_blob = NULL; /* to be allocated */
    BCRYPT_RSAKEY_BLOB *b_key;
    int key_blob_size;
    const BIGNUM *modulus;
    const BIGNUM *exponent;
    const BIGNUM *prime1;
    const BIGNUM *prime2;
    int mod_size;
    int exp_size;
    int prime1_size;
    int prime2_size;
    int key_size_bits;
    BYTE *mod_bytes;
    BYTE *exp_bytes;
    BYTE *prime1_bytes;
    BYTE *prime2_bytes;
    BCRYPT_ALG_HANDLE h_alg;
    NTSTATUS cng_retval;

    /* We may calculate prime1 and prime2 from the modulus, exponent and
     *   private key in the future, if needed. For now, require them to
     *   be provided in the key (which is usually the case anyway). */
    RSA_get0_key(rsa, &modulus, &exponent, NULL);
    if ((modulus == NULL) || (exponent == NULL)) {
        E_BCRYPT_err(
            rsa_ossl_to_rsa_bcrypt_private, R_INCORRECT_USAGE,
            "Converting incomplete RSA key, modulo or exponent missing");
        goto done;
    }
    RSA_get0_factors(rsa, &prime1, &prime2);
    if ((prime1 == NULL) || (prime2 == NULL)) {
        E_BCRYPT_err(
            rsa_ossl_to_rsa_bcrypt_private, R_INCORRECT_USAGE,
            "Converting incomplete RSA key, one or both primes missing");
        goto done;
    }

    mod_size = BN_num_bytes(modulus);
    exp_size = BN_num_bytes(exponent);
    prime1_size = BN_num_bytes(prime1);
    prime2_size = BN_num_bytes(prime2);
    key_size_bits = BN_num_bits(modulus);

    /* Construct CNG blob from OpenSSL public key
     *
     * BCRYPT_RSAKEY_BLOB
     * PublicExponent[cbPublicExp]
     * Modulus[cbModulus]
     * Prime1[cbPrime1]
     * Prime2[cbPrime2]
     */
    key_blob_size =
        sizeof(*b_key) + mod_size + exp_size + prime1_size + prime2_size;
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_private, R_MALLOC_FAILED,
                     "Allocating CNG private key blob");
        goto done;
    }
    CMN_memset(key_blob, 0, key_blob_size);

    b_key = (BCRYPT_RSAKEY_BLOB *)key_blob;
    b_key->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    b_key->BitLength = key_size_bits;
    b_key->cbPublicExp = exp_size;
    b_key->cbModulus = mod_size;
    b_key->cbPrime1 = prime1_size;
    b_key->cbPrime2 = prime2_size;

    exp_bytes = &(key_blob[sizeof(*b_key)]);
    retval = BN_bn2bin(exponent, exp_bytes);
    if (retval != exp_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_private, R_INTERNAL_ERROR,
                     "RSA exponent has unexpected length");
        goto done;
    }
    mod_bytes = &(exp_bytes[exp_size]);
    retval = BN_bn2bin(modulus, mod_bytes);
    if (retval != mod_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_private, R_INTERNAL_ERROR,
                     "RSA modulus has unexpected length");
        goto done;
    }
    prime1_bytes = &(mod_bytes[mod_size]);
    retval = BN_bn2bin(prime1, prime1_bytes);
    if (retval != prime1_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_private, R_INTERNAL_ERROR,
                     "RSA prime1 has unexpected length");
        goto done;
    }
    prime2_bytes = &(prime1_bytes[prime1_size]);
    retval = BN_bn2bin(prime2, prime2_bytes);
    if (retval != prime2_size) {
        E_BCRYPT_err(rsa_ossl_to_rsa_bcrypt_private, R_INTERNAL_ERROR,
                     "RSA prime2 has unexpected length");
        goto done;
    }

    /* Get CNG algorithm handle */
    if (alg_provider_rsa_get(&h_alg) != 1)
        goto done;

    /* Import public key from constructed blob */
    cng_retval = BCryptImportKeyPair(h_alg, NULL, BCRYPT_RSAPRIVATE_BLOB,
                                     h_key_out, key_blob, key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_ossl_to_rsa_bcrypt_private, cng_retval,
                        BCryptImportKeyPair,
                        "Importing RSA public key into CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);

    CMN_DBG_API_LEAVE;
    return result;
}

/* Generation of RSA key */
static int
rsa_generate(unsigned int nof_bits,
             BCRYPT_KEY_HANDLE *h_generated_key /* out */)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    ULONG key_size;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_rsa_alg;
    BCRYPT_KEY_HANDLE h_key = NULL;

    /* Does key size fall within supported range? */
    if ((nof_bits < 512) || (nof_bits > 16384) || ((nof_bits % 64) != 0)) {
        E_BCRYPT_err(rsa_generate, R_INCORRECT_USAGE,
                     "Requested key size not supported");
        goto done;
    }
    key_size = nof_bits;

    /* Get RSA CNG algorithm handle */
    if (alg_provider_rsa_get(&h_rsa_alg) != 1)
        goto done;

    /* Invoke key generation */
    cng_retval = BCryptGenerateKeyPair(h_rsa_alg, &h_key, key_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_generate, cng_retval, BCryptGenerateKeyPair,
                        "Generating CNG RSA key pair");
        goto done;
    }
    /* Commit to CNG */
    cng_retval = BCryptFinalizeKeyPair(h_key, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_generate, cng_retval, BCryptFinalizeKeyPair,
                        "Committing generated CNG RSA key");
        goto done;
    }

    *h_generated_key = h_key;
    result = 1;

done:
    if (result != 1) {
        rsa_bcrypt_release(h_key);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Signing */

/* Note that sig_len_out is an out-value only, it does not indicate the
 *   allocated length of sig_inout (unfortunately) */
static int
rsa_sign_digest(BCRYPT_KEY_HANDLE h_key, PVOID padding_info, ULONG padding_flag,
                const unsigned char *digest, unsigned int digest_len,
                unsigned char *sig_inout, unsigned int *sig_len_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG sig_len;

    CMN_DBG_PRECOND_NOT_NULL(digest);
    CMN_DBG_PRECOND_NOT_NULL(sig_inout);
    CMN_DBG_PRECOND_NOT_NULL(sig_len_out);

    /* Calculate the required length */
    cng_retval = BCryptSignHash(h_key, padding_info, (PUCHAR)digest, digest_len,
                                NULL, 0, &sig_len, padding_flag);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_sign_digest, cng_retval, BCryptSignHash,
                        "Getting length of RSA signature");
        goto done;
    }

    /* Do the signing */
    /* Write into the signature buffer directly, as the format is the
     *   same for both OpenSSL and CNG */
    cng_retval = BCryptSignHash(h_key, padding_info, (PUCHAR)digest, digest_len,
                                sig_inout, sig_len, &sig_len, padding_flag);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_sign_digest, cng_retval, BCryptSignHash,
                        "Signing hash with RSA key");
        goto done;
    }
    *sig_len_out = sig_len;
    result = 1;

done:

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/*Verification */

static int
rsa_verify_signed_digest(BCRYPT_KEY_HANDLE h_key, PVOID padding_info,
                         ULONG padding_flag, const unsigned char *digest,
                         unsigned int digest_len,
                         const unsigned char *signature,
                         unsigned int signature_len)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;
    ULONG b_sig_len;
    ULONG bytes_written;

    /* Query for CNG signature length to check if it has the right size */
    bytes_written = sizeof(b_sig_len);
    cng_retval =
        BCryptGetProperty(h_key, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&b_sig_len,
                          bytes_written, &bytes_written, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_verify_signed_digest, cng_retval, BCryptGetProperty,
                        "Getting RSA signature length");
        goto done;
    }
    if (signature_len != b_sig_len) {
        E_BCRYPT_err(rsa_verify_signed_digest, R_INCORRECT_USAGE,
                     "Verifying with wrong signature length");
        goto done;
    }

    /* Do the actual verification */
    cng_retval =
        BCryptVerifySignature(h_key, padding_info, (PUCHAR)digest, digest_len,
                              (PUCHAR)signature, signature_len, padding_flag);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_verify_signed_digest, cng_retval,
                        BCryptVerifySignature,
                        "Verifying signature with RSA key");
        goto done;
    }

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* Encryption and decryption */

static int
rsa_encrypt(BCRYPT_KEY_HANDLE *h_key, PVOID pad_info, ULONG pad_flags,
            int from_len, const unsigned char *from, unsigned char *to_inout,
            int *out_len_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = -1;
    NTSTATUS cng_retval;
    ULONG result_len;

    cng_retval = BCryptEncrypt(h_key, (PUCHAR)from, from_len, pad_info, NULL, 0,
                               NULL, 0, &result_len, pad_flags);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_encrypt, cng_retval, BCryptEncrypt,
                        "Getting output size before encrypting with RSA");
        goto done;
    }

    //result_len = from_len;
    cng_retval = BCryptEncrypt(h_key, (PUCHAR)from, from_len, pad_info, NULL, 0,
                               to_inout, result_len, &result_len, pad_flags);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_encrypt, cng_retval, BCryptEncrypt,
                        "Encrypting with RSA");
        goto done;
    }

    *out_len_out = result_len;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
rsa_decrypt(BCRYPT_KEY_HANDLE *h_key, PVOID pad_info, ULONG pad_flags,
            int from_len, const unsigned char *from, unsigned char *to_inout,
            int *out_len_out)
{
    CMN_DBG_TRACE_ENTER;

    int result = -1;
    NTSTATUS cng_retval;
    ULONG result_len;

    result_len = from_len;
    cng_retval = BCryptDecrypt(h_key, (PUCHAR)from, from_len, pad_info, NULL, 0,
                               to_inout, result_len, &result_len, pad_flags);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(rsa_decrypt, cng_retval, BCryptDecrypt,
                        "Decrypting with RSA");
        goto done;
    }

    *out_len_out = result_len;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* -------------------------------------- */
/* Actual implementations of RSA methods  */
/* -------------------------------------- */

static int
bcrypt_rsa_pub_enc(int from_len, const unsigned char *from,
                   unsigned char *to_inout, RSA *rsa, int padding_type)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    BCRYPT_KEY_HANDLE h_key = NULL;
    PVOID pad_info;
    ULONG pad_flag;
    BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
    int result_len;
#ifdef TRY_OAEP
    BCRYPT_OAEP_PADDING_INFO oaep_info;
    EVP_PKEY_CTX *pkey_ctx; /* Missing info :-( */
    EVP_MD *md;
    int retval;
#endif

    /* Convert OpenSSL formatted private key to BCrypt key */
    if (rsa_ossl_to_rsa_bcrypt_public(&h_key, rsa) != 1)
        goto done;

    /* Convert OpenSSL padding type into BCrypt padding flag */
    if (rsa_padding_type_to_flag(padding_type, &pad_flag) != 1)
        goto done;

    switch (padding_type) {
    case RSA_NO_PADDING:
        pad_info = NULL;
        break;
#ifdef TRY_OAEP
        /* Not possible at this moment with the way OpenSSL stores the OAEP info */
    case RSA_PKCS1_OAEP_PADDING:
        /* Query for the MD used */
        retval = EVP_PKEY_CTX_get_rsa_oaep_md(pkey_ctx, &md);
        if (retval != 1) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_ctrl, "Getting OAEP MD info");
            goto done;
        }
        /* Convert given md type into bcrypt algorithm name */
        if (md_type_to_algorithm(md, &oaep_info.pszAlgId) != 1)
            goto done;
        /* Query for the label and its length */
        retval = EVP_PKEY_CTX_get0_rsa_oaep_label(pkey_ctx, &oaep_info.pbLabel);
        if (retval < 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_ctrl, "Getting OAEP label info");
            goto done;
        }
        oaep_info.cbLabel = (ULONG)retval;
        /* Set the parameters to the bcrypt function */
        pad_info = &oaep_info;
        break;
#endif /* TRY_OAEP */
    case RSA_PKCS1_PADDING:
        /* Convert given md type into bcrypt algorithm name */
        pkcs1_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        pad_info = &pkcs1_info;
        break;
    default:
        E_BCRYPT_err(bcrypt_rsa_pub_enc, R_INCORRECT_USAGE,
                     "Encrypting with unexpected padding type");
        goto done;
    }

    /* Do the actual encryption with the given padding */
    if (rsa_encrypt(h_key, pad_info, pad_flag, from_len, from, to_inout,
                    &result_len) != 1)
        goto done;

    result = result_len;

done:
    rsa_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

/* BCrypt does not seem to support decryption with a public RSA key.
 *   Use the verify function instead. (But unfortunately, OpenSSL
 *   does not invoke the verify function when using PSS padding.) */
static int
bcrypt_rsa_pub_dec(int from_len, const unsigned char *from,
                   unsigned char *to_inout, RSA *rsa, int padding)
{
    CMN_DBG_API_ENTER;

    CMN_UNUSED(from_len);
    CMN_UNUSED(from);
    CMN_UNUSED(to_inout);
    CMN_UNUSED(rsa);
    CMN_UNUSED(padding);

    E_BCRYPT_err(
        bcrypt_rsa_pub_dec, R_INCORRECT_USAGE,
        "Decrypting with public key, should be invoking verify instead");

    CMN_DBG_API_LEAVE;
    return 0;
}

/* BCrypt does not seem to support encryption with a private RSA key.
 *   Use the sign function instead. (But unfortunately, OpenSSL
 *   does not invoke the sign function when using PSS padding.) */
static int
bcrypt_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                    RSA *rsa, int padding)
{
    CMN_DBG_API_ENTER;

    CMN_UNUSED(flen);
    CMN_UNUSED(from);
    CMN_UNUSED(to);
    CMN_UNUSED(rsa);
    CMN_UNUSED(padding);

    E_BCRYPT_err(
        bcrypt_rsa_priv_enc, R_INCORRECT_USAGE,
        "Encrypting with private key, should be invoking sign instead");

    CMN_DBG_API_LEAVE;
    return 0;
}

static int
bcrypt_rsa_priv_dec(int from_len, const unsigned char *from,
                    unsigned char *to_inout, RSA *rsa, int padding_type)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    BCRYPT_KEY_HANDLE h_key = NULL;
    PVOID pad_info;
    ULONG pad_flag;
    int result_len;
#ifdef TRY_OAEP
    BCRYPT_OAEP_PADDING_INFO oaep_info;
    EVP_PKEY_CTX *pkey_ctx; /* Missing info :-( */
    EVP_MD *md;
    int retval;
#endif

    /* Convert OpenSSL formatted private key to BCrypt key */
    if (rsa_ossl_to_rsa_bcrypt_private(&h_key, rsa) != 1)
        goto done;

    /* Convert OpenSSL padding type into BCrypt padding flag */
    if (rsa_padding_type_to_flag(padding_type, &pad_flag) != 1)
        goto done;

    switch (padding_type) {
    case RSA_NO_PADDING:
        pad_info = NULL;
        break;
#ifdef TRY_OAEP
    /* Not possible at this moment with the way OpenSSL stores the OAEP info */
    case RSA_PKCS1_OAEP_PADDING:
        /* Query for the MD used */
        retval = EVP_PKEY_CTX_get_rsa_oaep_md(pkey_ctx, &md);
        if (retval != 1) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_ctrl, "Getting OAEP MD info");
            goto done;
        }
        /* Convert given md type into bcrypt algorithm name */
        if (md_type_to_algorithm(md, &oaep_info.pszAlgId) != 1)
            goto done;
        /* Query for the label and its length */
        retval = EVP_PKEY_CTX_get0_rsa_oaep_label(pkey_ctx, &oaep_info.pbLabel);
        if (retval < 0) {
            E_BCRYPT_osslerr(EVP_PKEY_CTX_ctrl, "Getting OAEP label info");
            goto done;
        }
        oaep_info.cbLabel = (ULONG)retval;
        /* Set the parameters to the bcrypt function */
        pad_info = &oaep_info;
        break;
#endif /* TRY_OAEP */
    case RSA_PKCS1_PADDING:
        pad_info = NULL;
        break;
    default:
        E_BCRYPT_err(bcrypt_rsa_priv_dec, R_INCORRECT_USAGE,
                     "Decrypting with unexpected padding type");
        goto done;
    }

    /* Do the actual decryption with the given padding */
    if (rsa_decrypt(h_key, pad_info, pad_flag, from_len, from, to_inout,
                    &result_len) != 1)
        goto done;

    result = result_len;

done:
    rsa_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_rsa_init(RSA *rsa)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(rsa);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_rsa_finish(RSA *rsa)
{
    CMN_DBG_API_ENTER;

    int result = 0;

    CMN_UNUSED(rsa);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_rsa_sign(int md_type, const unsigned char *m, unsigned int m_length,
                unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_KEY_HANDLE h_key = NULL;
    ULONG padding_flag;
    LPCWSTR md_alg;
    PVOID padding_info;
    BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
#ifdef B_RSA_HAS_PSS
    BCRYPT_PSS_PADDING_INFO pss_info;
    const RSA_PSS_PARAMS *pss_params;
#endif

    /* Convert OpenSSL formatted private key to BCrypt key */
    if (rsa_ossl_to_rsa_bcrypt_private(&h_key, rsa) != 1)
        goto done;

    /* Convert OpenSSL digest type to the BCrypt equivalent */
    if (rsa_md_type_to_algorithm(md_type, &md_alg) != 1)
        goto done;

#ifdef B_RSA_HAS_PSS
    /* Get PSS params, if available */
    pss_params = RSA_get0_pss_params(rsa);
    if (pss_params != NULL) {
        /* Note: this currently never happens in OpenSSL because its 
         *   sign/verify implementation is broken */
        uint64_t salt_length;
        if (ASN1_INTEGER_get_uint64(&salt_length, pss_params->saltLength) !=
            1) {
            E_BCRYPT_osslerr(ASN1_INTEGER_get_uint64, "Converting salt length");
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

    /* Do the actual signing with the given padding */
    if (rsa_sign_digest(h_key, padding_info, padding_flag, m, m_length, sigret,
                        siglen) != 1)
        goto done;

    result = 1;

done:
    rsa_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_rsa_verify(int md_type, const unsigned char *m, unsigned int m_length,
                  const unsigned char *sigbuf, unsigned int siglen,
                  const RSA *rsa)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_KEY_HANDLE h_key = NULL;
    ULONG padding_flag;
    LPCWSTR md_alg;
    PVOID padding_info;
    BCRYPT_PKCS1_PADDING_INFO pkcs1_info;
#ifdef B_RSA_HAS_PSS
    BCRYPT_PSS_PADDING_INFO pss_info;
    const RSA_PSS_PARAMS *pss_params;
#endif

    /* Convert OpenSSL formatted public key to BCrypt key */
    if (rsa_ossl_to_rsa_bcrypt_public(&h_key, rsa) != 1)
        goto done;

    /* Convert OpenSSL digest type to the BCrypt equivalent */
    if (rsa_md_type_to_algorithm(md_type, &md_alg) != 1)
        goto done;

#ifdef B_RSA_HAS_PSS
    /* Get PSS params, if available */
    pss_params = RSA_get0_pss_params(rsa);
    if (pss_params != NULL) {
        /* Note: this currently never happens in OpenSSL because its
         *   sign/verify implementation is broken */
        uint64_t salt_length;
        if (ASN1_INTEGER_get_uint64(&salt_length, pss_params->saltLength) !=
            1) {
            E_BCRYPT_osslerr(ASN1_INTEGER_get_uint64, "Converting salt length");
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

    /* Do the actual verification with the given padding */
    if (rsa_verify_signed_digest(h_key, padding_info, padding_flag, m, m_length,
                                 sigbuf, siglen) != 1)
        goto done;

    result = 1;

done:
    rsa_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    BCRYPT_KEY_HANDLE h_key = NULL;

    CMN_UNUSED(e);
    CMN_UNUSED(cb);

    CMN_DBG_PRECOND_NOT_NULL(rsa);

    if (rsa_generate(bits, &h_key) != 1)
        goto done;
    if (rsa_bcrypt_to_rsa_ossl_private(rsa, h_key) != 1)
        goto done;

    result = 1;

done:
    rsa_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

/* ---------------------------------------------------------- */
/* Function that exposes the RSA methods to the outside world */
/* ---------------------------------------------------------- */

static RSA_METHOD *S_rsa_method = NULL;

const RSA_METHOD *
e_bcrypt_rsa_get(void)
{
    CMN_DBG_TRACE_ENTER;

    /* Nothing */

    CMN_DBG_TRACE_LEAVE;
    return S_rsa_method;
}

int
e_bcrypt_rsa_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    RSA_METHOD *method = NULL;

    CMN_DBG_ASSERT(S_rsa_method == NULL);

    method = RSA_meth_new("BCrypt RSA key", 0);
    if (method == NULL) {
        E_BCRYPT_osslerr(RSA_meth_new, "Creating RSA method struct");
        goto done;
    }

    RSA_meth_set_pub_enc(method, bcrypt_rsa_pub_enc);
    RSA_meth_set_pub_dec(method, bcrypt_rsa_pub_dec);
    RSA_meth_set_priv_enc(method, bcrypt_rsa_priv_enc);
    RSA_meth_set_priv_dec(method, bcrypt_rsa_priv_dec);
    RSA_meth_set_sign(method, bcrypt_rsa_sign);
    RSA_meth_set_verify(method, bcrypt_rsa_verify);
    RSA_meth_set_keygen(method, bcrypt_rsa_keygen);

    S_rsa_method = method;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_rsa_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(S_rsa_method);

    RSA_meth_free(S_rsa_method);
    S_rsa_method = NULL;

    result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}
