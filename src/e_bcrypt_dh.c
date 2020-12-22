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

#define CMN_THIS_FILE "src/e_bcrypt_dh.c"

/* Interface */
#include "e_bcrypt_dh.h"

/* Implementation */
#include "e_bcrypt_err.h"
#include "e_bcrypt_provider.h"
#include "e_bcrypt_secret.h"

/* Common header files */
#include "c_cmn.h"

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

static int
alg_provider_dh_get(BCRYPT_ALG_HANDLE *alg_handle)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    enum bcrypt_algorithm alg = B_DH_ALG;
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    static BCRYPT_ALG_HANDLE s_halg = NULL;

    if (!InitOnceExecuteOnce(&s_once, alg_provider_open, &alg, &s_halg)) {
        DWORD last_error = GetLastError();
        E_BCRYPT_winerr(alg_provider_dh_get, last_error, InitOnceExecuteOnce,
                        "DH one-time initialization");
        goto done;
    }

    *alg_handle = s_halg;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* -------------------------------------------------------- */
/* Static helper functions to implement the DH key methods */
/* -------------------------------------------------------- */

/* Key conversion functions */

/* Any key converted to a BCrypt key can be released with this function */
static void
dh_bcrypt_release(BCRYPT_KEY_HANDLE h_key)
{
    CMN_DBG_TRACE_ENTER;

    if (h_key != NULL) {
        NTSTATUS cng_retval = BCryptDestroyKey(h_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG DH key");
        }
    }

    CMN_DBG_TRACE_LEAVE;
}

/* Export BCrypt DH key to OpenSSL private DH key */
static int
dh_bcrypt_to_dh_ossl_private(DH *dh_inout, BCRYPT_KEY_HANDLE h_dh_key)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    NTSTATUS cng_retval;

    PUCHAR key_blob = NULL;
    DWORD key_blob_size;
    DWORD actual_blob_size;

    const BCRYPT_DH_KEY_BLOB *b_key;
    const BYTE *mod_bytes;
    const BYTE *gen_bytes;
    const BYTE *pub_bytes;
    const BYTE *priv_bytes;
    int mod_size;
    int gen_size;
    int pub_size;
    int priv_size;
    BIGNUM *modulus = NULL;
    BIGNUM *generator = NULL;
    BIGNUM *public_exponent = NULL;
    BIGNUM *private_key = NULL;
    BN_CTX *ctx = NULL;

    /* Export key from CNG */
    /* First get the memory size required for the export */
    cng_retval = BCryptExportKey(h_dh_key, NULL, BCRYPT_DH_PRIVATE_BLOB, NULL,
                                 0, &key_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_bcrypt_to_dh_ossl_private, cng_retval,
                        BCryptExportKey, "Getting size of CNG DH keypair");
        goto done;
    }

    /* Allocate the required memory */
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_MALLOC_FAILED,
                     "Creating CNG private DH key blob");
        goto done;
    }

    /* Do the actual export */
    cng_retval = BCryptExportKey(h_dh_key, NULL, BCRYPT_DH_PRIVATE_BLOB,
                                 key_blob, key_blob_size, &actual_blob_size, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_bcrypt_to_dh_ossl_private, cng_retval,
                        BCryptExportKey,
                        "Converting CNG DH keypair to OpenSSL keypair");
        goto done;
    }
    CMN_DBG_ASSERT_NOT_NULL(key_blob);
    CMN_DBG_ASSERT(key_blob_size == actual_blob_size);

    /* Get its contents */
    b_key = (const BCRYPT_DH_KEY_BLOB *)key_blob;
    if (b_key->dwMagic != BCRYPT_DH_PRIVATE_MAGIC) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_PASSED_UNKNOWN_VALUE,
                     "Received unexpected magic value when exporting DH key");
        goto done;
    }

    /* Construct OpenSSL key from CNG blob
     *
     * BCRYPT_DH_KEY_BLOB
     * Modulus[cbKey]
     * Generator[cbKey]
     * Public[cbKey]
     * PrivateExponent[cbKey]
     */

    /* They happen to be all the same :-) */
    mod_size = b_key->cbKey;
    gen_size = b_key->cbKey;
    pub_size = b_key->cbKey;
    priv_size = b_key->cbKey;

    mod_bytes = &(key_blob[sizeof(*b_key)]);
    modulus = BN_bin2bn(mod_bytes, mod_size, NULL);
    if (modulus == NULL) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_INTERNAL_ERROR,
                     "Converting DH modulus");
        goto done;
    }
    gen_bytes = &(mod_bytes[mod_size]);
    generator = BN_bin2bn(gen_bytes, gen_size, NULL);
    if (generator == NULL) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_INTERNAL_ERROR,
                     "Converting DH generator");
        goto done;
    }
    pub_bytes = &(gen_bytes[gen_size]);
    public_exponent = BN_bin2bn(pub_bytes, pub_size, NULL);
    if (public_exponent == NULL) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_INTERNAL_ERROR,
                     "Converting DH public exponent");
        goto done;
    }
    priv_bytes = &(pub_bytes[pub_size]);
    private_key = BN_bin2bn(priv_bytes, priv_size, NULL);
    if (private_key == NULL) {
        E_BCRYPT_err(dh_bcrypt_to_dh_ossl_private, R_INTERNAL_ERROR,
                     "Converting DH private exponent");
        goto done;
    }

    if (DH_set0_key(dh_inout, public_exponent, private_key) != 1) {
        E_BCRYPT_osslerr(DH_set0_key, "Converting DH key from CNG");
        goto done;
    }

    if (DH_set0_pqg(dh_inout, modulus, NULL, generator) != 1) {
        E_BCRYPT_osslerr(DH_set0_pqg, "Converting DH key from CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);
    BN_CTX_free(ctx);
    if (result != 1) {
        BN_free(private_key);
        BN_free(public_exponent);
        BN_free(generator);
        BN_free(modulus);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

static int
dh_ossl_to_dh_bcrypt_private(BCRYPT_KEY_HANDLE *h_key_out, int key_size,
                             const BIGNUM *modulus, const BIGNUM *generator,
                             const BIGNUM *public_exponent,
                             const BIGNUM *private_key)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int retval;
    PBYTE key_blob = NULL; /* to be allocated */
    PBCRYPT_DH_KEY_BLOB b_key;
    int key_blob_size;
    int mod_size;
    int gen_size;
    int pub_size;
    int priv_size;
    PBYTE mod_bytes;
    PBYTE gen_bytes;
    PBYTE pub_bytes;
    PBYTE priv_bytes;
    BCRYPT_ALG_HANDLE h_alg;
    NTSTATUS cng_retval;

    mod_size = BN_num_bytes(modulus);
    gen_size = BN_num_bytes(generator);
    pub_size = BN_num_bytes(public_exponent);
    priv_size = BN_num_bytes(private_key);

    if ((mod_size > key_size) || (gen_size > key_size) ||
        (pub_size > key_size) || (priv_size > key_size)) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_INTERNAL_ERROR,
                     "DH key size elements have inconsistent sizes");
        goto done;
    }

    /* Construct CNG blob from OpenSSL privatekey
     *
     * BCRYPT_DH_KEY_BLOB
     * Modulus[cbKey]
     * Generator[cbKey]
     * Public[cbKey]
     * PrivateExponent[cbKey]
     */
    key_size = mod_size;
    key_blob_size = sizeof(*b_key) + 4 * key_size;
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_MALLOC_FAILED,
                     "Allocating CNG private key blob");
        goto done;
    }
    CMN_memset(key_blob, 0, key_blob_size);

    b_key = (PBCRYPT_DH_KEY_BLOB)key_blob;
    b_key->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
    b_key->cbKey = mod_size;

    mod_bytes = &(key_blob[sizeof(*b_key)]);
    retval = BN_bn2bin(modulus, &mod_bytes[key_size - mod_size]);
    if (retval != mod_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_INTERNAL_ERROR,
                     "DH modulus has unexpected length");
        goto done;
    }
    gen_bytes = &(mod_bytes[key_size]);
    retval = BN_bn2bin(generator, &gen_bytes[key_size - gen_size]);
    if (retval != gen_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_INTERNAL_ERROR,
                     "DH generator has unexpected length");
        goto done;
    }
    pub_bytes = &(gen_bytes[key_size]);
    retval = BN_bn2bin(public_exponent, &pub_bytes[key_size - pub_size]);
    if (retval != pub_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_INTERNAL_ERROR,
                     "DH public exponent has unexpected length");
        goto done;
    }
    priv_bytes = &(pub_bytes[key_size]);
    retval = BN_bn2bin(private_key, &priv_bytes[key_size - priv_size]);
    if (retval != priv_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_private, R_INTERNAL_ERROR,
                     "DH private exponent has unexpected length");
        goto done;
    }

    /* Get CNG algorithm handle */
    if (alg_provider_dh_get(&h_alg) != 1)
        goto done;

    /* Import public key from constructed blob */
    cng_retval =
        BCryptImportKeyPair(h_alg, NULL, BCRYPT_DH_PRIVATE_BLOB, h_key_out,
                            key_blob, key_blob_size, BCRYPT_NO_KEY_VALIDATION);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_ossl_to_dh_bcrypt_private, cng_retval,
                        BCryptImportKeyPair,
                        "Importing DH public key into CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);

    CMN_DBG_API_LEAVE;
    return result;
}

static int
dh_ossl_to_dh_bcrypt_public(BCRYPT_KEY_HANDLE *h_key_out, int key_size,
                            const BIGNUM *modulus, const BIGNUM *generator,
                            const BIGNUM *public_exponent)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int retval;
    PBYTE key_blob = NULL; /* to be allocated */
    PBCRYPT_DH_KEY_BLOB b_key;
    int key_blob_size;
    int mod_size;
    int gen_size;
    int pub_size;
    PBYTE mod_bytes;
    PBYTE gen_bytes;
    PBYTE pub_bytes;
    BCRYPT_ALG_HANDLE h_alg;
    NTSTATUS cng_retval;

    mod_size = BN_num_bytes(modulus);
    gen_size = BN_num_bytes(generator);
    pub_size = BN_num_bytes(public_exponent);

    if ((mod_size > key_size) || (gen_size > key_size) ||
        (pub_size > key_size)) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_public, R_INTERNAL_ERROR,
                     "DH key size elements have inconsistent sizes");
        goto done;
    }

    /* Construct CNG blob from OpenSSL privatekey
     *
     * BCRYPT_DH_KEY_BLOB
     * Modulus[cbKey]
     * Generator[cbKey]
     * Public[cbKey]
     */
    key_blob_size = sizeof(*b_key) + 3 * key_size;
    key_blob = CMN_malloc(key_blob_size);
    if (key_blob == NULL) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_public, R_MALLOC_FAILED,
                     "Allocating CNG public key blob");
        goto done;
    }
    CMN_memset(key_blob, 0, key_blob_size);

    b_key = (PBCRYPT_DH_KEY_BLOB)key_blob;
    b_key->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    b_key->cbKey = mod_size;

    mod_bytes = &(key_blob[sizeof(*b_key)]);
    retval = BN_bn2bin(modulus, &mod_bytes[key_size - mod_size]);
    if (retval != mod_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_public, R_INTERNAL_ERROR,
                     "DH modulus has unexpected length");
        goto done;
    }
    gen_bytes = &(mod_bytes[key_size]);
    retval = BN_bn2bin(generator, &gen_bytes[key_size - gen_size]);
    if (retval != gen_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_public, R_INTERNAL_ERROR,
                     "DH generator has unexpected length");
        goto done;
    }
    pub_bytes = &(gen_bytes[key_size]);
    retval = BN_bn2bin(public_exponent, &pub_bytes[key_size - pub_size]);
    if (retval != pub_size) {
        E_BCRYPT_err(dh_ossl_to_dh_bcrypt_public, R_INTERNAL_ERROR,
                     "DH public exponent has unexpected length");
        goto done;
    }

    /* Get CNG algorithm handle */
    if (alg_provider_dh_get(&h_alg) != 1)
        goto done;

    /* Import public key from constructed blob */
    cng_retval =
        BCryptImportKeyPair(h_alg, NULL, BCRYPT_DH_PUBLIC_BLOB, h_key_out,
                            key_blob, key_blob_size, BCRYPT_NO_KEY_VALIDATION);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_ossl_to_dh_bcrypt_public, cng_retval,
                        BCryptImportKeyPair,
                        "Importing DH public key into CNG");
        goto done;
    }

    result = 1;

done:
    CMN_free(key_blob);

    CMN_DBG_API_LEAVE;
    return result;
}

/* Generation of DH key */

static int
dh_generate(unsigned int nof_bits, const BIGNUM *modulus,
            const BIGNUM *generator, BCRYPT_KEY_HANDLE *h_key_out /* out */)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    int retval;
    ULONG key_size;
    int mod_len;
    int gen_len;
    BCRYPT_DH_PARAMETER_HEADER *params_header;
    PBYTE params_blob = NULL;
    ULONG params_blob_size;
    PBYTE mod_bytes;
    PBYTE gen_bytes;
    NTSTATUS cng_retval;
    BCRYPT_ALG_HANDLE h_dh_alg;
    BCRYPT_KEY_HANDLE h_key = NULL;

    /* Does key size fall within supported range? */
    if ((nof_bits < 512) || (nof_bits > 4096) || ((nof_bits % 64) != 0)) {
        E_BCRYPT_err(dh_generate, R_NOT_SUPPORTED,
                     "Requested key size not supported");
        goto done;
    }

    /* Get DH CNG algorithm handle */
    if (alg_provider_dh_get(&h_dh_alg) != 1)
        goto done;

    /* Invoke key generation */
    cng_retval = BCryptGenerateKeyPair(h_dh_alg, &h_key, nof_bits, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_generate, cng_retval, BCryptGenerateKeyPair,
                        "Generating CNG DH key pair");
        goto done;
    }

    /* Construct blob with generation parameters, if given */
    if ((modulus != NULL) && (generator != NULL)) {
        /* BCRYPT_DH_PARAMETER_HEADER
         * Modulus[cbKey]
         * Generator[cbKey] */
        key_size = (nof_bits + 7) / 8;
        params_blob_size = sizeof(*params_header) + 2 * key_size;
        params_blob = CMN_malloc(params_blob_size);
        if (params_blob == NULL) {
            E_BCRYPT_err(dh_generate, R_MALLOC_FAILED,
                         "Constructing DH parameters blob");
            goto done;
        }
        memset(params_blob, 0, params_blob_size);

        params_header = (BCRYPT_DH_PARAMETER_HEADER *)params_blob;
        params_header->cbLength = params_blob_size;
        params_header->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
        params_header->cbKeyLength = key_size;

        mod_len = BN_num_bytes(modulus);
        mod_bytes = &(params_blob[sizeof(*params_header)]);
        retval = BN_bn2bin(modulus, &mod_bytes[key_size - mod_len]);
        if (retval != mod_len) {
            E_BCRYPT_osslerr(BN_bn2bin, "Serializing DH modulus");
            goto done;
        }

        gen_len = BN_num_bytes(generator);
        gen_bytes = &(mod_bytes[key_size]);
        retval = BN_bn2bin(generator, &gen_bytes[key_size - gen_len]);
        if (retval != gen_len) {
            E_BCRYPT_osslerr(BN_bn2bin, "Serializing DH generator");
            goto done;
        }

        cng_retval = BCryptSetProperty(h_key, BCRYPT_DH_PARAMETERS, params_blob,
                                       params_blob_size, 0);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winerr(dh_generate, cng_retval, BCryptSetProperty,
                            "Setting properties for DH key generation");
            goto done;
        }
    }

    /* Commit/calculate */
    cng_retval = BCryptFinalizeKeyPair(h_key, 0);
    if (NT_FAILED(cng_retval)) {
        E_BCRYPT_winerr(dh_generate, cng_retval, BCryptFinalizeKeyPair,
                        "Committing generated CNG DH key");
        goto done;
    }

    *h_key_out = h_key;
    result = 1;

done:
    CMN_free(params_blob);
    if (result != 1) {
        dh_bcrypt_release(h_key);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* -------------------------------------- */
/* Actual implementations of DH methods  */
/* -------------------------------------- */

static int
bcrypt_dh_compute_key(unsigned char *key, const BIGNUM *bn_pub_key, DH *dh)
{
    CMN_DBG_API_ENTER;

    /* Returns the length of the computed key, -1 is failure*/
    int result = -1;
    NTSTATUS cng_retval;
    int key_size;
    const BIGNUM *modulus;
    const BIGNUM *generator;
    const BIGNUM *private_key;
    const BIGNUM *public_exponent;
    BCRYPT_KEY_HANDLE h_my_private_key = NULL;
    BCRYPT_KEY_HANDLE h_other_public_key = NULL;
    PUCHAR cng_key = NULL;
    ULONG cng_outlen;

    CMN_DBG_PRECOND_NOT_NULL(key);
    CMN_DBG_PRECOND_NOT_NULL(bn_pub_key);
    CMN_DBG_PRECOND_NOT_NULL(dh);

    key_size = DH_size(dh);
    DH_get0_pqg(dh, &modulus, NULL, &generator);
    if ((modulus == NULL) || (generator == NULL)) {
        E_BCRYPT_err(
            dh_ossl_to_dh_bcrypt_private, R_INCORRECT_USAGE,
            "Converting incomplete DH key, modulus and/or generator missing");
        goto done;
    }
    DH_get0_key(dh, &public_exponent, &private_key);
    if ((private_key == NULL) || (bn_pub_key == NULL)) {
        E_BCRYPT_err(bcrypt_dh_compute_key, R_INCORRECT_USAGE,
                     "Private and/or public exponent missing");
    }

    /* Convert local (private) key to BCrypt */
    if (dh_ossl_to_dh_bcrypt_private(&h_my_private_key, key_size, modulus,
                                     generator, public_exponent,
                                     private_key) != 1)
        goto done;

    /* Convert remote (public) key to BCrypt */
    if (dh_ossl_to_dh_bcrypt_public(&h_other_public_key, key_size, modulus,
                                    generator, bn_pub_key) != 1)
        goto done;

        /* Determine shared secret */
#if B_NO_RAW_SECRET
    if (secret_derive(h_my_private_key, h_other_public_key,
                      BCRYPT_DH_PRIVATE_MAGIC, &cng_key, &cng_outlen) != 1)
        goto done;
#else
    if (secret_derive(h_my_private_key, h_other_public_key, &cng_key,
                      &cng_outlen) != 1)
        goto done;
#endif

    /* Verfiy that the size is as expected */
    if (cng_outlen != (ULONG)(DH_bits(dh) + 7) / 8) {
        E_BCRYPT_err(bcrypt_dh_compute_key, R_INTERNAL_ERROR,
                     "Secret agreement length different than expected");
        goto done;
    }

    memcpy(key, cng_key, cng_outlen);
    result = cng_outlen;

done:
    CMN_free(cng_key);

    if (h_my_private_key != NULL) {
        cng_retval = BCryptDestroyKey(h_my_private_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG DH private key");
        }
    }
    if (h_other_public_key != NULL) {
        cng_retval = BCryptDestroyKey(h_other_public_key);
        if (NT_FAILED(cng_retval)) {
            E_BCRYPT_winwarn(cng_retval, BCryptDestroyKey,
                             "Destroying temporary CNG DH public key");
        }
    }

    CMN_DBG_API_LEAVE;
    return result;
}

static int
bcrypt_dh_generate_key(DH *dh)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int nof_bits;
    const BIGNUM *modulus;
    const BIGNUM *generator;
    BCRYPT_KEY_HANDLE h_key = NULL;

    CMN_DBG_PRECOND_NOT_NULL(dh);

    /* Get generation parameters */
    nof_bits = DH_bits(dh);
    DH_get0_pqg(dh, &modulus, NULL, &generator);
    if ((modulus == NULL) != (generator == NULL)) {
        E_BCRYPT_err(
            bcrypt_dh_generate_key, R_INCORRECT_USAGE,
            "Inconsisten modulus/generator settings in DH key generation");
        goto done;
    }

    if (dh_generate(nof_bits, modulus, generator, &h_key) != 1)
        goto done;
    if (dh_bcrypt_to_dh_ossl_private(dh, h_key) != 1)
        goto done;

    result = 1;

done:
    dh_bcrypt_release(h_key);

    CMN_DBG_API_LEAVE;
    return result;
}

/* --------------------------------------------------------- */
/* Function that exposes the DH methods to the outside world */
/* --------------------------------------------------------- */

static DH_METHOD *S_dh_method = NULL;

const DH_METHOD *
e_bcrypt_dh_get(void)
{
    CMN_DBG_TRACE_ENTER;

    /* Nothing */

    CMN_DBG_TRACE_LEAVE;
    return S_dh_method;
}

int
e_bcrypt_dh_initialize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;
    DH_METHOD *method = NULL;

    CMN_DBG_ASSERT(S_dh_method == NULL);

    method = DH_meth_new("BCrypt DH method", 0);
    if (method == NULL) {
        E_BCRYPT_osslerr(DH_meth_new, "Creating DH method struct");
        goto done;
    }

    DH_meth_set_compute_key(method, bcrypt_dh_compute_key);
    DH_meth_set_generate_key(method, bcrypt_dh_generate_key);

    S_dh_method = method;
    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

int
e_bcrypt_dh_finalize(void)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    CMN_DBG_PRECOND_NOT_NULL(S_dh_method);

    DH_meth_free(S_dh_method);
    S_dh_method = NULL;

    result = 1;

    CMN_DBG_TRACE_LEAVE;
    return result;
}
