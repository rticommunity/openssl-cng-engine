
// (c) 2020 Copyright, Real-Time Innovations, Inc. (RTI)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test_bcrypt.h"
#include "test_bcrypt_ossl.h"

#include <openssl/rsa.h>

// ----------------------------------------------------------------------------
//
// OpenSSL helper functions
// If any of the functions in this section throw exceptions, it is most likely
//   a configuration error
//
// ----------------------------------------------------------------------------

static bcrypt_testing::unique_EVP_PKEY
construct_hardcoded_rsa_key_public(
    const bcrypt_testing::Number &num_modulo,
    const bcrypt_testing::Number &num_exponent)
{
    bcrypt_testing::unique_BIGNUM bn_modulo(
        BN_bin2bn(num_modulo.data(), (int)num_modulo.size(), NULL));
    if (!bn_modulo) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_exponent(
        BN_bin2bn(num_exponent.data(), (int)num_exponent.size(), NULL));
    if (!bn_exponent) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_RSA rsa(RSA_new());
    if (!rsa) throw bcrypt_testing::ossl_error();

    // The only variant is set0, but our managed pointers will always invoke
    //   BN_free when going out of scope. Therefore, duplicate the BNs
    if (RSA_set0_key(rsa.get(), BN_dup(bn_modulo.get()),
        BN_dup(bn_exponent.get()), NULL) != 1)
        throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();

    if (EVP_PKEY_set1_RSA(result.get(), rsa.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}

// Given n, e and d, try to calculate p and q with p q = n
// For a description of the algorithm, check out HAC section 8.2.2
//   (HAC = Handbook of Applied Cryptography)
// Note: this function is just for fun and convenience.
//   You may use it when adding new tests that include the modulo
//   but not its prime factors, like the NIST vectors do. Once you have
//   calculated the primes using this function, you can add them to the
//   test parameters.
static bool
factorize_modulo(
    const BIGNUM *modulo,
    const BIGNUM *exponent,
    const BIGNUM *priv_key,
    BIGNUM *p_inout,
    BIGNUM *q_inout)
{
    // Context used for multiplications and powers
    bcrypt_testing::unique_BN_CTX ctx(BN_CTX_new());
    if (!ctx) throw bcrypt_testing::ossl_error();

    // Start with e to build ed - 1
    bcrypt_testing::unique_BIGNUM ed_min_1(BN_dup(exponent));
    if (!ed_min_1) throw bcrypt_testing::ossl_error();
    // ed
    if (BN_mul(ed_min_1.get(), ed_min_1.get(), priv_key, ctx.get()) != 1)
        throw bcrypt_testing::ossl_error();
    // ed - 1
    if (BN_sub_word(ed_min_1.get(), 1) != 1)
        throw bcrypt_testing::ossl_error();

    // Determine t and s, when ed - 1 = 2^s t with t odd
    bcrypt_testing::unique_BIGNUM t(BN_dup(ed_min_1.get()));
    if (!t) throw bcrypt_testing::ossl_error();
    unsigned int s = 0;
    while (BN_is_odd(t.get()) != 1) {
        s++;
        // Divide by 2
        if (BN_rshift1(t.get(), t.get()) != 1)
            throw bcrypt_testing::ossl_error();
    }

    // Need to compare to n-1 at some point, so create its BN
    bcrypt_testing::unique_BIGNUM n_min_1(BN_dup(modulo));
    if (!n_min_1) throw bcrypt_testing::ossl_error();
    // n - 1
    if (BN_sub_word(n_min_1.get(), 1) != 1) throw bcrypt_testing::ossl_error();

    // Likelihood of success with every try is >50%, so this is
    // expected to be sufficient
    unsigned int tries_left = 100;
    bool found = false;
    do {
        // Not really needed, but let's do each test with a random 32-bits prime a
        const int a_bits = 32;
        bcrypt_testing::unique_BIGNUM a(BN_new());
        if (!a) throw bcrypt_testing::ossl_error();
        if (BN_generate_prime_ex(a.get(), a_bits, 0, NULL, NULL, NULL) != 1)
            throw bcrypt_testing::ossl_error();

        // a^(2^(i-1)t) (in the loop), starting with i = 1
        bcrypt_testing::unique_BIGNUM a_pow_prev(BN_new());
        if (!a_pow_prev) throw bcrypt_testing::ossl_error();
        if (BN_mod_exp(a_pow_prev.get(), a.get(), t.get(), modulo, ctx.get()) != 1)
            throw bcrypt_testing::ossl_error();

        // a^((2^i)t) (in the loop)
        bcrypt_testing::unique_BIGNUM a_pow(BN_new());
        if (!a_pow) throw bcrypt_testing::ossl_error();

        bool no_fit = false;
        for (unsigned int i = 1; (i <= s) && !found && !no_fit; i++) {
            // Next power in the sequence
            if (BN_mod_mul(a_pow.get(), a_pow_prev.get(), a_pow_prev.get(),
                modulo, ctx.get()) != 1)
                throw bcrypt_testing::ossl_error();

            // Check if it is equal to 1
            if (BN_is_one(a_pow.get()) != 1) {
                // Not there yet, the new one becomes the previous
                a_pow.swap(a_pow_prev);
            } else {
                // This may be a solution. Double check that the previous one
                //   was not equal to 1 or n-1
                if ((BN_is_one(a_pow_prev.get()) != 1) &&
                    (BN_cmp(a_pow_prev.get(), n_min_1.get()) != 0))
                {
                    // This is it, calculate GCD of a^(2^(i-1)t)-1 and n
                    if (BN_sub_word(a_pow_prev.get(), 1) != 1)
                        throw bcrypt_testing::ossl_error();
                    if (BN_gcd(p_inout, a_pow_prev.get(), modulo, ctx.get()) != 1)
                        throw bcrypt_testing::ossl_error();

                    // q = n / p. Double check remainder is 0
                    bcrypt_testing::unique_BIGNUM rem(BN_new());
                    if (BN_div(q_inout, rem.get(), modulo, p_inout, ctx.get()) != 1)
                        throw bcrypt_testing::ossl_error();
                    if (BN_is_zero(rem.get()) != 1)
                        throw bcrypt_testing::ossl_error();
                    found = true;
                } else {
                    // Unfortunately, does not meet the criteria -- this
                    //   is expected to happen in less than 50% of the cases
                    no_fit = true;
                }
            }
        }
        tries_left--;
    } while (!found && (tries_left != 0));

#if 0
// For some reason, these lines make VS identify an 8 bytes mem leak
#include <openssl/crypto.h>
    {
        char *modulo_str = BN_bn2hex(modulo);
        std::cerr << "modulo: " << modulo_str << std::endl;
        OPENSSL_free(modulo_str);

        if (found) {
            char *p_str = BN_bn2hex(p_inout);
            char *q_str = BN_bn2hex(q_inout);
            std::cerr << "prime1: " << p_str << std::endl;
            std::cerr << "prime2: " << q_str << std::endl;
            OPENSSL_free(p_str);
            OPENSSL_free(q_str);
        } else {
            std::cerr << "Failed to factorize" << std::endl;
        }
    }
#endif

    return found;
}

static bcrypt_testing::unique_EVP_PKEY
construct_hardcoded_rsa_key(
    const bcrypt_testing::Number &num_modulo,
    const bcrypt_testing::Number &num_exponent,
    const bcrypt_testing::Number &num_priv_key,
    const std::optional<bcrypt_testing::Number> &num_prime1,
    const std::optional<bcrypt_testing::Number> &num_prime2)
{
    bcrypt_testing::unique_BIGNUM bn_modulo(
        BN_bin2bn(num_modulo.data(), (int)num_modulo.size(), NULL));
    if (!bn_modulo) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_exponent(
        BN_bin2bn(num_exponent.data(), (int)num_exponent.size(), NULL));
    if (!bn_exponent) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_privkey(
        BN_bin2bn(num_priv_key.data(), (int)num_priv_key.size(), NULL));
    if (!bn_privkey) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_RSA rsa(RSA_new());
    if (!rsa) throw bcrypt_testing::ossl_error();

    // The only variant is set0, but our managed pointers will always invoke
    //   BN_free when going out of scope. Therefore, duplicate the BNs
    if (RSA_set0_key(rsa.get(), BN_dup(bn_modulo.get()),
        BN_dup(bn_exponent.get()), BN_dup(bn_privkey.get())) != 1)
        throw bcrypt_testing::ossl_error();

    // Engine requires p and q to be set, so calculate those if needed
    if (num_prime1.has_value() && num_prime2.has_value()) {

        bcrypt_testing::unique_BIGNUM bn_prime1(
            BN_bin2bn(num_prime1.value().data(), (int)num_prime1.value().size(), NULL));
        if (!bn_prime1) throw bcrypt_testing::ossl_error();

        bcrypt_testing::unique_BIGNUM bn_prime2(
            BN_bin2bn(num_prime2.value().data(), (int)num_prime2.value().size(), NULL));
        if (!bn_prime2) throw bcrypt_testing::ossl_error();

        // And set them
        if (RSA_set0_factors(rsa.get(),
            BN_dup(bn_prime1.get()), BN_dup(bn_prime2.get())) != 1)
            throw bcrypt_testing::ossl_error();

    } else {

        bcrypt_testing::unique_BIGNUM bn_prime1(BN_new());
        if (!bn_prime1) throw bcrypt_testing::ossl_error();
        bcrypt_testing::unique_BIGNUM bn_prime2(BN_new());
        if (!bn_prime2) throw bcrypt_testing::ossl_error();

        if (!factorize_modulo(bn_modulo.get(), bn_exponent.get(),
            bn_privkey.get(), bn_prime1.get(), bn_prime2.get()))
            throw bcrypt_testing::ossl_error();

        // And set them
        if (RSA_set0_factors(rsa.get(),
            BN_dup(bn_prime1.get()), BN_dup(bn_prime2.get())) != 1)
            throw bcrypt_testing::ossl_error();

    }

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();

    if (EVP_PKEY_set1_RSA(result.get(), rsa.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}

// ----------------------------------------------------------------------------
//
// RSA value-parameterized tests for signature verification
// Note: they currently all assume SHA-256
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct RsaVerifyParams {
    int sha_nid;
    struct {
        const char *modulus;
        const char *exponent;
    } key;
    const char* was_signed;
    const char* signature;
    int padding_type;
    bool passes;
};

static const RsaVerifyParams rsa_verify_params[] = {
{
    // sha_nid
    NID_sha256,
    // key, 1024 bits
    {
        // modulus
        "8592b5850b9ba96e7faecbdd67e50ed5fb2018fda0bc6a09ab6345910fc445ac"
        "6bdb0e7a4c6b72c9441649c9e78109bbaa1d79f9fafb8794a1a06cb638bd8f3c"
        "3416d44c43cf862b8ac1d5006310b05a7760d341d07077ae775f1695061d3c72"
        "97dd3ab8fc5d03d09ed1602a1bb69891bb377fd0aad6cd90f8b207467db36279",
        // exponent
        "eef211"
    },
    // was_signed
    "23d29062797ec367d664542872324b63a72305caed23d04b0834b594801095d7"
    "521078cae54c21f33f04e622793fbe3f70b19c45bee2fb8fe98dba53d9462b6c"
    "9060675c150ee491b1c849e75ef1806f7db60d6fc7399fa986efe5e00546a399"
    "458c051ff10c33c9947a257f0a91b97b35fa034df170e4224922de45eb5826e6",
    // signature
    "02d07177f91c0db0b74e34b532aa18673d27fdee370b7aa9094ef765c9a8278b"
    "7128f1bd24fd3992e6376f83bdea9e505be10de15163286a7c9d9873bdbcffe0"
    "535f9f8cb0dd99ba34e24ec462e4ad03618258b66894daeac9415545e030bd96"
    "3f2beb8d089183ec7ff1be67e6f94e6871d42fb7d7c694682a9f4af599bfdf81",
    // padding_type
    RSA_PKCS1_PADDING,
    // passes
    false
},
{
    // sha_nid
    NID_sha256,
    // key, 1024 bits
    {
        // modulus
        "8592b5850b9ba96e7faecbdd67e50ed5fb2018fda0bc6a09ab6345910fc445ac"
        "6bdb0e7a4c6b72c9441649c9e78109bbaa1d79f9fafb8794a1a06cb638bd8f3c"
        "3416d44c43cf862b8ac1d5006310b05a7760d341d07077ae775f1695061d3c72"
        "97dd3ab8fc5d03d09ed1602a1bb69891bb377fd0aad6cd90f8b207467db36279",
        // exponent
        "eef211",
    },
    // was_signed
    "1e422f898ff258a99bc53648541709b3a3bba5828d36d070b42bec6a2117d6e6"
    "403f0d762ce6179d2dc220e180b1e52156a9d0291eed64840787dc91c1f20fda"
    "841797a0547b32bb83b668a177276fc4aee64b21fefa391522cc4e7372dc5cd5"
    "f2b3152f8e1973aaa48757afc3df7041b35b5e91b5c317cc0be48a38bb3d837f",
    // signature
    "2e37c8221597f7e2b1970c40a50db5fefde31b1dff1e9b9d6a70b023acb01497"
    "1580eddf1d67f15d9fbbddfcdf49cda14ccb7516c33b787a3a3fd43d005d02de"
    "10f93ffc99585ae5dfaa766c0f1f5bfa62e50e76a059a4a1e814c1ee9836e015"
    "95731dce48f94aa1ae36d9c5165a3eb28013fac271e091f7018fe96ec26009c1",
    // padding_type
    RSA_PKCS1_PADDING,
    // passes
    true
}
, {
    // sha_nid
    NID_sha256,
    // key, 2048 bits
    {
        // modulus
        "a17a08272e656cf600f4650ef0952b15d568d9fb7f1b3f3559aa3792743f7d89"
        "5e4e26dec2bf09996de8a99f7c434bc25b0c7d61e83fe5647c213b19902abfa0"
        "53321a16048642cd3800de26172eb39ccab029130ceb82e5c25c676e89007cb0"
        "0666a2d8f64e59fea64628cbec9c361abe25841551db01f58b80ab17f02a93cb"
        "aaffc2630ffb6f56f206b8a6f8e0f1e5790652e7c7227258dbcd5924e94876f9"
        "83ed02e4e82272f5d44967bc501d1515d80dc25d5c838d0357d0d1704b0253d6"
        "e78802c02931000fea2e865c90b266c8a0b472e8eb17456777973342da6978cb"
        "45d2100cf91ca6f6d69ff30ee8f3164bfb180de0b355c067bd8f1a8544b9aac9",
        // exponent
        "66a13d"
    },
    // was_signed
    "41c00eae64f3e330222e114541eeb5eae1a705ca0c0687a68e7982fa07f1b3de"
    "3ee7402ab89df2dd8aa69ec06ba8e4460d611cb7aee88e8dea35e11fd3e4d77c"
    "4336379a71590ab0c3e909e0e3b6571915c86c3cc8a0517d6ac1130d816f72f6"
    "f8b7d946b6af936f76ff3beed2a0742ba0e4dba082b73a3eb924ff0c3a1bec12",
    // signature
    "13165444a1f039da049b998e332cf7655149975713b5378ac5772f2e176ddbf3"
    "38a25e297d873cca5f19eb4e4157c532d06249d1e99c2857f8d74bb74cc7593b"
    "c872daf5b45541a373aadc43a0711b3b2f27ccfed06d9578b2a3c7d10a12e398"
    "d0302f86e05f154e3cfd2a0e072aae157cae529bd5688fd0ccea22f58181d069"
    "eaa0957a5b0eaa2e3f5a4aeaf3d1512a43dd2f8434579eb57e23852d7323c5dd"
    "22359e9dfec59dd75ee3b8e234a41863fe0a68c46f777a9f48887a786cfaa40d"
    "b1c7d9e04efb8a882d8169764b47a013b5d1d15f4cbf758adc83c53e9548e77d"
    "e20f14b3b5f064465beaaa32ee41755aa48264a14df837ce5fb85a5ab91bf6eb",
    // padding_type
    RSA_PKCS1_PADDING,
    // passes
    true
},
{
    // sha_nid
    NID_sha384,
    // key, 3072 bits
    {
        // modulus
        "e1b23c29762d8572f1d41f1e7a846876d9901705bb4b3e0228ae65b2572dd1b3"
        "305f4d42a7704dda5934260ae9afb1eb34e7d865bbe11ae16d292f170711487e"
        "bce1d7363cd00acda5894f06127c1d4a7d9897373b4767a118b1646bc7a38086"
        "bc7d359067e9857b8b8642294cd08bab7646ee8ae0b3c7a51527a58ead49dabd"
        "11c3ee8326dade7f803cecb906c73aced669d5c3aed02c373d51bba4ffa98018"
        "892245f1ee6b035d52a3ccacb2c28062e572f213d607bb403725b34c65ea54bf"
        "70c0613e1a8d0552489787e3dc16c0b8cc7ca2d0b4d3e37d1c448a1ca4dcba20"
        "c146e78e2a6b3be888c7f65e49a47fe83e491dc33c684a1fd8acea8be091fdb7"
        "0945c889df40431241e96a58cf7042f7a54f236ab01214a4e17d713945f79f60"
        "5a8bc1bb6a2c4a342537b95beb92bcd722b68c14c346a1578c567f3ae277a46c"
        "264f4e4ef324ec2cc20ad43fbaf4035df169675575374de658df91cb5b3830bb"
        "31f69a8161c98f3b7f9e5983d96cbd9204c5e356980589c2df25188c474191bf",
        // exponent
        "3bd4ff"
    },
    // was_signed
    "8f3b827a1dc3967aa2e26c9d9052a97e64b047c186cf980070528708137a2246"
    "763c557ca197f8b8b9240d876cef42669085be79064e1980e51dac06d4060cdb"
    "b870d1c5906a9c739c4358b2c554bfe4392120ad56a160efc9d940f9f7b0ddfb"
    "9cfe7dbdb1e688919466d587632c27dfa8abf8c43c6f753765adc949421f9e8d",
    // signature
    "a5e1136bc2db78827f97e435352303519df3c6ba149748ecea4c493f3355def8"
    "f94beb1ab45870d8bb1e32bb10c6cda4546c0bcf90da0758fa1e99b22742302f"
    "f17c7d5f0c5580a727304066204f524dd206e1a2a232d4394b74f3daeebc81d8"
    "609034dafec29620427caaa72f648fbf39028ff685925b1b7ae4b53e154ca938"
    "21b6b152da380217a2f82c864437df45c32253a9e3ecfcda3444f5db879cd12f"
    "2fe80d0b88a6fad7cb69303b82e1ed0b761e9f829fafbf4a7027fa2a6164f770"
    "1684f7aafd8b5dbf41e6d4031ca28bb4ce360fb3815c33fdb6051c9741ff4f9e"
    "bffcfd2f52873ba5567c17d40eb8a92af139b21a184b2e0740e0ade97effeea7"
    "33cb2e1fe7ff65077c200b36e544f61e90dab2f524a74ed46f10d5244509faad"
    "c47f8bb57cac5026e00d1438b24f328dd5fa11fa3add3acd33b20f3c75b1007b"
    "cb5379cd8cd8e0f964dacda0157952f41e128ac43878c55acc5967cc2fc63101"
    "0594248a439820df0ab1b7bd1be5f81bb026016dcc65a674d9ea03bf1958e591",
    // padding_type
    RSA_PKCS1_PADDING,
    // passes
    true
},
{
    // sha_nid
    NID_sha256,
    // key, 2048 bits
    {
        // modulus
        "a17a08272e656cf600f4650ef0952b15d568d9fb7f1b3f3559aa3792743f7d89"
        "5e4e26dec2bf09996de8a99f7c434bc25b0c7d61e83fe5647c213b19902abfa0"
        "53321a16048642cd3800de26172eb39ccab029130ceb82e5c25c676e89007cb0"
        "0666a2d8f64e59fea64628cbec9c361abe25841551db01f58b80ab17f02a93cb"
        "aaffc2630ffb6f56f206b8a6f8e0f1e5790652e7c7227258dbcd5924e94876f9"
        "83ed02e4e82272f5d44967bc501d1515d80dc25d5c838d0357d0d1704b0253d6"
        "e78802c02931000fea2e865c90b266c8a0b472e8eb17456777973342da6978cb"
        "45d2100cf91ca6f6d69ff30ee8f3164bfb180de0b355c067bd8f1a8544b9aac9",
        // exponent
        "66a13d"
    },
    // was_signed
    "be91864d3728f895c689f09b28484138e0afa29589bba7486a68f0bf4b2ea1e2"
    "87cc11f46344c7ba9e27a2e049125798d97921847ba3b3d6a7f672b6f875e1e4"
    "3b875c9ec6fa0ac40b470d3a6c18fb8e510792da78a9a7ec8dcb60a5fbfba39f"
    "014bce120851a9f9347299703961166170e25e5f2ad46bd2446e2355fbc9d05c",
    // signature
    "631529e0b149ee1528d514861cac711eab8c01c1c22c7ff6ccbc08783a1ccb27"
    "48c22e57a1deefa867dcb1ae74c40b1969db2cee64c0706af8daf4c9e91c1267"
    "2d8f0849af4bd0c4c5f8e439a3ba7e3ddf38a9b38db545410dec0aa40522d6a3"
    "cbc2ab53a838298f0b93ae7d362158f04858fc33ec03fa6d3b7ff0f27d74cc4a"
    "bcedd25642f4d259d41511456004c24385ec32553ae5d5728a8f68707ddd6bfa"
    "51c2f4574e1c96ef4db0715675fa4fbc57b9091759eda387e16057e9d89797f6"
    "1df9196044b98667866e12c5132928eb735fa2d02c0ee7e08ed68d80fe1f76bd"
    "85756a3967c6d3e1378a754fecee72362928cb622731bb01231758ebcb805f5e",
    // padding_type
    RSA_PKCS1_PADDING,
    // passes
    false
}

#ifdef PSS_PADDING_SUPPORTED
// Due to OpenSSL's implementation of PSS, the BCrypt engine does not support it.
, {
    // key
    {
        // modulus
        "c4b9ea11f21cd93c01f56c4219db7d2e52581a6c968705c06588c036b6f51a27"
        "de43ba0006d6e54d9ee20dd8bc1c4787b4c45e9545cf98c7872100f6c3492f5c"
        "3f1ce2d28caf10fa611cc4a4ec94543fbb872ef0fc8bb9558360960e4e386874"
        "d3beef4e9662e8779304e8d09bfc290a6fc19e9908e8eb49336ef02224107bd7"
        "4de231f2610d76fa834baad342e87f5ffbd56ee8b459702425109af864401b71"
        "3cd9e96a01137a860c3079e13704d3328003136631062b198be8d644ed99a0c6"
        "2f94cf7971a0f2875592f35e362abcf2845a11ee98e5f01a515abd0d03646da2"
        "8123b45cea4cbfd7de9bc399fd9f05349a2d0386516f70f5c9a9970d3231ff73",
        // exponent
        "24f1bf"
    },
    // was_signed
    "f991a40a6c3cda01f1a2fed01ca0cf425588a071205eb997a147fa205f3ec104"
    "48090e53f56be512309cf445b3f6764d33f157749d5199c7a09ef6246bd5c793"
    "b85d24d9093c4d4b318b48e11727cc8bb7aa5ec8699aba7466e074e1887bdf2a"
    "51752ec42f16d956fe5943cbcf9c99a5e89bfd940c9fe447fcf3bc823d98d371",
    // signature
    "6b42514e88d93079d158336897dc34b450e424d61f6ddcf86fe8c9a368ae8a22"
    "c4ee4084c978b5169379da10ae6a6ae8cd80028e198cd0a8db532cd78a409f53"
    "baf7d231b545835b0dc06d594d76868d986889419a959268fd321bbc8bad5e80"
    "0e452fe1a1a2a5a851d542494473deb425171a2f37ffc4cf0600a8d561b20f77"
    "7407bbef1b596f92e518c0929e8bd52b015c2718d14443a56056f65015515673"
    "deef32ae5399ae71f97873ec1508f8c41d6a66a13017685134e5425c4b580a7f"
    "6986c26fb272f0ed215d6698dcec9e7c5258173b295b3611869254a538945de9"
    "52dedf291837df0d7a205e1b76b01140df4edce3afe7245d46ee3b292bb117b1",
    // padding_type
    RSA_PKCS1_PSS_PADDING,
    // passes
    true
}
#endif
};


class RsaVerifyTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<RsaVerifyParams>
{
public:
    RsaVerifyTest()
    {
        RsaVerifyParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_key_modulus =
            bcrypt_testing::number_from_string(params.key.modulus).value();
        bcrypt_testing::Number num_key_exponent =
            bcrypt_testing::number_from_string(params.key.exponent).value();
        bcrypt_testing::Bytes was_signed =
            bcrypt_testing::bytes_from_string(params.was_signed).value();
        bcrypt_testing::Number signature =
            bcrypt_testing::number_from_string(params.signature).value();

        // Initialize members from them
        digest_ = EVP_get_digestbynid(params.sha_nid);
        key_signer_ = construct_hardcoded_rsa_key_public(
            num_key_modulus, num_key_exponent);
        was_signed_ = was_signed;
        signature_ = signature;
        padding_type_ = params.padding_type;
        passes_ = params.passes;
    }

    const EVP_MD *digest_;
    bcrypt_testing::unique_EVP_PKEY key_signer_;
    bcrypt_testing::Bytes was_signed_;
    bcrypt_testing::Number signature_;
    int padding_type_;
    bool passes_;
};


TEST_P(RsaVerifyTest, Verify)
{
    OSSL_ASSERT_NE(nullptr, digest_);

    // Verify signature provided
    bcrypt_testing::unique_EVP_MD_CTX md_verify_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_verify_ctx);
    // No automatic memory management for this ctx because it gets
    // destroyed by ossl when the md ctx is destroyed
    EVP_PKEY_CTX *pkey_ctx_raw = NULL;
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyInit(md_verify_ctx.get(),
        &pkey_ctx_raw, digest_, NULL, key_signer_.get()));
    OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_padding(pkey_ctx_raw, padding_type_));
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyUpdate(md_verify_ctx.get(),
        was_signed_.data(), was_signed_.size()));
    if (passes_) {
        // Verification is expected to succeed
        OSSL_ASSERT_EQ(1, EVP_DigestVerifyFinal(md_verify_ctx.get(),
            signature_.data(), signature_.size()));
    } else {
        // Verification is not expected to succeed
        OSSL_ASSERT_EQ(0, EVP_DigestVerifyFinal(md_verify_ctx.get(),
            signature_.data(), signature_.size()));
        // There should be an error message...
        // Check if any error messages have been ignored
        OSSL_EXPECT_NE(bcrypt_testing::GetOpenSSLErrors(), "")
            << "Expected to find OpenSSL error string";
    }
}

INSTANTIATE_TEST_CASE_P(RsaVerifyTests, RsaVerifyTest,
    testing::ValuesIn(rsa_verify_params));


class RsaGenerateTest : public bcrypt_testing::Test
{
    // Nothing, this class is just to make sure the bcrypt testing
    //   baseclass gets invoked.
};

// Not yet supported by the engine
TEST_F(RsaGenerateTest, SimpleGenerate)
{
    bcrypt_testing::unique_EVP_PKEY_CTX key_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    OSSL_ASSERT_TRUE(key_ctx);
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen_init(key_ctx.get()));
    OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx.get(), 2048));
    EVP_PKEY* temp_rsa_key(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen(key_ctx.get(), &temp_rsa_key));
    bcrypt_testing::unique_EVP_PKEY rsa_key(temp_rsa_key);
    ASSERT_TRUE(rsa_key);
}



// Parameters for this type of test
struct RsaSignParams {
    int sha_nid;
    struct {
        const char *modulo;
        const char *exponent;
        const char *priv;
        const char *prime1;
        const char *prime2;
    } key;
    const char *to_be_signed;
    const char *signature;
};

static const RsaSignParams rsa_sign_params[] = {
{
    // sha_nid
    NID_sha256,
    // key, 2048 bits
    {
        // modulo
        "cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c"
        "c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef"
        "b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681"
        "5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30"
        "b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf"
        "a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11"
        "813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a"
        "8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d",
        // exponent
        "260445",
        // private
        "0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc938970"
        "9f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dc"
        "d65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f2"
        "19f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e"
        "0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56"
        "b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c"
        "8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773b"
        "af498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d",
        // prime1, optional
        "F364E16EF12017EC95B192308C01E087CEE619AB50A5D537CC01841DC92B30BC"
        "EF0D9F2C6BBD5DC10BDF5B9F6C354A4F9F210520CAA72B4F5C36B8D33F10324C"
        "55956141891E45B84B49F59EA5BFAC6FFA38900ACA5099AFCD02F6A8257C41CE"
        "5BB2E4153832B5C22F91EB389FA2035C3CF9B3374531C483CB30CEB007259B1D",
        // prime2, optional
        "D95C0995FABDFCBCCFE63E0F3262F806869AB571E1793E97234CBB9BD4B6872A"
        "7695389955CF6CE7245345A5DF8021F7D9519563AFBC2667F5311FAD093DE2C0"
        "2CD069109B630D68E3BF767F8A788A6ADD7AB199F2D8F6A40B7C1910D9DAB52A"
        "C80D0D333AACAB321A9309DC884DDD4DB637A0C1115AE3C08EFA683F99EB7331"
    },
    // to_be_signed
    "0c8491fc348d341fe85c46a56115f26035c59e6a2be765c44e2ec83d407ea096"
    "d13b57e3d0c758342246c47510a56793e5daeae1b96d4ab988378966876aa341"
    "b7d1c31bba59b7dbe6d1a16898eef0caca928f8ce84d5c64e025dc1679922d95"
    "e5cd3c6b994a385c5c8346469ef8764c0c74f5336191850c7f7e2b14be0027d8",
    // signature
    "cacc8d9f5ecd34c143488461135c4951676145c6e472b92f12f758046f172142"
    "fa388f285f3fff068242028829047e248059ed4fd39d2c5ade469dc7c39345e5"
    "114950d2031cc7465fe712c4041d05c756d3f2d88a46ceb99f2e24a52e958a03"
    "cd2519a9b137e62d5ca2b353f7b047b625c3602313fdb53c8db23d83951a599d"
    "b328fedc4ae06da89ce7f56259b5c8222f7bd3d9740478fd28e5810db78aee86"
    "23fdd39f603f8ddf98081d7873980c4eb0e22a9cd408f7c4134c12d2049a2d12"
    "0f4b62e6b382b997fc375ef7ac955fcf80b045c3d6385ff422dad350c6887053"
    "9068a162a2edbb93ceefed9677939b90bd3dfa0dc053460b4e2332efa692179a"
},
{
    // sha_nid
    NID_sha384,
    // key, 2048 bits
    {
        // modulo
        "cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c"
        "c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef"
        "b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681"
        "5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30"
        "b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf"
        "a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11"
        "813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a"
        "8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d",
        // exponent
        "260445",
        // private
        "0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc938970"
        "9f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dc"
        "d65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f2"
        "19f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e"
        "0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56"
        "b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c"
        "8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773b"
        "af498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d",
        // prime1, optional
        "F364E16EF12017EC95B192308C01E087CEE619AB50A5D537CC01841DC92B30BC"
        "EF0D9F2C6BBD5DC10BDF5B9F6C354A4F9F210520CAA72B4F5C36B8D33F10324C"
        "55956141891E45B84B49F59EA5BFAC6FFA38900ACA5099AFCD02F6A8257C41CE"
        "5BB2E4153832B5C22F91EB389FA2035C3CF9B3374531C483CB30CEB007259B1D",
        // prime2, optional
        "D95C0995FABDFCBCCFE63E0F3262F806869AB571E1793E97234CBB9BD4B6872A"
        "7695389955CF6CE7245345A5DF8021F7D9519563AFBC2667F5311FAD093DE2C0"
        "2CD069109B630D68E3BF767F8A788A6ADD7AB199F2D8F6A40B7C1910D9DAB52A"
        "C80D0D333AACAB321A9309DC884DDD4DB637A0C1115AE3C08EFA683F99EB7331"
    },
    // to_be_signed
    "6cd59fdd3efd893d091afdc3155d354f10d6d88167427a2cf7246207e51791a6"
    "ca6200a914cd2834a9b3c79fcd59e26e457e0683bc33d49267edbdd6e5d90902"
    "696f1e7b1a4affc4ba371339868c28015ebbb73e262669866c35db974ba69e46"
    "8f2583b9191d15d686cd66fb0b9e0ff0a3b4721a6dc342f14f2446b4e028595b",
    // signature
    "3974900bec3fcb081f0e5a299adf30d087aabaa633911410e87a4979bbe3fa80"
    "c3abcf221686399a49bc2f1e5ac40c35df1700e4b9cb7c805a896646573f4a57"
    "0a9704d2a2e6baee4b43d916906884ad3cf283529ea265e8fcb5cc1bdf7b7dee"
    "85941e4b4fb25c1fc7b951fb129ab393cb069be271c1d954da3c43674309f1d2"
    "12826fabb8e812de2d53d12597de040d32cb28c9f813159cb18c1b51f7a874cb"
    "f229cc222caeb98e35ec5e4bf5c5e22cc8528631f15117e8c2be6eac91f4070e"
    "ecdd07ecc6db6c46eaa65f472f2006988efef0b51c538c6e04d7519c8e3da4b1"
    "72b1e2761089ed3ad1197992ef37c168dc881c8b5f8bbfee919f7c7afd25b8fc"
},
{
    // sha_nid
    NID_sha512,
    // key, 2048 bits
    {
        // modulo
        "cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c"
        "c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef"
        "b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681"
        "5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30"
        "b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf"
        "a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11"
        "813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a"
        "8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d",
        // exponent
        "260445",
        // private
        "0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc938970"
        "9f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dc"
        "d65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f2"
        "19f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e"
        "0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56"
        "b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c"
        "8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773b"
        "af498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d",
        // prime1, optional
        "F364E16EF12017EC95B192308C01E087CEE619AB50A5D537CC01841DC92B30BC"
        "EF0D9F2C6BBD5DC10BDF5B9F6C354A4F9F210520CAA72B4F5C36B8D33F10324C"
        "55956141891E45B84B49F59EA5BFAC6FFA38900ACA5099AFCD02F6A8257C41CE"
        "5BB2E4153832B5C22F91EB389FA2035C3CF9B3374531C483CB30CEB007259B1D",
        // prime2, optional
        "D95C0995FABDFCBCCFE63E0F3262F806869AB571E1793E97234CBB9BD4B6872A"
        "7695389955CF6CE7245345A5DF8021F7D9519563AFBC2667F5311FAD093DE2C0"
        "2CD069109B630D68E3BF767F8A788A6ADD7AB199F2D8F6A40B7C1910D9DAB52A"
        "C80D0D333AACAB321A9309DC884DDD4DB637A0C1115AE3C08EFA683F99EB7331"
    },
    // to_be_signed
    "a7c309d44a57188bbd7b726b98b98ce12582228e1415864870a23961d2afb82c"
    "d5bc98bec922d5f2ac4168b056da176ef3ba91f6b699ba6acc4144868ff37f26"
    "fd06720868d12ad26ecb52572cf10416af68df03ab645a8b704857d2190ffc3f"
    "07eabe3a8e2abe34ed6159e884c4fae141d4333d5c3e0db044ff9cccd9cbd67f",
    // signature
    "148af61ed5ea8a87a08b3f403929bf8031db4fd3999b64409ba489f97a3ee520"
    "8ea4202d2ec18734f615003a51f77441085be6ac0f11810ffa2dad58f0e186d5"
    "520ac2b8a5d3966e8d2abb8074e13b50a4e7de83be10a66fdc7ca18118c5774f"
    "781212de9efebc6376fcdddc65a3b1b8f1ab31492fe478259ce719b3db587498"
    "d879a01dec96e8eabeb07ff7073f3f3eb446084955ca26329a791315a2c259d2"
    "25e26b2154b2047b21faba68115bfd962e5e24ec52d7c5d231e3044cbcd8c880"
    "4855703cbaa622b15b6ef78c7421a367166f1b02576c87360593da75b7189efa"
    "fd1082bd59f6857f1701f646c24d70c95273c49d5b11e6afe258821b55c1680c"
}
// More to follow...
};


class RsaSignTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<RsaSignParams>
{
public:
    RsaSignTest()
    {
        RsaSignParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_modulo =
            bcrypt_testing::number_from_string(params.key.modulo).value();
        bcrypt_testing::Number num_exponent =
            bcrypt_testing::number_from_string(params.key.exponent).value();
        bcrypt_testing::Number num_private =
            bcrypt_testing::number_from_string(params.key.priv).value();
        std::optional<bcrypt_testing::Number> num_prime1 =
            bcrypt_testing::number_from_string(params.key.prime1);
        std::optional<bcrypt_testing::Number> num_prime2 =
            bcrypt_testing::number_from_string(params.key.prime2);
        bcrypt_testing::Bytes bytes_to_be_signed =
            bcrypt_testing::bytes_from_string(params.to_be_signed).value();
        bcrypt_testing::Number num_signature =
            bcrypt_testing::number_from_string(params.signature).value();

        // Initialize members from them
        digest_ = EVP_get_digestbynid(params.sha_nid);
        key_signer_ = construct_hardcoded_rsa_key(
            num_modulo, num_exponent, num_private, num_prime1, num_prime2);
        to_be_signed_ = bytes_to_be_signed;
        signature_ = num_signature;
    }

    const EVP_MD *digest_;
    bcrypt_testing::unique_EVP_PKEY key_signer_;
    bcrypt_testing::Bytes to_be_signed_;
    bcrypt_testing::Number signature_;
};


TEST_P(RsaSignTest, Sign)
{
    size_t signature_len;

    OSSL_ASSERT_NE(nullptr, digest_);

    // Create signature
    bcrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_sign_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(),
        NULL, digest_, NULL, key_signer_.get()));
    OSSL_ASSERT_EQ(1, EVP_DigestSignUpdate(md_sign_ctx.get(),
        to_be_signed_.data(), to_be_signed_.size()));
    OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
        NULL, &signature_len));
    std::vector<unsigned char>signature(signature_len);
    OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
        &signature[0], &signature_len));
    ASSERT_LE(signature_len, signature.size());
    signature.resize(signature_len);
    ASSERT_EQ(signature, signature_);
}

INSTANTIATE_TEST_CASE_P(RsaSignTests, RsaSignTest,
    testing::ValuesIn(rsa_sign_params));


// ----------------------------------------------------------------------------
//
// RSA value-parameterized tests for public key encryption
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct RsaEncryptParams {
    struct {
        const char *modulus;
        const char *exponent;
    } key;
    const char *input_given;
    const char *output_expected;
    int padding_type;
};

static const RsaEncryptParams rsa_encrypt_params[] = {
#if 0
{
    // key, 1024 bits
    {
        // modulus
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab"
        "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72"
        "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514"
        "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
        // exponent
        "010001",
    },
    // input_given
    "274c8b0f39f1e1878a8f662c60233ace85e7c611410810b73e07d3ffc239e9de"
    "0e5a963b399f1c512c9c2205a5fdd9be033561463f9a65a2e2b87a8870619e52"
    "b62b806df52dad993491f6a9ea7e7136ab193c6fbe6019f9fafcaa206cbd9cd6"
    "a3e6ca29a8b8728a81107c1e48f2604358d7935f648e24488204a241e9f44204",
    // output_expected
    "02d07177f91c0db0b74e34b532aa18673d27fdee370b7aa9094ef765c9a8278b"
    "7128f1bd24fd3992e6376f83bdea9e505be10de15163286a7c9d9873bdbcffe0"
    "535f9f8cb0dd99ba34e24ec462e4ad03618258b66894daeac9415545e030bd96"
    "3f2beb8d089183ec7ff1be67e6f94e6871d42fb7d7c694682a9f4af599bfdf81",
    // padding_type
    RSA_NO_PADDING
},
#endif
{
    //key, 3072 bits
    {
        // modulus
        "8463c890e4c35309b918d443bc668ac4dcc46a13b0fb14df56af82485f3cf75d"
        "f1afea37027ab1e22fc664e57de3f812913578e3af33fa5290185007776988ed"
        "af36329226570bd3f2e6de039438e01eaf5eda80c3a98fe8f5e1c8cc37bbc7e7"
        "f34f4650541ec1f0d0bc08512ac2a09413e5a29642efa8c35beaeedc758f6243"
        "c8b7c98a23529a92af441a75a9142f9357ebbf691eb602dd14ee0ddb00c141c6"
        "4c8a50d9d783fdff681b42701ad6ce605ec3ba62603658d9e617141c86786e1f"
        "b2568919b0b0c5c47ba4792f4d1dcb7c23658f41501067f4a2e212250f72e5b6"
        "5c3bb873c92deb3cd48aa20fd13f6e77f21df70be113783c72f5544a97f252a8"
        "2405fb66da1c7554a15827260351c4dc704231a14a859189638fe30c1687f094"
        "9121f73e302b549437b4fa55906560ff37a49d77c3f9810363f0562fd4201eb9"
        "7ac6b694148ace022e42b4c4641bdf0de517d04cb93d6bf9635ae20cd71dc935"
        "bf1bbf0060bf553e91881d898ea30a914be455bf3990a5b9254a60fc7408d361",
        // exponent
        "010001"
    },
    // input_given
    "61182e5af738fd50cb41dcf46ce6623e6ed642708342624d6c4a7be5782846e7"
    "ddbf67a39d46e1360192feccbf2cbde1c9ede45d356f3028d17762eeecaf0bb4"
    "070ca9327beff24061427ba602d20d6023684966ae9614bfa7711eceac6bb3b4"
    "a73acd25ca593e261430aeea3669ce24ee31cbb86ca0c6c60b8803034f24bf72"
    "076499c27fcfbdae9aeb25eeaac4529e49f121223be0e60862458bc668f2775c"
    "bcfc98ed2e0dba25c23f6b23d6039ab5dbf761b13b9c2e1666523bf673ffea46"
    "6aed58d8a77f8aefd675195b065656c70bb8fd700cc9356f2f552ad0c0a2071e"
    "73dbae454e5964c9e11bbe19dddc002122b427741ff19a03cf930e68aae59b54"
    "686b665c7f0722d75c6d593563cfe17b510fa18bda5df21b579c9071e2461576"
    "c85e0c9c8fadd3bed89fbcd6578b1bcdd4d4e3d0c7e9bf312ffca6874e31b0ff"
    "bf352c65834f07623a7853bf9a2da08fb66ee11254927b54947c7efcb55c9d54"
    "dd849d839389a63d506914ab24983407b256eba4a7be45eed450e6c226fcd4c1",
    // output_expected
    "756889efc9e3695a80ca8654cec35d44a2d62da4d3d674155c0e1a014977ac2b"
    "f84276aabb479193b66449b45cfaef4ab2565338935e3ce17001503d07929925"
    "66abcf2379fc5fdf36af48b56c0352fd154c2e9b87aed59f98fd0c70684e128e"
    "c56e246fed6b845ebcdb8a4e49f5fdf0a048027ffbfa220a22442dc7b2d4adaa"
    "2bbeba9863d5b7fcad95607169d36dead66599f77b8661cbe6ec5ec053da83c8"
    "239d27d9b8bea022eb6c822787a2397824f55723eaa1a7be2d3916f45aa42733"
    "6997119893339c3d510bdf2e712a5b1faee52ce3792ca9b727e244e311983b91"
    "be4ef393f47d8c7f1a5b1dae0c61050ea854135a144a992b6fae5907018ed462"
    "0f313b97353a781556394e529d4fafe8fc836c2b3af1c0659b065e38c67895a5"
    "384f8d7cea35bb87f15bcfffad3602ab33615084a21c2cc998c74f53d4201e0a"
    "e061ae33b000a9cfe49ccc3e274516aa6589adecea6c7f8068394a96022502ba"
    "963407460ffaefaf288bd424cc01cd73e8ac7587e130ab9f0602ba5a07c473ba",
    // padding_type
    RSA_NO_PADDING
}
};

class RsaEncryptTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<RsaEncryptParams>
{
public:
    RsaEncryptTest()
    {
        RsaEncryptParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_key_modulus =
            bcrypt_testing::number_from_string(params.key.modulus).value();
        bcrypt_testing::Number num_key_exponent =
            bcrypt_testing::number_from_string(params.key.exponent).value();
        bcrypt_testing::Number num_input_given =
            bcrypt_testing::bytes_from_string(params.input_given).value();
        bcrypt_testing::Number num_output_expected =
            bcrypt_testing::number_from_string(params.output_expected).value();

        // Initialize members from them
        key_ = construct_hardcoded_rsa_key_public(
            num_key_modulus, num_key_exponent);
        input_given_ = num_input_given;
        output_expected_ = num_output_expected;
        padding_type_ = params.padding_type;
    }

    bcrypt_testing::unique_EVP_PKEY key_;
    bcrypt_testing::Number input_given_;
    bcrypt_testing::Number output_expected_;
    int padding_type_;
};


TEST_P(RsaEncryptTest, Encrypt)
{
    RSA *rsa_key = EVP_PKEY_get0_RSA(key_.get());
    OSSL_ASSERT_NE(nullptr, rsa_key);

    size_t out_len = output_expected_.size();
    std::vector<unsigned char>ciphertext(out_len);
    OSSL_ASSERT_EQ((int)out_len, RSA_public_encrypt((int)input_given_.size(),
        input_given_.data(), &ciphertext[0], rsa_key, padding_type_));
    ASSERT_EQ(output_expected_, ciphertext);
}

INSTANTIATE_TEST_CASE_P(RsaEncryptTests, RsaEncryptTest,
    testing::ValuesIn(rsa_encrypt_params));


// ----------------------------------------------------------
//
// RSA value-parameterized tests for private key decryption
//
// ----------------------------------------------------------

// Parameters for this type of test
struct RsaDecryptParams {
    struct {
        const char *modulus;
        const char *exponent;
        const char *priv;
        const char *prime1;
        const char *prime2;
    } key;
    const char *input_given;
    const char *output_expected;
    int padding_type;
};

static const RsaDecryptParams rsa_decrypt_params[] = {
{
    // key, 1024 bits
    {
        // modulus
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab"
        "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72"
        "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514"
        "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
        // exponent
        "010001",
        // private
        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd"
        "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55"
        "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf"
        "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
        // prime1
        "d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30a"
        "f38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d",
        // prime2
        "cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c"
        "4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77"
    },
    // input_given
    "02d07177f91c0db0b74e34b532aa18673d27fdee370b7aa9094ef765c9a8278b"
    "7128f1bd24fd3992e6376f83bdea9e505be10de15163286a7c9d9873bdbcffe0"
    "535f9f8cb0dd99ba34e24ec462e4ad03618258b66894daeac9415545e030bd96"
    "3f2beb8d089183ec7ff1be67e6f94e6871d42fb7d7c694682a9f4af599bfdf81",
    // output_expected
    "274c8b0f39f1e1878a8f662c60233ace85e7c611410810b73e07d3ffc239e9de"
    "0e5a963b399f1c512c9c2205a5fdd9be033561463f9a65a2e2b87a8870619e52"
    "b62b806df52dad993491f6a9ea7e7136ab193c6fbe6019f9fafcaa206cbd9cd6"
    "a3e6ca29a8b8728a81107c1e48f2604358d7935f648e24488204a241e9f44204",
    // padding_type
    RSA_NO_PADDING
},
{
    //key
    {
        // modulus
        "8463c890e4c35309b918d443bc668ac4dcc46a13b0fb14df56af82485f3cf75d"
        "f1afea37027ab1e22fc664e57de3f812913578e3af33fa5290185007776988ed"
        "af36329226570bd3f2e6de039438e01eaf5eda80c3a98fe8f5e1c8cc37bbc7e7"
        "f34f4650541ec1f0d0bc08512ac2a09413e5a29642efa8c35beaeedc758f6243"
        "c8b7c98a23529a92af441a75a9142f9357ebbf691eb602dd14ee0ddb00c141c6"
        "4c8a50d9d783fdff681b42701ad6ce605ec3ba62603658d9e617141c86786e1f"
        "b2568919b0b0c5c47ba4792f4d1dcb7c23658f41501067f4a2e212250f72e5b6"
        "5c3bb873c92deb3cd48aa20fd13f6e77f21df70be113783c72f5544a97f252a8"
        "2405fb66da1c7554a15827260351c4dc704231a14a859189638fe30c1687f094"
        "9121f73e302b549437b4fa55906560ff37a49d77c3f9810363f0562fd4201eb9"
        "7ac6b694148ace022e42b4c4641bdf0de517d04cb93d6bf9635ae20cd71dc935"
        "bf1bbf0060bf553e91881d898ea30a914be455bf3990a5b9254a60fc7408d361",
        // exponent
        "010001",
        // private
        "48743fc124a1cd6145ded3d49a58585bf322bf973545c49f92568d6bc44b9e69"
        "d8aad8f8f02f6c0908f28027a4e54dd0038e8b31b8a22ebe5ec41f906686e87c"
        "846699f8a868fd3d2af3b4cfaaa011f05934054b7149ec4ba7bdc0e21b2276fe"
        "77878c48cc30e51d416f96f1ad004557a52808fa4979d617ccc75fa061ea6df2"
        "00f8aca12041c5fcbf54fb52278db797e10751835b5e6b64c95e9b509f322528"
        "3c9d7a302ea5bb2dbbb1278428fc24885374b51dbfe01e726a5d79113f7acb71"
        "5824d99e488c6b7de5c021aeabd2d486d846d7014d58faa64eb57456102b7e3b"
        "9f69cc08968381b9b3b29915e5d294c8f69318ca539846ac34aa3850a999f2c0"
        "d6c14c7199c794b48d55f2b3e853b125650baaa2390b08a091a08a84e581a501"
        "0a6ba516dfd4b4141fc69bd3c18252cffdbb7f092bccd676be05eebbffc1811b"
        "d8520c5a15dbaee1afc02dafaed54bdab8ec693da7674ca1b6c171f96a77adf4"
        "858b4dcf538769d0769ec1cbdb9d405cfeac08e7b3105cbd4231b0d11a2c0801",
        // prime1
        "e9c5a29d60f28978d610a25d0d55e41ba38cfac6768d3dec33b1c2bf39d79e3f"
        "f0f459f440ab63c82866cab9278191438f539113d88c5c7b76bd4f464089f283"
        "ea8aa96f5eb2c9332111b6d44581a86cfcdeb18f900020fd8471980bdfbe8a4c"
        "bc7044239029edac88451892ac527cd21180ac694826e8636b27131293a54275"
        "246790151f15d4742ca6ea325b477e83b1c7bf4e768b914ad60ca65fd732fa73"
        "7d66a2664e78cdceef9dddee8492c877621799708ee6679116b9321374ffefa1",
        // prime2
        "90fa59e5cf34d310bb77cafb4b0df4a7acfe29f9300b8fbb9c6f55725994ec85"
        "eac3f53239296e250ed5be916411bd4a00b4f9e3dfd35788b08403329f179af4"
        "b316d0df310f73804b2d059b9d39def202167f0ca452650cfc9c0fbc370dd825"
        "a57b613818a3983f6619f13b95534e05dfeb1b86e6ba4e32c028e45092f159c6"
        "ebf20ac40ff96d494be000461a2e536bc836c349787f55bb5e3d6b4c4c45f6eb"
        "83cf151e05023fdcbf46ecf87af2f9295bc8fbf9bb1a28eeac0aad66ec414bc1"
    },
    // input_given
    "54bad533de0c9042ce8455147702e4c4092a14457286763356659c016fb64151"
    "538611617ca25f8cb7e503318c1c1df5f541747eda789abe1a9fbc4182fb4507"
    "db81349ad137d99257ab7ee4235b2570de4e6a34f7b425b80e13687951ee6388"
    "d51fcc16211ad0ab6d57961a701f8e3938bffcdcd7ff932f79af8f9a245dd193"
    "cbdd2ffad8dc00936692ecd6423214d34e20fb85e195ee0ffde53ec05409c347"
    "622737be55246482aec41847073fca5b32194c2a7cbab65c25a10728cd1a03bd"
    "6bc48211c5958c814d93edc9a0ccdbd0aee8b982fb2bdf4534cd50822cf3de0c"
    "0ebc67317cb05e6719c9ce8b2546e358e4072370f74a0ce6323520c2277af298"
    "36b93b435f59009ed86afc745381f07344f582402ecfeb1025a12858406cec30"
    "779e6d95d99dc27f1b31fa9fabea05cf095e94c2a680d4d8e770ff87884d45d9"
    "847b1a7982459b58ac8907f08b946057a5e9eeb95786e1c1cf548211933a7e4b"
    "c1fa8d6ffc952fffc6d7a78a4b8408eb148783c7587b571556957d62d8f7fa2f",
    // output_expected
    "3ab5eb5a2864def620cbdbc3ef76d2c4c4e5a37c4392d93927053183f5bfe60d"
    "6d0bf21d9809711751239b6ba12a89d011a94033a8d7095ac6e02882cde3f065"
    "0ad135c78348cbce55f5cba7ad97f312325568b24146d34644d685ff252c8922"
    "7ae4551bef79243377734a5fb75eb86627951de757189aa4f55415599b422dfe"
    "afd3bbe54a57db3e162a73199819e4fa5a387c3edb045020781a61934581884c"
    "576476e4e6f9c650919248a595413c7bc6713586515e62b657b5fa1c2908a482"
    "26d588edc9096e46a797091229894b2332db5d51eeb13f0e0d27c4dda921738f"
    "28e469eecb267d2b059f63a3526d1f7dd3513b59b6b09a480c9390a2b2720fd2"
    "b9b7dd362180daa8b9335f43440b66a20b08c6f2976bf6fea5703822826ae47c"
    "13c945b7fb9e126cb0963264aa6d4a36bd056654b8cecddfc493f9811f420377"
    "2488706959edb8261c2af9fdacff9dd46331cc1f434d4b110c5f99cddba6f9b0"
    "03182f5df4b123ed69a4cfcad0d9ba429ff50c88691e22bcc5a7d83b2a508183",
    // padding_type
    RSA_NO_PADDING
}
};

class RsaDecryptTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<RsaDecryptParams>
{
public:
    RsaDecryptTest()
    {
        RsaDecryptParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_key_modulus =
            bcrypt_testing::number_from_string(params.key.modulus).value();
        bcrypt_testing::Number num_key_exponent =
            bcrypt_testing::number_from_string(params.key.exponent).value();
        bcrypt_testing::Number num_key_private =
            bcrypt_testing::number_from_string(params.key.priv).value();
        std::optional<bcrypt_testing::Number> num_key_prime1 =
            bcrypt_testing::number_from_string(params.key.prime1);
        std::optional<bcrypt_testing::Number> num_key_prime2 =
            bcrypt_testing::number_from_string(params.key.prime2);
        bcrypt_testing::Number num_input_given =
            bcrypt_testing::bytes_from_string(params.input_given).value();
        bcrypt_testing::Number num_output_expected =
            bcrypt_testing::number_from_string(params.output_expected).value();

        // Initialize members from them
        key_ = construct_hardcoded_rsa_key(num_key_modulus, num_key_exponent,
            num_key_private, num_key_prime1, num_key_prime2);
        input_given_ = num_input_given;
        output_expected_ = num_output_expected;
        padding_type_ = params.padding_type;
    }

    bcrypt_testing::unique_EVP_PKEY key_;
    bcrypt_testing::Number input_given_;
    bcrypt_testing::Number output_expected_;
    int padding_type_;
};


TEST_P(RsaDecryptTest, Decrypt)
{
    RSA *rsa_key = EVP_PKEY_get0_RSA(key_.get());
    OSSL_ASSERT_NE(nullptr, rsa_key);

    size_t out_len = output_expected_.size();
    std::vector<unsigned char>plaintext(out_len);
    OSSL_ASSERT_EQ((int)out_len, RSA_private_decrypt((int)input_given_.size(),
        input_given_.data(), &plaintext[0], rsa_key, padding_type_));
    ASSERT_EQ(output_expected_, plaintext);
}

INSTANTIATE_TEST_CASE_P(RsaDecryptTests, RsaDecryptTest,
    testing::ValuesIn(rsa_decrypt_params));
