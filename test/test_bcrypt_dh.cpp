
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

// ----------------------------------------------------------------------------
//
// OpenSSL helper functions
// If any of the functions in this section throw exceptions, it is most likely
//   a configuration error
//
// ----------------------------------------------------------------------------

static bcrypt_testing::unique_EVP_PKEY
construct_dh_key_private(
    const bcrypt_testing::Number &num_mod,
    const bcrypt_testing::Number &num_gen,
    const bcrypt_testing::Number &num_priv,
    const bcrypt_testing::Number &num_pub)
{
    bcrypt_testing::unique_BIGNUM bn_mod(
        BN_bin2bn(num_mod.data(), (int)num_mod.size(), NULL));
    if (!bn_mod) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_gen(
        BN_bin2bn(num_gen.data(), (int)num_gen.size(), NULL));
    if (!bn_gen) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_priv(
        BN_bin2bn(num_priv.data(), (int)num_priv.size(), NULL));
    if (!bn_priv) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_pub(
        BN_bin2bn(num_pub.data(), (int)num_pub.size(), NULL));
    if (!bn_pub) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_DH dh(DH_new());
    if (!dh) throw bcrypt_testing::ossl_error();

    // set0 transfers ownership so need to dup here
    if (DH_set0_key(dh.get(), BN_dup(bn_pub.get()), BN_dup(bn_priv.get()))
        != 1) throw bcrypt_testing::ossl_error();
    if (DH_set0_pqg(dh.get(), BN_dup(bn_mod.get()), NULL, BN_dup(bn_gen.get()))
        != 1) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();
    if (EVP_PKEY_set1_DH(result.get(), dh.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}


static bcrypt_testing::unique_EVP_PKEY
construct_dh_key_public(
    const bcrypt_testing::Number &num_mod,
    const bcrypt_testing::Number &num_gen,
    const bcrypt_testing::Number &num_pub)
{
    bcrypt_testing::unique_BIGNUM bn_mod(
        BN_bin2bn(num_mod.data(), (int)num_mod.size(), NULL));
    if (!bn_mod) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_gen(
        BN_bin2bn(num_gen.data(), (int)num_gen.size(), NULL));
    if (!bn_gen) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_pub(
        BN_bin2bn(num_pub.data(), (int)num_pub.size(), NULL));
    if (!bn_pub) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_DH dh(DH_new());
    if (!dh) throw bcrypt_testing::ossl_error();

    // set0 transfers ownership so need to dup here
    if (DH_set0_key(dh.get(), BN_dup(bn_pub.get()), NULL)
        != 1) throw bcrypt_testing::ossl_error();
    if (DH_set0_pqg(dh.get(), BN_dup(bn_mod.get()), NULL, BN_dup(bn_gen.get()))
        != 1) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();
    if (EVP_PKEY_set1_DH(result.get(), dh.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}


// ----------------------------------------------------------------------------
//
// DH key generation value-parameterized tests
//
// ----------------------------------------------------------------------------

// Generate key for specific (well-known) parameter combinations
struct DhGenerateParams {
    int nid;
    bool is_supported;
};


static const DhGenerateParams dh_generate_params[] = {
{
    // nid
    NID_ffdhe2048,
    // is_supported
    true
},
{
    // nid
    NID_ffdhe3072,
    // is_supported
    true
},
{
    // nid
    NID_ffdhe4096,
    // is_supported
    true
},
{
    // nid
    NID_ffdhe6144,
    // is_supported
#ifndef B_DO_OSSL_BUILTIN
    false
#else
    true // OpenSsL actually does support this
#endif
},
{
    // nid
    NID_ffdhe8192,
    // is_supported
#ifndef B_DO_OSSL_BUILTIN
    false
#else
    true // OpenSsL actually does support this
#endif
}
#if 0
,
{
    // nid
    NID_undef,
    // is_supported
    true
}
#endif
};


class DhGenerateTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<DhGenerateParams>
{
public:
    DhGenerateTest()
    {
        DhGenerateParams params = GetParam();

        // Initialize members from parameters
        nid_ = params.nid;
        is_supported_ = params.is_supported;
    }

    int nid_;
    bool is_supported_;
};

static void
print_dh(
    const DH *dh)
{
    const BIGNUM *pub_key = NULL;
    const BIGNUM *priv_key = NULL;

    printf("\nDH key:");
    DH_get0_key(dh, &pub_key, &priv_key);
    printf("\n  modulus: ");
    BN_print_fp(stdout, DH_get0_p(dh));
    printf("\n  generator: ");
    BN_print_fp(stdout, DH_get0_g(dh));
    printf("\n  private: ");
    BN_print_fp(stdout, priv_key);
    printf("\n  public: ");
    BN_print_fp(stdout, pub_key);
    printf("\n");
}


// use EVP functions to generate public/private dh components
TEST_P(DhGenerateTest, SimpleGenerate)
{
    bcrypt_testing::unique_EVP_PKEY_CTX params_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL));
    OSSL_ASSERT_TRUE(params_ctx);
    // Initialize the parameter generation context
    OSSL_ASSERT_EQ(1, EVP_PKEY_paramgen_init(params_ctx.get()));
    // Specifying the parameters we want to use, if provided
    // Note: if NID_undef is provided, OpenSSL will use the default generation
    //   paramters, which will result in a key size of 1024 bits.
    if (nid_ != NID_undef) {
        OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_dh_nid(params_ctx.get(), nid_));
    }
    // Create the parameter object params
    EVP_PKEY* temp_key(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_paramgen(params_ctx.get(), &temp_key));
    bcrypt_testing::unique_EVP_PKEY key_params(temp_key);
    ASSERT_TRUE(key_params);
    // Create the context for the key generation.
    bcrypt_testing::unique_EVP_PKEY_CTX key_ctx(EVP_PKEY_CTX_new(key_params.get(), NULL));
    OSSL_ASSERT_TRUE(key_ctx);
    // Generate the key
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen_init(key_ctx.get()));
    EVP_PKEY* temp_dh_key(nullptr);
    if (is_supported_) {
        OSSL_ASSERT_EQ(1, EVP_PKEY_keygen(key_ctx.get(), &temp_dh_key));
        bcrypt_testing::unique_EVP_PKEY dh_key(temp_dh_key);
        ASSERT_TRUE(dh_key);
    } else {
        OSSL_ASSERT_EQ(0, EVP_PKEY_keygen(key_ctx.get(), &temp_dh_key));
        // There should be an error message...
        // Check if any error messages have been ignored
        OSSL_EXPECT_NE(bcrypt_testing::GetOpenSSLErrors(), "")
            << "Expected to find OpenSSL error string";
    }
}

INSTANTIATE_TEST_CASE_P(DhGenerateTests, DhGenerateTest,
    testing::ValuesIn(dh_generate_params));


// ----------------------------------------------------------------------------
//
// DH key generation as well as secret derivation, value-parameterized tests
//
// ----------------------------------------------------------------------------

// Generate key for specific (well-known) parameter combinations
struct DhFullParams {
    int nid;
};


static const DhFullParams dh_full_params[] = {
{
    // nid
    NID_ffdhe2048,
},
{
    // nid
    NID_ffdhe3072,
},
{
    // nid
    NID_ffdhe4096,
}
#if 0
,
{
    // nid
    NID_undef
}
#endif
};


class DhFullTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<DhFullParams>
{
public:
    DhFullTest()
    {
        DhFullParams params = GetParam();

        // Initialize members from parameters
        nid_ = params.nid;
    }

    int nid_;
};

// use EVP functions to generate public/private dh components
TEST_P(DhFullTest, GenerateAndDerive)
{
    bcrypt_testing::unique_EVP_PKEY_CTX params_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL));
    OSSL_ASSERT_TRUE(params_ctx);
    // Initialize the parameter generation context
    OSSL_ASSERT_EQ(1, EVP_PKEY_paramgen_init(params_ctx.get()));
    // Specifying the parameters we want to use
    if (nid_ != NID_undef) {
        OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_dh_nid(params_ctx.get(), nid_));
    }
    // Create the parameter object params
    EVP_PKEY *temp_key(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_paramgen(params_ctx.get(), &temp_key));
    bcrypt_testing::unique_EVP_PKEY key_params(temp_key);
    ASSERT_TRUE(key_params);

    // Create the context for the key generation for Alice
    bcrypt_testing::unique_EVP_PKEY_CTX key_ctx_alice(EVP_PKEY_CTX_new(key_params.get(), NULL));
    OSSL_ASSERT_TRUE(key_ctx_alice);
    // Generate the key for Alice
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen_init(key_ctx_alice.get()));
    EVP_PKEY *temp_dh_key_alice(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen(key_ctx_alice.get(), &temp_dh_key_alice));
    bcrypt_testing::unique_EVP_PKEY dh_key_alice(temp_dh_key_alice);
    ASSERT_TRUE(dh_key_alice);

    // Create the context for the key generation for Bob
    bcrypt_testing::unique_EVP_PKEY_CTX key_ctx_bob(EVP_PKEY_CTX_new(key_params.get(), NULL));
    OSSL_ASSERT_TRUE(key_ctx_bob);
    // Generate the key for Bob
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen_init(key_ctx_bob.get()));
    EVP_PKEY *temp_dh_key_bob(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen(key_ctx_bob.get(), &temp_dh_key_bob));
    bcrypt_testing::unique_EVP_PKEY dh_key_bob(temp_dh_key_bob);
    ASSERT_TRUE(dh_key_bob);

    // Create the context for the secret derivation -- alice local bob remote
    bcrypt_testing::unique_EVP_PKEY_CTX ctx_alice_bob(
        EVP_PKEY_CTX_new(dh_key_alice.get(), NULL));
    OSSL_ASSERT_TRUE(ctx_alice_bob);
    // Initialise that context
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive_init(ctx_alice_bob.get()));
    // Provide the peer public key
    OSSL_ASSERT_EQ(1,
        EVP_PKEY_derive_set_peer(ctx_alice_bob.get(), dh_key_bob.get()));
    // Check required buffer length for shared secret
    size_t outlen_alice_bob;
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(
        ctx_alice_bob.get(), NULL, &outlen_alice_bob));
    // Derive the secret
    bcrypt_testing::Number secret_alice_bob(outlen_alice_bob);
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(
        ctx_alice_bob.get(), &secret_alice_bob[0], &outlen_alice_bob));

    // Create the context for the secret derivation -- alice local bob remote
    bcrypt_testing::unique_EVP_PKEY_CTX ctx_bob_alice(
        EVP_PKEY_CTX_new(dh_key_alice.get(), NULL));
    OSSL_ASSERT_TRUE(ctx_bob_alice);
    // Initialise that context
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive_init(ctx_bob_alice.get()));
    // Provide the peer public key
    OSSL_ASSERT_EQ(1,
        EVP_PKEY_derive_set_peer(ctx_bob_alice.get(), dh_key_bob.get()));
    // Check required buffer length for shared secret
    size_t outlen_bob_alice;
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(
        ctx_bob_alice.get(), NULL, &outlen_bob_alice));
    // Derive the secret
    bcrypt_testing::Number secret_bob_alice(outlen_bob_alice);
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(
        ctx_bob_alice.get(), &secret_bob_alice[0], &outlen_bob_alice));

    // Compare with the expected secret
    EXPECT_EQ(secret_alice_bob, secret_bob_alice);

    //std::cout << "Secret key calculated:" << std::endl;
    //std::string hex_secret(OPENSSL_buf2hexstr(&secret_alice_bob[0], (long)secret_alice_bob.size()));
    //std::cout << hex_secret << std::endl;
    //print_dh(EVP_PKEY_get0_DH(dh_key_alice.get()));
    //print_dh(EVP_PKEY_get0_DH(dh_key_bob.get()));

}

INSTANTIATE_TEST_CASE_P(DhFullTests, DhFullTest,
    testing::ValuesIn(dh_full_params));


// ----------------------------------------------------------------------------
//
// DH value-parameterized tests
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct DhParams {
    struct {
        const char *modulus;
        const char* generator;
    } params;
    struct {
        const char* priv;
        const char* pub;
    } local_key;
    struct {
        const char* pub;
    } remote_key;
    const char* secret;
};

static const DhParams dh_params[] = {
// It seems that BCrypt only supports generator 2, so only test this Ossl
#if B_DO_OSSL_BUILTIN
{
    // params
    {
        // modulus
        "ca60d25245efbba8c7f61d2344fd692aa42df7842b83131ad8e6afd94f51adf0"
        "1fc79a5db87ce2f7c2235fec416ae9d1268e1827b179a3602add735d167d6034"
        "cc4f6e33671e6e68bb5340ffc7e8172ed183881d20f773e271ff5db5524bdc3b"
        "8bf3ea9e505c993c7879b2c3575c25e0c66800266998ec45a0f8fcfb44884d07"
        "156ae63b5be321944453a5c425612a6d76d44fda03530423ffe08245a86702f6"
        "b9d7bc87103c4094d9cbb2a69a6560386f025cea444c2779a576efdfbe470209"
        "d091609c29a3321402993f820a67de6044a9a3eae9c11d882de1c19a8dd8f8bd"
        "c4193c432826cac60bed5e691b441a4c6995d1fe3117a9418777e767afdcdeff",
        // generator
        "758d43fb520121e1ad3d6af76e9e84da1057741594d14ca75d6ca296217df11f"
        "62db8703f3e212c8bbd381a961a83815f41e4135c068d27417d320acce628539"
        "3d8c456bf1298c29545426ede51ae129063159c9467ae7fea75864863a4b2d01"
        "feaf6e3da76caf62cfdb5d63751a6188f31b1191f46c0dd141079b16cf545d7c"
        "8db633759295efeb4357f8c7bb23006b5f541eb8b7d16f8d43d65b69455e1597"
        "27fa281cd80a01c4376922a2f0ddd3e1f61f42297a212f9f27fde0ded87974eb"
        "63eb1bf3f65986bce9868a88590196779f95e00a87bb271ab159e09c2596ae58"
        "e507ab285a0b0b1cf67aac8c31d51bf8da4d0ef99c7e9d5d7cfb765f75cc0a63"
    },
    // local_key
    {
        // priv
        "2d25d9f28cc82bdc857d39004009f3a43bea6b963fcaa39cb6896372",
        //pub
        "46b4baa0d01823679a7f9eaaf3d2816f12ac6501ab80f5b513b5305d68795508"
        "e0a98528a75b79f4d3e247d9e456fc92c9a5e3a3b5968d7dcc672d5a982030b3"
        "b10bdd5ea11f35ba12f8014079adee0b7bc811f9c71a22421de76b6d834d2fd0"
        "8090128c705adda99b1165092bc90d3abccacf7d0894d3db0b5d229a6f3be973"
        "8510c11453729dcc83ae92560732b4a658215d872ee040c4736598337af724a4"
        "63265b540df4e009ff255d853dc0b72072b24a179ca9c5e9b8041f73ab88c8b6"
        "af1fbcc1b5b957a79903e516da82a5a3f3d9407bf1afed1e96bf168c0b972498"
        "d5e922204d0619d2415bd0a96bdda3fc19b0594712037fc783838c5f6269a8c1"
    },
    // remote_key
    {
        // pub
        "6d0ee76c49a260390e0723f201b1ef7008c8b2deb1d942090ac3c2f8e31973b4"
        "5d2312b2cd931fbbd1bd2faf4fbc93b9dfaea74a47bcd5a306fde0dfe38630fb"
        "cd3631db65168e09f36033ed1aec3c8e29c24b34d95ebd1e81ec8cf993d0a2f2"
        "a926807916cad9b9ff7d2bb982e503b7ee74969d318b6fc02e8ab5580fb2dea1"
        "f112ed4d23e6ead7930aafd45339697a62a51df70524e2fb94a8cf358115a2da"
        "3396eaa9933fada49127a3c42baef23b46d966ff97b28afcd4930be0b2cd34d9"
        "189b861613f50e4348758b47e50d4dea46695985d87de8bc7d550227ba9f8aab"
        "c84e0a11c8c0dc6deb6771dd8cef09b0d51b9e77234d97d1c1fefc2d9e187ed3"
    },
    // secret
    "6d591b1caa5b1fada11e35cee218ca4e0d0ecf7238ec48271ebc2e86eb02e116"
    "304a8a52a9a8c8c13741bfea94d4072cc1a386e032600a2ef339b2ad6af9db48"
    "4eb7fad3dac54d2f4df7d40b8ec8268ed2553c149d25839e05766e2403d5cdce"
    "7c93b66dc17203ee94540f1621d47d5c58570c4786624e6181028b0cbbee1abb"
    "76a37c20e806e6367ab51b66cbb58dee5e569f83ae18c4ccaa5dde2937a72620"
    "4a26df22b2547763fcbc6f31257b473057ae676153d4bab2a461f2406e44d1ac"
    "2c6c91458ac67333dc8091161e547d5756d39bcbc2df274bc3c868d876291eac"
    "3dd407aabfb837cdac7fde223ffe6ee8c1a66a6c76e9a0e62f6eccdf869ce20d"
},
{
    // params
    {
        // modulus
        "ca60d25245efbba8c7f61d2344fd692aa42df7842b83131ad8e6afd94f51adf0"
        "1fc79a5db87ce2f7c2235fec416ae9d1268e1827b179a3602add735d167d6034"
        "cc4f6e33671e6e68bb5340ffc7e8172ed183881d20f773e271ff5db5524bdc3b"
        "8bf3ea9e505c993c7879b2c3575c25e0c66800266998ec45a0f8fcfb44884d07"
        "156ae63b5be321944453a5c425612a6d76d44fda03530423ffe08245a86702f6"
        "b9d7bc87103c4094d9cbb2a69a6560386f025cea444c2779a576efdfbe470209"
        "d091609c29a3321402993f820a67de6044a9a3eae9c11d882de1c19a8dd8f8bd"
        "c4193c432826cac60bed5e691b441a4c6995d1fe3117a9418777e767afdcdeff",
        // generator
        "758d43fb520121e1ad3d6af76e9e84da1057741594d14ca75d6ca296217df11f"
        "62db8703f3e212c8bbd381a961a83815f41e4135c068d27417d320acce628539"
        "3d8c456bf1298c29545426ede51ae129063159c9467ae7fea75864863a4b2d01"
        "feaf6e3da76caf62cfdb5d63751a6188f31b1191f46c0dd141079b16cf545d7c"
        "8db633759295efeb4357f8c7bb23006b5f541eb8b7d16f8d43d65b69455e1597"
        "27fa281cd80a01c4376922a2f0ddd3e1f61f42297a212f9f27fde0ded87974eb"
        "63eb1bf3f65986bce9868a88590196779f95e00a87bb271ab159e09c2596ae58"
        "e507ab285a0b0b1cf67aac8c31d51bf8da4d0ef99c7e9d5d7cfb765f75cc0a63"
    },
    // local_key
    {
        // priv
        "11c56feec7053b931294b44b08ec5210653c1264b7b305245b97872e",
        //pub
        "6d0ee76c49a260390e0723f201b1ef7008c8b2deb1d942090ac3c2f8e31973b4"
        "5d2312b2cd931fbbd1bd2faf4fbc93b9dfaea74a47bcd5a306fde0dfe38630fb"
        "cd3631db65168e09f36033ed1aec3c8e29c24b34d95ebd1e81ec8cf993d0a2f2"
        "a926807916cad9b9ff7d2bb982e503b7ee74969d318b6fc02e8ab5580fb2dea1"
        "f112ed4d23e6ead7930aafd45339697a62a51df70524e2fb94a8cf358115a2da"
        "3396eaa9933fada49127a3c42baef23b46d966ff97b28afcd4930be0b2cd34d9"
        "189b861613f50e4348758b47e50d4dea46695985d87de8bc7d550227ba9f8aab"
        "c84e0a11c8c0dc6deb6771dd8cef09b0d51b9e77234d97d1c1fefc2d9e187ed3"
    },
    // remote_key
    {
        // pub
        "46b4baa0d01823679a7f9eaaf3d2816f12ac6501ab80f5b513b5305d68795508"
        "e0a98528a75b79f4d3e247d9e456fc92c9a5e3a3b5968d7dcc672d5a982030b3"
        "b10bdd5ea11f35ba12f8014079adee0b7bc811f9c71a22421de76b6d834d2fd0"
        "8090128c705adda99b1165092bc90d3abccacf7d0894d3db0b5d229a6f3be973"
        "8510c11453729dcc83ae92560732b4a658215d872ee040c4736598337af724a4"
        "63265b540df4e009ff255d853dc0b72072b24a179ca9c5e9b8041f73ab88c8b6"
        "af1fbcc1b5b957a79903e516da82a5a3f3d9407bf1afed1e96bf168c0b972498"
        "d5e922204d0619d2415bd0a96bdda3fc19b0594712037fc783838c5f6269a8c1"
    },
    // secret
    "6d591b1caa5b1fada11e35cee218ca4e0d0ecf7238ec48271ebc2e86eb02e116"
    "304a8a52a9a8c8c13741bfea94d4072cc1a386e032600a2ef339b2ad6af9db48"
    "4eb7fad3dac54d2f4df7d40b8ec8268ed2553c149d25839e05766e2403d5cdce"
    "7c93b66dc17203ee94540f1621d47d5c58570c4786624e6181028b0cbbee1abb"
    "76a37c20e806e6367ab51b66cbb58dee5e569f83ae18c4ccaa5dde2937a72620"
    "4a26df22b2547763fcbc6f31257b473057ae676153d4bab2a461f2406e44d1ac"
    "2c6c91458ac67333dc8091161e547d5756d39bcbc2df274bc3c868d876291eac"
    "3dd407aabfb837cdac7fde223ffe6ee8c1a66a6c76e9a0e62f6eccdf869ce20d"
},
#endif  // B_DO_OSSL_BUILTIN
{
    // params
    {
        // modulus
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
        "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
        "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
        "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
        "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
        "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
        "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
        "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
        "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A"
        "7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038"
        "092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
        "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF",
        // generator
        "02"
    },
    // local_key
    {
        // priv
        "77C07EB4D4BA4A1D7AF7E6B4E4AE6B1750CA107EE9CA8CA2F98393E44B5322A9"
        "C32FE41EEAF9AECDBABC1A1113D21A7E078AECBC2363F9CD0D64582A3E07FB70"
        "40774C47A45FFD5B11A402BD0CB1073688244A6227D08A200DA5CF1CF38735F1"
        "10A4B337D2E2E6911B5798031C3876A00F3123D579AFDDF7CBFB4C1B13E31B01"
        "5C4E0B38FAB19E67BC7E308DD14FAA37943338C5AFB15D6214018B5437DF3404"
        "5C641661C2ED4560ABFB3AFB2B70CEA6F88AA88DC2F10438880D7BC441DEC19F"
        "CBC28A69E79CCE1E504645417AC0A774387A4FC24EB0329FC48328663D62807E"
        "C966DE8224A03F6DDF6FB8BFE9D80FACBDAA8FD9D7E7259998505945D9D74336"
        "E93B1DC3783E85E4261FE8808989249436B91CF53F9E9B5743549E91ACCAAA3C"
        "44D7DF92D20882D90DB55522D3CF9E5EC0EC64A36AFAAE5C163DF8E5D1BFE34F"
        "7214CAD34FC2D631D3BF043DD1898F60EC29AFC1A13EFE283D418B73295819A4"
        "43EDF7D9BBA9169F6E83BFCCF6F5F767CBCD6431F5E8BFC4E64DDFFF06238CDE"
        "9D4C5CF2B65CF6611AE30408CB83E3CB6F9D72822A17C31963D580507ACAB9F9"
        "53EC18FB2711B29A5F49A2856B041918AD01A7F2AB1BB6B1F8521028EE63EF86"
        "22AC5B0A93AE4B1F22F524DBB5E64C585A8111025DE9BBA8059C98AC98A85DCA"
        "FDD06E970332C732103BA78D8E1FE7D7E9E4A30128B7F4DBAD78C62764B602B3",
        //pub
        "836E88E644743DB61718594FAFB6949D9AE69070ABA1B7C3FF60509417798AD1"
        "7386AD6A333DBDCFC5E197CF171AB776C803308CD27794AA3D4E9DAF23DEB990"
        "7C08AA300C19204D9BB173B2BCE425C1677E92917906B5CFD9B1635B990B1809"
        "C71AFBA2C6ED6BB867444A41039812241C2925AD8B430CD8C7D90DA1F34BBBD5"
        "6A22255B17623FE7018A645BFE3DA6DD25F087832806F318F2FD84235A6F7163"
        "E5D94B51DBEE07F6BAE72B96E0D981A94176EB04491855CC85718CCCE75B3AF9"
        "C0F6D859059552B55F17590CBC443E11A2A43BDE3A452E55553A5C1A1EB314E1"
        "EC4AD560124DFDE93426AE2A3034647E6D90E9FCEE6E6DB0EDC5DBF03750DBB7"
        "E76DBCBEA2F35FCAB429B2CEA1A4F22E02C6783ACF146E5F961425AADCBCC70A"
        "5E546DA321E09592E3C6D241DD554FF64C6398C99231A2FAF887B79BE3ED5975"
        "2B94ABABE2801AD36247E2A78FDB53425F52D83F0196DA1ED6C350A70DEB5A48"
        "21945AFC4A866EBCFEC6B5C5C6792EC58E3CA1F04433E92AD65C364B4F119C08"
        "462364D50A1752668C1713BA96006D060B6129C678678A044FCC93D0904C0CD2"
        "0CEF02CB38043E13D6A18999FD1518BA566241523981FE7B8A05B59B77758F4B"
        "03C995BAF6D2471F7993B67D33E3BC47D5A75D5D2D30522E5C508778F135194B"
        "B20A72531E4734A612022047B9492283EBDE75B7AC3F10414F86A2D642FC196C"
    },
    // remote_key
    {
        // pub
        "0CA57FE0DF5690FF79CB559BEFFD864281ED32FF622081BC0D9B6BEB30658483"
        "29F7A8788F01096C31418AD3C47B14CE7E8A010D5B99D05C4ED57181F8172408"
        "D474088A8971EAF71778D4B40548963B026E0EC0F2795C6BE24F605C2E79DD51"
        "DB007301E4E8A5EB02D3AAAB54BD2CEB7E27827F76EDCC12CB91BF3976488B2D"
        "C197F3C90987D6FA713DBDFD16303C68D53FBD80B99DC5D3ED597D5B6AAEBF14"
        "E6AE0548DFE2EFE7B86CE885394137BCF48CF7819024FBE43A8019F1BCE16F8C"
        "1C580214B3F7E81C08EA4C3B540DC80E1BE534104E09132D5C31D21C1E86904D"
        "5618847E407675ED730E43DE6E8B704C7A9583CCBB7B24F2B28BCE028E5656A3"
        "F60D5D0C1CB85F66C305CDAE6070D5A67FF27528C9BE1A3958D0AF9A61063AB0"
        "D88F86B956CA75E5EA83F9C72D12339F6A00534C2D86FB5ED7A77FAD3089E1CB"
        "7FC9C9B1F46E4A4379A995B51EE224CBDE42300EEB640ED63C17B5B93DCCFAAE"
        "E4C8350C58D6AC2096B1F5E8E1AE2D48096322C65A70112CA2D6FA037D66E68C"
        "46F1C3D83E6740EC558B695C7A9AE79B9DE0B5D8FC5C91C1B04B5BDD91A40604"
        "8CEC6494D5768AC3B33E5C0B9427E54B0AFACFE657BB89007B1B95D9A2A240D6"
        "E0CAD8456CE77F8F6F697C9C2604DCA192890BE70740A46FC76910C68768A69D"
        "7FB453FD52F44B0EBD0546B31E115F2424968B97050998AA30B510A60BEC24"
    },
    // secret
    "A5478DC545D626AFBA901CD9D038074B5CBB3BB7DAAAA41B65188B12ECED7B66"
    "AA74F66243254B0DBEAA48F68DD444588467C7B7B3F933B72D6D179CF5C01DF0"
    "3996E55C1BB5E39DA1E50F5D32E32900AFB659A1A55012F3D213AC3D0A7CE6ED"
    "F312FFA4826418EBD05AAF75E71F069369D3CFB80FF839D27C19F499A85E5921"
    "691BABB449FBCDEA7B2EC4CCFFA2FF39EF1CE52BA65F3A31C021D95C87901A26"
    "A7974E37D0165131455BC90C864AE449430124118D200E5C7D4DAB0D192F642B"
    "2053F59ACBE216B3E804BAC720D3889B5D16E2B0743305950D61B2D9EE822F62"
    "5045FBB10C087566775CAF237EE3D8739A9AEAB0C2F853A57BD1DDE96B7C0CE7"
    "01C37399EF7C48A07502E5012D892CA773A79B323132EE8DEAD1CAB29D750394"
    "BB1B055B2FECBC4C2EDA4CC0206FECC4DCD1CFE063E8A9E39F35312F4A31105A"
    "A9AE8D86202A65BA1F1A0352EDF8103686D8118FEE6C34A4B63F245E41BC2738"
    "FAB9A8B9AAA37E5F3AB190751B3B65546B5261553322DD978C9749C003A3794D"
    "946EC5CDBA0016A419FBC292582E275198A2C8677887D38DA82D1C17604F2260"
    "7776F22AB3DC456B2FB4DC0298C35F049F433D58BE73131DF5F64E528F643EA7"
    "35AD889F12095081F847BA2125BB0FA677426E24656FF377DD51573A64031885"
    "B595CEFC731B25FA7338F82FE1963EA668E84888F820F783FB7E2BCB8B3A3428"
},
{
    // params
    {
        // modulus
        "8ECCED3DFEBAC1FBCBBE41121C23940BC3AE926733431F77B9E2D973EF352630"
        "B21079E4AD1E1DA3BE44C4D5D0E4F5CE0BA387F62164A855F855301769DF07C9"
        "19C4A198B46F5CB1164EA47274F3C5AA92371D7DD7D5320AFCE88FC0EB5EEB90"
        "E5A5324CEAA2B7729316508121DFF681AAA4D60C084ED14D2F1EDE5FC2FE19B1"
        "F9179893555BB0F0E5F70A96741EAC6322450C515B75ACE9DDA1B70C317362AC"
        "533C26B08ACDD36C130D5FD87B0C98E51C5810AAD5BBEB898F304DD1141878CC"
        "FD5C9861A2C5A54C4CE58F0ADE9361CE1E4A25C6997434AFC21A29673B1A9D05"
        "C1665BD7A717E713F8C8C2299F09FBD2BD66BED2EE9F7B415F6EBA861764B573",
        // generator
        "02"
    },
    // local_key
    {
        // priv
        "013AA20D13D1046A9A4D5FECA5CF6F3FE57EC19C47DA9692CB883D9E937A582F"
        "799091C4E5E1DA42C9666297370375320EC3E88154E5F7BA61C88F1192879657"
        "45CCC3E34CE0351FA3E766EA397FB411EE279F260411E47FB77F0308D38FACD9"
        "EDAB8AF186D5A653E2B9AD202EA76F4D28BC160316D832B3284AC4073A8BF1AA"
        "F72F9A14839D34DC3C6353C2AB2AB227399A197A376BA9A4F5813F8FF0693E6B"
        "537CD99981DBA18AF390CE1D6A9FC9A26B5889DE915F9BA134330C6FBC4D36FD"
        "E7BA98D5366418BC24D4ED9692733B417C45CEE0894E7EBEF90B804E0A4296E4"
        "17052C4D9DAA5FA04539FB43823A8E50005465D9310DB1C4ECB03C496A22DF53",
        //pub
        "6D09B26A96D0B0D7B206D0EF2144B8D7C5D2601ED134242BD5F0BD0AA625C5EA"
        "BA1BEBC43A4B8820A18257B08E2C64F0B0CD7495081E5E050E451237784ACEB2"
        "201B1C28CDF771D4860E6A721CD788615F78E70F8BC512FA3A144761274FB64A"
        "06317A4F14AB8504BB01FB9B78251260965B6F2F30B3261743FF832AB3B03020"
        "FF75B27B2921F8630857493F4FC8868516CC06DBF1C802F5DCF8743292D5E6D0"
        "B8CDFCA0A244480584E3500E0C40F19B54052427554564AC9FEE1207FF85878C"
        "93280D18D1F7DEE3A714A28018ACB39F9AEAA352CAEC15E9BEC9E1299E09CE07"
        "6DC62E0A5A8FA36FCD8DAE30625B2BD857FA6A730C9367E60290E147EAFCEFCA"
    },
    // remote_key
    {
        // pub
        "1F413A20AD3AEDE745C14C26E935CE56AAFE1BFA31D44F4A11F04D110B7F8D86"
        "02E527BDF3FC30F4D6C8C5878F6B43751153BB674F8083D85A5B10309C1A32CF"
        "5FE3603EED7E19BD6C4867EBC4FF0EC6E9115433134E08D6AF9AB545C8856597"
        "3B8C9010C9EFB8863ED6E7BB79657480C400C3F2F1BC01778D314D2F9377744A"
        "6528D511683F97A4E3359506B5CB8FE9819CAAE9853FC9E1AE3E9D8F9212795C"
        "5EBF9C92C49FE413F7D32A9A1D89ACCBE988174E65E08242420B3265908C0ABD"
        "2F8894F4A8F6B6C0865262C537184BAEE156DC453E7FCBC187EAF18E0A32A117"
        "D2912BD15010C026E4974E914E248771DC680D7B0462DBA681ECCEAE56F432B4"
    },
    // secret
    "41575FD233013A758C22745A910C91FB14D18D96BCACFEED10366C30CB39C19D"
    "D17E29820CC10D478B14C8F3EF44666AA81F9EC661AB42810F46A6DA07D9917A"
    "05BF182CBC24541BF93FDE2590072A880DF1C9663E9BAB2EC13CC9D27EB90F9C"
    "7CB89C7D7D181FE56DD620B103844F07E860AEC17A57351E3B6B420CC21F13CE"
    "0BDB82E30719B9111BDFE304CADED1A3BC90C6895E68434ED8EC699E845729C9"
    "94E3319F42DED9F9000CED5CCCE031340F3CE52D53443723943B06E685404AB2"
    "301E1A300785E6D80558D6DCD87A3ED4C4ECB6B7D90C85B5DE887350DC247F30"
    "370FED3337D58F80DBEC3E7535569273F35D67C701B8879163671B09D3307B3F"
}
// More to follow...
};


class DhDeriveTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<DhParams>
{
public:
    DhDeriveTest()
    {
        DhParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_modulus =
            bcrypt_testing::number_from_string(params.params.modulus).value();
        bcrypt_testing::Number num_generator =
            bcrypt_testing::number_from_string(params.params.generator).value();
        bcrypt_testing::Number num_local_priv =
            bcrypt_testing::number_from_string(params.local_key.priv).value();
        bcrypt_testing::Number num_local_pub =
            bcrypt_testing::number_from_string(params.local_key.pub).value();
        bcrypt_testing::Number num_remote_pub =
            bcrypt_testing::number_from_string(params.remote_key.pub).value();
        bcrypt_testing::Number num_secret =
            bcrypt_testing::number_from_string(params.secret).value();

        // Initialize members from them
        local_key_ = construct_dh_key_private(num_modulus, num_generator,
            num_local_priv, num_local_pub);
        remote_key_ = construct_dh_key_public(num_modulus, num_generator,
            num_remote_pub);
        secret_ = num_secret;
    }

    bcrypt_testing::unique_EVP_PKEY local_key_;
    bcrypt_testing::unique_EVP_PKEY remote_key_;
    bcrypt_testing::Number secret_;
};

TEST_P(DhDeriveTest, HardCodedDerive)
{
    size_t outlen;
    bcrypt_testing::Number outsecret(secret_.size());

    // Create the context for the shared secret derivation
    bcrypt_testing::unique_EVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(local_key_.get(), NULL));
    OSSL_ASSERT_TRUE(ctx);
    // Initialise that context
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive_init(ctx.get()));
    // Provide the peer public key
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive_set_peer(ctx.get(), remote_key_.get()));
    // Check required buffer length for shared secret
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(ctx.get(), NULL, &outlen));
    ASSERT_GE(outsecret.size(), outlen);
    // Derive the secret
    OSSL_ASSERT_EQ(1, EVP_PKEY_derive(ctx.get(), &outsecret[0], &outlen));

    // Compare with the expected secret
    EXPECT_EQ(outsecret, secret_);
}

INSTANTIATE_TEST_CASE_P(DhDeriveTests, DhDeriveTest,
    testing::ValuesIn(dh_params));


#if 0
// Keep this around for later reference
// The CNG engine automaticall does SHA-ing of the shared secret, so need to
//     make distinction between CNG and non-CNG */
result = result_key_len;
e_cng_test_KDF kdf = e_cng_test_get_KDF();
if (kdf == NULL) {
    if (EVP_PKEY_derive(ctx, result_key, &result) != 1) handleErrors();
} else {
    unsigned char* shared_secret;
    size_t shared_secret_len = expected_key_len;
    shared_secret = OPENSSL_malloc(expected_key_len);
    if (EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len) != 1) handleErrors();
    result = result_key_len;
    kdf(shared_secret, shared_secret_len, result_key, &result);
    OPENSSL_free(shared_secret);
}
#endif
