
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
construct_ec_key_private(
    int nid,
    const bcrypt_testing::Number &num_priv_d)
{
    bcrypt_testing::unique_EC_GROUP group(EC_GROUP_new_by_curve_name(nid));
    if (!group) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_privkey(
        BN_bin2bn(num_priv_d.data(), (int)num_priv_d.size(), NULL));
    if (!bn_privkey) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_POINT pubkey(EC_POINT_new(group.get()));
    if (!pubkey) throw bcrypt_testing::ossl_error();

    if (EC_POINT_mul(group.get(), pubkey.get(), bn_privkey.get(),
        NULL, NULL, NULL) != 1) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_KEY eckey(EC_KEY_new_by_curve_name(nid));
    if (!eckey) throw bcrypt_testing::ossl_error();

    if (EC_KEY_set_private_key(eckey.get(), bn_privkey.get()) != 1)
        throw bcrypt_testing::ossl_error();
    if (EC_KEY_set_public_key(eckey.get(), pubkey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();
    if (EVP_PKEY_set1_EC_KEY(result.get(), eckey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}


static bcrypt_testing::unique_EVP_PKEY
construct_ec_key_public(
    int nid,
    const bcrypt_testing::Number &num_x,
    const bcrypt_testing::Number &num_y)
{
    bcrypt_testing::unique_EC_GROUP group(EC_GROUP_new_by_curve_name(nid));
    if (!group) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_x(
        BN_bin2bn(num_x.data(), (int)num_x.size(), NULL));
    if (!bn_x) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_y(
        BN_bin2bn(num_y.data(), (int)num_y.size(), NULL));
    if (!bn_y) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_POINT pubkey(EC_POINT_new(group.get()));
    if (!pubkey) throw bcrypt_testing::ossl_error();

    if (EC_POINT_set_affine_coordinates(group.get(), pubkey.get(),
        bn_x.get(), bn_y.get(), NULL) != 1) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_KEY eckey(EC_KEY_new_by_curve_name(nid));
    if (!eckey) throw bcrypt_testing::ossl_error();

    if (EC_KEY_set_public_key(eckey.get(), pubkey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();
    if (EVP_PKEY_set1_EC_KEY(result.get(), eckey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}

// Note: y always assumed positive -- that is OK for ECDH.
// If that is not what you need, use the function above.
static bcrypt_testing::unique_EVP_PKEY
construct_ec_key_public_compressed(
    int nid,
    const bcrypt_testing::Number &num_x)
{
    bcrypt_testing::unique_EC_GROUP group(EC_GROUP_new_by_curve_name(nid));
    if (!group) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_x(
        BN_bin2bn(num_x.data(), (int)num_x.size(), NULL));
    if (!bn_x) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_POINT pubkey(EC_POINT_new(group.get()));
    if (!pubkey) throw bcrypt_testing::ossl_error();

    // y always assumed positive
    if (EC_POINT_set_compressed_coordinates(group.get(), pubkey.get(),
        bn_x.get(), 1, NULL) != 1) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EC_KEY eckey(EC_KEY_new_by_curve_name(nid));
    if (!eckey) throw bcrypt_testing::ossl_error();

    if (EC_KEY_set_public_key(eckey.get(), pubkey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_EVP_PKEY result(EVP_PKEY_new());
    if (!result) throw bcrypt_testing::ossl_error();
    if (EVP_PKEY_set1_EC_KEY(result.get(), eckey.get()) != 1)
        throw bcrypt_testing::ossl_error();

    return result;
}


static std::vector<unsigned char>
construct_ecdsa_sig(
    const bcrypt_testing::Number &num_r,
    const bcrypt_testing::Number &num_s)
{
    bcrypt_testing::unique_BIGNUM bn_r(
        BN_bin2bn(num_r.data(), (int)num_r.size(), NULL));
    if (!bn_r) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_BIGNUM bn_s(
        BN_bin2bn(num_s.data(), (int)num_s.size(), NULL));
    if (!bn_s) throw bcrypt_testing::ossl_error();

    bcrypt_testing::unique_ECDSA_SIG sig(ECDSA_SIG_new());
    if (!sig) throw bcrypt_testing::ossl_error();
    // set0 transfers ownership so need to dup here */
    if (ECDSA_SIG_set0(sig.get(), BN_dup(bn_r.get()),
        BN_dup(bn_s.get())) != 1) throw bcrypt_testing::ossl_error();

    int sig_len = i2d_ECDSA_SIG(sig.get(), NULL);
    if (sig_len <= 0) throw bcrypt_testing::ossl_error();
    std::vector<unsigned char> sig_bytes(sig_len);
    unsigned char *p = sig_bytes.data();
    sig_len = i2d_ECDSA_SIG(sig.get(), &p);
    if (sig_len > (int)sig_bytes.size()) throw bcrypt_testing::ossl_error();
    sig_bytes.resize(sig_len);

    return sig_bytes;
}

// ----------------------------------------------------------------------------
//
// EC key generation value-parameterized tests
//
// ----------------------------------------------------------------------------

// Generate key for a specific type of curve
struct EcGenerateParams {
    int curve_nid;
};


static const EcGenerateParams ec_generate_params[] = {
{
        // curve_nid
        NID_X9_62_prime256v1
    },
    {
        // curve_nid
        NID_secp384r1
    },
    {
        // curve_nid
        NID_secp521r1
    }
};


class EcGenerateTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<EcGenerateParams>
{
public:
    EcGenerateTest()
    {
        EcGenerateParams params = GetParam();

        // Initialize members from parameters
        curve_nid_ = params.curve_nid;
    }

    int curve_nid_;
};

// use EVP functions to generate public/private ec components
TEST_P(EcGenerateTest, SimpleGenerate)
{
    bcrypt_testing::unique_EVP_PKEY_CTX params_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    OSSL_ASSERT_TRUE(params_ctx);
    // Initialize the parameter generation context
    OSSL_ASSERT_EQ(1, EVP_PKEY_paramgen_init(params_ctx.get()));
    // Specifying the curve we want to use
    OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
        params_ctx.get(), curve_nid_));
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
    EVP_PKEY* temp_ec_key(nullptr);
    OSSL_ASSERT_EQ(1, EVP_PKEY_keygen(key_ctx.get(), &temp_ec_key));
    bcrypt_testing::unique_EVP_PKEY ec_key(temp_ec_key);
    ASSERT_TRUE(ec_key);
}

INSTANTIATE_TEST_CASE_P(EcGenerateTests, EcGenerateTest,
    testing::ValuesIn(ec_generate_params));


// ---------------------------------------------------------------------------
//
// ECDH value-parameterized tests
//
// ---------------------------------------------------------------------------

// Parameters for this type of ECDH test
struct EcdhParams {
    int nid;
    const char *local_key_d;
    const char *remote_key_x;
    const char* secret;
};

static const EcdhParams ec_dh_params[] = {
{
    // nid
    NID_X9_62_prime256v1,
    // local_key_d
    "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
    // remote_key_x
    "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
    // secret
    "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
},
{
    // nid
    NID_X9_62_prime256v1,
    // local_key_d
    "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5",
    // remote_key_x
    "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
    // secret
    "057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67"
},
{
    // nid
    NID_secp384r1,
    // local_key_d
    "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774"
    "ad463b205da88cf699ab4d43c9cf98a1",
    // remote_key_x
    "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
    "734466b400091adbf2d68c58e0c50066",
    // secret
    "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457"
    "e5621e766c40a2e3d4d6a04b25e533f1"
},
{
    // nid
    NID_secp384r1,
    // local_key_d
    "83d70f7b164d9f4c227c767046b20eb34dfc778f5387e32e834b1e6daec20edb"
    "8ca5bb4192093f543b68e6aeb7ce788b",
    // remote_key_x
    "a721f6a2d4527411834b13d4d3a33c29beb83ab7682465c6cbaf6624aca6ea58"
    "c30eb0f29dd842886695400d7254f20f",
    // secret
    "1023478840e54775bfc69293a3cf97f5bc914726455c66538eb5623e218feef7"
    "df4befa23e09d77145ad577db32b41f9"
},
{
    // nid
    NID_secp521r1,
    // local_key_d
    "0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce8027351"
    "51f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9ed"
    "b4d6fc47",
    // remote_key_x
    "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a949034"
    "0854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf1766668"
    "77a2046d",
    // secret
    "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e13"
    "6672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148"
    "c831"
},
{
    // nid
    NID_secp521r1,
    // local_key_d
    "000001fd90e3e416e98aa3f2b6afa7f3bf368e451ad9ca5bd54b5b14aee2ed67"
    "23dde5181f5085b68169b09fbec721372ccf6b284713f9a6356b8d560a8ff78c"
    "a3737c88",
    // remote_key_x
    "000001c35823e440a9363ab98d9fc7a7bc0c0532dc7977a79165599bf1a9cc64"
    "c00fb387b42cca365286e8430360bfad3643bc31354eda50dc936c329ecdb609"
    "05c40fcb",
    // secret
    "0100c8935969077bae0ba89ef0df8161d975ec5870ac811ae7e65ca5394efba4"
    "f0633d41bf79ea5e5b9496bbd7aae000b0594baa82ef8f244e6984ae87ae1ed1"
    "24b7"
}
// More to follow...
};


class EcdhDeriveTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<EcdhParams>
{
public:
    EcdhDeriveTest()
    {
        EcdhParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_local_d =
            bcrypt_testing::number_from_string(params.local_key_d).value();
        bcrypt_testing::Number num_remote_x =
            bcrypt_testing::number_from_string(params.remote_key_x).value();
        bcrypt_testing::Number secret =
            bcrypt_testing::number_from_string(params.secret).value();

        // Initialize members from them
        local_key_ = construct_ec_key_private(params.nid, num_local_d);
        remote_key_ = construct_ec_key_public_compressed(params.nid, num_remote_x);
        secret_ = secret;
    }

    bcrypt_testing::unique_EVP_PKEY local_key_;
    bcrypt_testing::unique_EVP_PKEY remote_key_;
    bcrypt_testing::Number secret_;
};

TEST_P(EcdhDeriveTest, DeriveAliceBob)
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

INSTANTIATE_TEST_CASE_P(EcdhDeriveTests, EcdhDeriveTest,
    testing::ValuesIn(ec_dh_params));


#if 0
// Keep this around for later reference
// The CNG engine automaticall does SHA-ing of the shared secret, so need to
//     make distinction between CNG and non-CNG */
result = result_key_len;
e_cng_test_KDF kdf = e_cng_test_get_KDF();
if (kdf == NULL) {
    if (EVP_PKEY_derive(ctx, result_key, &result) != 1) handleErrors();
} else {
    unsigned char* secret;
    size_t secret_len = expected_key_len;
    secret = OPENSSL_malloc(expected_key_len);
    if (EVP_PKEY_derive(ctx, secret, &secret_len) != 1) handleErrors();
    result = result_key_len;
    kdf(secret, secret_len, result_key, &result);
    OPENSSL_free(secret);
}
#endif


// Parameters for this type of test
struct EcdsaSignVerifyParams {
    int nid;
    const char* key_signer_d;
    const char* to_be_signed;
};

static const EcdsaSignVerifyParams ecdsa_sign_verify_params[] = {
{
    // nid
    NID_X9_62_prime256v1,
    // key_signer_d
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    // to_be_signed
    "12345678901234567890123456789012"
}
// More to follow...
};


class EcdsaSignVerifyTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<EcdsaSignVerifyParams>
{
public:
    EcdsaSignVerifyTest()
    {
        EcdsaSignVerifyParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_key_signer =
            bcrypt_testing::number_from_string(params.key_signer_d).value();
        bcrypt_testing::Bytes bytes_to_be_signed =
            bcrypt_testing::number_from_string(params.to_be_signed).value();

        // Initialize members from them
        key_signer_ = construct_ec_key_private(params.nid, num_key_signer);
        to_be_signed_ = bytes_to_be_signed;
    }

    bcrypt_testing::unique_EVP_PKEY key_signer_;
    bcrypt_testing::Bytes to_be_signed_;
};


TEST_P(EcdsaSignVerifyTest, SignVerify)
{
    size_t signature_len;

    const EVP_MD* md_type = EVP_sha256();
    OSSL_ASSERT_NE(nullptr, md_type);
 
    // Create signature
    bcrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_sign_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(),
        NULL, md_type, NULL, key_signer_.get()));
    OSSL_ASSERT_EQ(1, EVP_DigestSignUpdate(md_sign_ctx.get(),
        to_be_signed_.data(), to_be_signed_.size()));
    OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
        NULL, &signature_len));
    std::vector<unsigned char>signature(signature_len);
    OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
        &signature[0], &signature_len));
    ASSERT_LE(signature_len, signature.size());
    signature.resize(signature_len);

    // Verify signature just created
    bcrypt_testing::unique_EVP_MD_CTX md_verify_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_verify_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyInit(md_verify_ctx.get(),
        NULL, md_type, NULL, key_signer_.get()));
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyUpdate(md_verify_ctx.get(),
        to_be_signed_.data(), to_be_signed_.size()));
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyFinal(md_verify_ctx.get(),
        &signature[0], signature.size()));
}

INSTANTIATE_TEST_CASE_P(EcdsaSignVerifyTests, EcdsaSignVerifyTest,
    testing::ValuesIn(ecdsa_sign_verify_params));



// Parameters for this type of test
struct EcdsaVerifyParams {
    int nid;
    int digest_nid;
    struct {
        const char *x;
        const char *y;
    } key_signer;
    const char* was_signed;
    struct {
        const char *r;
        const char *s;
    } signature;
    bool verifies;
};

static const EcdsaVerifyParams ec_dsa_verify_params[] = {
#if 0
{
    // nid
    NID_X9_62_prime256v1,
    // digest_nid
    NID_sha256,
    // key_signer
    {
        "",
        ""
    },
    // was_signed
    "",
    // signature
    {
        "",
        ""
    },
    // verifies

},
#endif
{
    // nid
    NID_X9_62_prime256v1,
    // digest_nid
    NID_sha256,
    // key_signer
    {
        "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
        "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"
    },
    // was_signed
    "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f"
    "d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217"
    "ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce4"
    "70a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
    // signature
    {
        "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f",
        "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c"
    },
    // verifies
    true
},
{
    // nid
    NID_X9_62_prime256v1,
    // digest_nid
    NID_sha256,
    // key_signer
    {
        "e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864",
        "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a"
    },
    // was_signed
    "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730f"
    "b68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f226"
    "63bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a"
    "6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08",
    // signature
    {
        "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407",
        "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a"
    },
    // verifies
    true
},
{
    // nid
    NID_X9_62_prime256v1,
    // digest_nid
    NID_sha256,
    // key_signer
    {
        "87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555",
        "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9"
    },
    // was_signed
    "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
    // signature
    {
        "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0",
        "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6"
    },
    // verifies
    false
},
{
    // nid
    NID_secp384r1,
    // digest_nid
    NID_sha256,
    // key_signer
    {
        "86ac12dd0a7fe5b81fdae86b12435d316ef9392a3f50b307ab65d9c6079dd0d2"
        "d819dc09e22861459c2ed99fbab66fae",
        "ac8444077aaed6d6ccacbe67a4caacee0b5a094a3575ca12ea4b4774c030fe1c"
        "870c9249023f5dc4d9ad6e333668cc38"
    },
    // was_signed
    "862cf14c65ff85f4fdd8a39302056355c89c6ea1789c056262b077dab33abbfd"
    "a0070fce188c6330de84dfc512744e9fa0f7b03ce0c14858db1952750d7bbe6b"
    "d9c8726c0eae61e6cf2877c655b1f0e0ce825430a9796e7420e5c174eab7a504"
    "59e291510bc515141738900d390217c5a522e4bde547e57287d8139dc916504e",
    // signature
    {
        "798065f1d1cbd3a1897794f4a025ed47565df773843f4fa74c85fe4d30e3a394"
        "783ec5723b530fc5f57906f946ce15e8",
        "b57166044c57c7d9582066805b5885abc06e0bfc02433850c2b74973205ca357"
        "a2da94a65172086f5a1580baa697400b"
    },
    // verifies
    true
},
{
    // nid
    NID_secp384r1,
    // digest_nid
    NID_sha384,
    // key_signer
    {
        "cb908b1fd516a57b8ee1e14383579b33cb154fece20c5035e2b3765195d1951d"
        "75bd78fb23e00fef37d7d064fd9af144",
        "cd99c46b5857401ddcff2cf7cf822121faf1cbad9a011bed8c551f6f59b2c360"
        "f79bfbe32adbcaa09583bdfdf7c374bb"
    },
    // was_signed
    "9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef"
    "85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860"
    "cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c336"
    "25e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd",
    // signature
    {
        "33f64fb65cd6a8918523f23aea0bbcf56bba1daca7aff817c8791dc92428d605"
        "ac629de2e847d43cee55ba9e4a0e83ba",
        "4428bb478a43ac73ecd6de51ddf7c28ff3c2441625a081714337dd44fea8011b"
        "ae71959a10947b6ea33f77e128d3c6ae"
    },
    // verifies
    true
},
{
    // nid
    NID_secp521r1,
    // digest_nid
    NID_sha512,
    // key_signer
    {
        "0153eb2be05438e5c1effb41b413efc2843b927cbf19f0bc9cc14b693eee26394"
        "a0d8880dc946a06656bcd09871544a5f15c7a1fa68e00cdc728c7cfb9c448034867",
        "0143ae8eecbce8fcf6b16e6159b2970a9ceb32c17c1d878c09317311b7519ed5e"
        "ce3374e7929f338ddd0ec0522d81f2fa4fa47033ef0c0872dc049bb89233eef9bc1"
    },
    // was_signed
    "f69417bead3b1e208c4c99236bf84474a00de7f0b9dd23f991b6b60ef0fb3c62"
    "073a5a7abb1ef69dbbd8cf61e64200ca086dfd645b641e8d02397782da92d354"
    "2fbddf6349ac0b48b1b1d69fe462d1bb492f34dd40d137163843ac11bd099df7"
    "19212c160cbebcb2ab6f3525e64846c887e1b52b52eced9447a3d31938593a87",
    // signature
    {
        "dd633947446d0d51a96a0173c01125858abb2bece670af922a92dedcec067136"
        "c1fa92e5fa73d7116ac9c1a42b9cb642e4ac19310b049e48c53011ffc6e7461c36",
        "efbdc6a414bb8d663bb5cdb7c586bccfe7589049076f98cee82cdb5d203fddb2"
        "e0ffb77954959dfa5ed0de850e42a86f5a63c5a6592e9b9b8bd1b40557b9cd0cc0"
    },
    // verifies
    true
}
// More to follow...
};


class EcdsaVerifyTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<EcdsaVerifyParams>
{
public:
    EcdsaVerifyTest()
    {
        struct EcdsaVerifyParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_key_signer_x =
            bcrypt_testing::number_from_string(params.key_signer.x).value();
        bcrypt_testing::Number num_key_signer_y =
            bcrypt_testing::number_from_string(params.key_signer.y).value();
        bcrypt_testing::Bytes bytes_was_signed =
            bcrypt_testing::number_from_string(params.was_signed).value();
        bcrypt_testing::Number num_sig_r =
            bcrypt_testing::number_from_string(params.signature.r).value();
        bcrypt_testing::Number num_sig_s =
            bcrypt_testing::number_from_string(params.signature.s).value();

        // Initialize members from them
        digest_ = EVP_get_digestbynid(params.digest_nid);
        key_signer_ = construct_ec_key_public(
            params.nid, num_key_signer_x, num_key_signer_y);
        was_signed_ = bytes_was_signed;
        signature_ = construct_ecdsa_sig(num_sig_r, num_sig_s);
        verifies_ = params.verifies;
    }

    const EVP_MD *digest_;
    bcrypt_testing::unique_EVP_PKEY key_signer_;
    bcrypt_testing::Bytes was_signed_;
    std::vector<unsigned char> signature_;
    bool verifies_;
};

TEST_P(EcdsaVerifyTest, Verify)
{
    OSSL_ASSERT_NE(nullptr, digest_);

    // Verify signature provided
    bcrypt_testing::unique_EVP_MD_CTX md_verify_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_verify_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyInit(md_verify_ctx.get(),
        NULL, digest_, NULL, key_signer_.get()));
    OSSL_ASSERT_EQ(1, EVP_DigestVerifyUpdate(md_verify_ctx.get(),
        was_signed_.data(), was_signed_.size()));
    if (verifies_) {
        OSSL_ASSERT_EQ(1, EVP_DigestVerifyFinal(md_verify_ctx.get(),
            signature_.data(), signature_.size()));
    } else {
        OSSL_ASSERT_EQ(0, EVP_DigestVerifyFinal(md_verify_ctx.get(),
            signature_.data(), signature_.size()));
        // There should be an error message...
        // Check if any error messages have been ignored
        // Note: for some reason, the builtin OpenSSL implementation
        //   does not set any error values in this case.
        if (!doing_builtin()) {
            OSSL_EXPECT_NE(bcrypt_testing::GetOpenSSLErrors(), "")
                << "Expected to find OpenSSL error string";
        }
    }
}

INSTANTIATE_TEST_CASE_P(EcdsaVerifyTests, EcdsaVerifyTest,
    testing::ValuesIn(ec_dsa_verify_params));
