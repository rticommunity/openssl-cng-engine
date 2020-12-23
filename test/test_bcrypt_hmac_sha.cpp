
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
generate_hardcoded_hmac_key(
    const bcrypt_testing::Number& num_key)
{
    bcrypt_testing::unique_EVP_PKEY hmac_key(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_HMAC, NULL, num_key.data(), num_key.size()));
    if (!hmac_key) throw bcrypt_testing::ossl_error();

    return hmac_key;
}


// ----------------------------------------------------------------------------
//
// HMAC value-parameterized tests
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct HmacParams {
    int nid;
    const char* secret_key;
    const char* was_signed;
    const char* hmac_tag;
};

static const HmacParams hmac_params[] = {
#if 0
{
    // nid
    NID_sha256,
    // secret key   
    "6b6579",
    // message
    "54686520717569636b2062726f776e20666f78206a756d7073206f7665722074"
    "6865206c617a7920646f67",
    // hmac tag
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
},
{
    // nid
    NID_sha256,
    // secret key   
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    // message
    "4869205468657265",
    // hmac tag
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
},
{
    // nid
    NID_sha384,
    // secret key   
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    // message
    "4869205468657265",
    // hmac tag
    "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
    "faea9ea9076ede7f4af152e8b2fa9cb6"
},
{
    // nid
    NID_sha512,
    // secret key   
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    // message
    "4869205468657265",
    // hmac tag
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
},
{
    // nid
    NID_sha256,
    // secret key   
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa",
    // message
    // "This is a test using a larger than block-size key and a larger than block-size data. "
    // "The key needs to be hashed before being used by the HMAC algorithm.",
    "5468697320697320612074657374207573696e672061206c6172676572207468"
    "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
    "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
    "647320746f20626520686173686564206265666f7265206265696e6720757365"
    "642062792074686520484d414320616c676f726974686d2e",
    // hmac tag
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
},
{
    // nid
    NID_sha384,
    // secret key   
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa",
    // message
    // "This is a test using a larger than block-size key and a larger than block-size data. "
    // "The key needs to be hashed before being used by the HMAC algorithm.",
    "5468697320697320612074657374207573696e672061206c6172676572207468"
    "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
    "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
    "647320746f20626520686173686564206265666f7265206265696e6720757365"
    "642062792074686520484d414320616c676f726974686d2e",
    // hmac tag
    "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5"
    "a678cc31e799176d3860e6110c46523e"
},
#endif
{
    // nid
    NID_sha512,
    // secret key   
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa",
    // message
    // "This is a test using a larger than block-size key and a larger than block-size data. "
    // "The key needs to be hashed before being used by the HMAC algorithm.",
    "5468697320697320612074657374207573696e672061206c6172676572207468"
    "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
    "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
    "647320746f20626520686173686564206265666f7265206265696e6720757365"
    "642062792074686520484d414320616c676f726974686d2e",
    // hmac tag
    "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
    "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
}
// More to follow...
};


class HmacTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<HmacParams>
{
public:
    HmacTest()
    {
        HmacParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Number num_secret_key =
            bcrypt_testing::number_from_string(params.secret_key).value();
        bcrypt_testing::Bytes was_signed =
            bcrypt_testing::number_from_string(params.was_signed).value();
        bcrypt_testing::Number hmac_tag =
            bcrypt_testing::number_from_string(params.hmac_tag).value();

        // Initialize members from them
        digest_ = EVP_get_digestbynid(params.nid);
        secret_key_ = generate_hardcoded_hmac_key(num_secret_key);
        was_signed_ = was_signed;
        hmac_tag_ = hmac_tag;
    }

    const EVP_MD *digest_;
    bcrypt_testing::unique_EVP_PKEY secret_key_;
    bcrypt_testing::Bytes was_signed_;
    bcrypt_testing::Number hmac_tag_;
};

TEST_P(HmacTest, DigestSign)
{
    OSSL_ASSERT_NE(nullptr, digest_);

    bcrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_sign_ctx);

    OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(),
        NULL, digest_, NULL, secret_key_.get()));
    std::vector<unsigned char> signature(hmac_tag_.size());
    size_t signature_len = signature.size();
    OSSL_ASSERT_EQ(1, EVP_DigestSign(md_sign_ctx.get(),
        &signature[0], &signature_len, was_signed_.data(), was_signed_.size()));
    EXPECT_EQ(signature, hmac_tag_);
}

TEST_P(HmacTest, DigestSignSteps)
{
    OSSL_ASSERT_NE(nullptr, digest_);

    bcrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_sign_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(),
        NULL, digest_, NULL, secret_key_.get()));
    OSSL_ASSERT_EQ(1, EVP_DigestSignUpdate(md_sign_ctx.get(),
        was_signed_.data(), was_signed_.size()));
    std::vector<unsigned char> signature(hmac_tag_.size());
    size_t signature_len = signature.size();
    OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
        &signature[0], &signature_len));
    EXPECT_EQ(signature, hmac_tag_);
}


INSTANTIATE_TEST_CASE_P(HmacTests, HmacTest,
    testing::ValuesIn(hmac_params));
