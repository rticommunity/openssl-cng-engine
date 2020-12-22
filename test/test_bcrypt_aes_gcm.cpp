
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
// AES-GCM Encryption/Decryption value-parameterized tests
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct AesGcmParams {
    int nid;
    const char* key;
    const char* iv;
    const char* ciphertext;
    const char* tag;
    const char* plaintext;
};

static const AesGcmParams aes_gcm_params[] = {
{
    // nid
    NID_aes_256_gcm,
    // key
    "02f766c0fe1df7718d2d00a6a70ae757f2a513325d6eab528411ad8d4ae420bc",
    // iv
    "4690088234979bca3f7442c6",
    // ciphertext
    "9f26e984fda82f8ee3f60427845aee18c3346df91fabb2d738e9ac0a37ae2b72e9c101d0517f1b42c31b91c1aa4cbf38170324",
    // tag
    "5d4852f3dd3754be6be1a3103a3567",
    // plaintext
    "1252608f3eef8b376475264935ee7feaa35fdc37391197919c390ec06d6ba50b4cfdda5fba8a65b5488afff0f014fb1ad682c0"
},
{
    // nid
    NID_aes_256_gcm,
    // key
    "eebc1f57487f51921c0465665f8ae6d1658bb26de6f8a069a3520293a572078f",
    // iv
    "99aa3e68ed8173a0eed06684",
    // ciphertext
    "f7264413a84c0e7cd536867eb9f21736",
    // tag
    "6c7a53e55513a20bf14e7ead52263e4a",
    // plaintext
    "f56e87055bc32d0eeb31b2eacc2bf2a5"
}
// More to follow...
};


class AesGcmTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<AesGcmParams>
{
public:
    AesGcmTest()
    {
        AesGcmParams params = GetParam();

        key_ = bcrypt_testing::number_from_string(params.key).value();
        iv_ = bcrypt_testing::number_from_string(params.iv).value();
        ciphertext_ = bcrypt_testing::bytes_from_string(params.ciphertext).value();
        tag_ = bcrypt_testing::number_from_string(params.tag).value();
        plaintext_ = bcrypt_testing::bytes_from_string(params.plaintext).value();
        cipher_ = EVP_get_cipherbynid(params.nid);
    }

    bcrypt_testing::Number key_;
    bcrypt_testing::Number iv_;
    bcrypt_testing::Bytes ciphertext_;
    bcrypt_testing::Number tag_;
    bcrypt_testing::Bytes plaintext_;
    const EVP_CIPHER* cipher_;
};


TEST_P(AesGcmTest, Encrypt)
{
    int outlen, foutlen;
    bcrypt_testing::Bytes outbuf(ciphertext_.size());
    bcrypt_testing::Number outtag(tag_.size());
    unsigned char* outptr(nullptr);
    bcrypt_testing::unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());

    OSSL_ASSERT_TRUE(ctx);
    OSSL_ASSERT_EQ(1, EVP_EncryptInit_ex(ctx.get(), cipher_, NULL,
        key_.data(), iv_.data()));
    OSSL_ASSERT_EQ(1, EVP_EncryptUpdate(ctx.get(), &outbuf[0], &outlen,
        plaintext_.data(), (int)plaintext_.size()));
    if (outbuf.size() > (size_t)outlen) outptr = &outbuf[outlen];
    OSSL_ASSERT_EQ(1, EVP_EncryptFinal_ex(ctx.get(), outptr, &foutlen));
    outlen += foutlen;
    OSSL_ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
        (int)tag_.size(), &outtag[0]));

    // Compare results with expected values
    EXPECT_EQ(ciphertext_.size(), outlen) <<
        "Array of encrypted bytes does not have expected length";
    EXPECT_EQ(ciphertext_, outbuf) <<
        "Encrypted bytes do not match expected bytes";
    EXPECT_EQ(tag_, outtag) <<
        "GCM tag does not match expected tag";
}


TEST_P(AesGcmTest, Decrypt)
{
    int outlen, foutlen;
    bcrypt_testing::Bytes outbuf(plaintext_.size());
    unsigned char* outptr(nullptr);
    bcrypt_testing::unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());

    OSSL_ASSERT_TRUE(ctx);
    OSSL_ASSERT_EQ(1, EVP_DecryptInit_ex(ctx.get(), cipher_, NULL,
        key_.data(), iv_.data()));
    OSSL_ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
        (int)tag_.size(), tag_.data()));
    OSSL_ASSERT_EQ(1, EVP_DecryptUpdate(ctx.get(), &outbuf[0], &outlen,
        ciphertext_.data(), (int)ciphertext_.size()));
    if (outbuf.size() > (size_t)outlen) outptr = &outbuf[outlen];
    OSSL_ASSERT_EQ(1, EVP_DecryptFinal_ex(ctx.get(), outptr, &foutlen))
        << "GCM tag validation failed";
    outlen += foutlen;

    // Compare results with expected values
    EXPECT_EQ(plaintext_.size(), outlen) <<
        "Array of decrypted bytes does not have expected length";
    EXPECT_EQ(plaintext_, outbuf) <<
        "Decrypted bytes do not match expected bytes";
}

INSTANTIATE_TEST_CASE_P(AesGcmTests, AesGcmTest,
    testing::ValuesIn(aes_gcm_params));



// ----------------------------------------------------------------------------
//
// AES-GCM Decryption with incorrect tag value-parameterized tests
//
// ----------------------------------------------------------------------------


// Parameters for this type of test
struct AesGcmFailTagParams {
    int nid;
    const char* key;
    const char* iv;
    const char* ciphertext;
    const char* tag;
};

static const AesGcmFailTagParams aes_gcm_fail_tag_params[] = {
{
    // nid
    NID_aes_256_gcm,
    // key
    "02f766c0fe1df7718d2d00a6a70ae757f2a513325d6eab528411ad8d4ae420bc",
    // iv
    "4690088234979bca3f7442c6",
    // ciphertext
    "9f26e984fda82f8ee3f60427845aee18c3346df91fabb2d738e9ac0a37ae2b72e9c101d0517f1b42c31b91c1aa4cbf38170324",
    // tag
    "4d4852f3dd3754be6be1a3103a3567"
},
{
    // nid
    NID_aes_256_gcm,
    // key
    "eebc1f57487f51921c0465665f8ae6d1658bb26de6f8a069a3520293a572078f",
    // iv
    "99aa3e68ed8173a0eed06684",
    // ciphertext
    "f7264413a84c0e7cd536867eb9f21736",
    // tag
    "5c7a53e55513a20bf14e7ead52263e4b"
}
};


class AesGcmFailTagTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<AesGcmFailTagParams>
{
public:
    AesGcmFailTagTest()
    {
        AesGcmFailTagParams params = GetParam();

        // Convert parameters
        auto num_key = bcrypt_testing::number_from_string(params.key);
        auto num_iv = bcrypt_testing::number_from_string(params.iv);
        auto bytes_ciphertext = bcrypt_testing::bytes_from_string(params.ciphertext);
        auto num_tag = bcrypt_testing::number_from_string(params.tag);

        // Initialize members from it
        key_ = num_key.value();
        iv_ = num_iv.value();
        ciphertext_ = bytes_ciphertext.value();
        tag_ = num_tag.value();
        cipher_ = EVP_get_cipherbynid(params.nid);
    }

    bcrypt_testing::Number key_;
    bcrypt_testing::Number iv_;
    bcrypt_testing::Bytes ciphertext_;
    bcrypt_testing::Number tag_;
    const EVP_CIPHER* cipher_;
};


TEST_P(AesGcmFailTagTest, FailTag)
{
    int outlen, foutlen;
    bcrypt_testing::Bytes outbuf(ciphertext_.size());
    unsigned char* outptr(nullptr);

    bcrypt_testing::unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
    OSSL_ASSERT_TRUE(ctx);
    OSSL_ASSERT_EQ(1, EVP_DecryptInit_ex(ctx.get(), cipher_, NULL,
        key_.data(), iv_.data()));
    OSSL_ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
        (int)tag_.size(), tag_.data()));
    OSSL_ASSERT_EQ(1, EVP_DecryptUpdate(ctx.get(), &outbuf[0], &outlen,
        ciphertext_.data(), (int)ciphertext_.size()));
    if (outbuf.size() > (size_t)outlen) outptr = &outbuf[outlen];
    // This step should fail, meaning the return value should be 0
    OSSL_EXPECT_EQ(0, EVP_DecryptFinal_ex(ctx.get(), outptr, &foutlen))
        << "Tag verification succeeded unexpectedly";
    // There should be an error message...
    // Check if any error messages have been ignored
    // Note: for some reason, the builtin OpenSSL implementation
    //   does not set any error values in this case.
#ifndef B_DO_OSSL_BUILTIN
    OSSL_EXPECT_NE(bcrypt_testing::GetOpenSSLErrors(), "")
        << "Expected to find OpenSSL error string";
#endif
}

INSTANTIATE_TEST_CASE_P(AesGcmFailTagTests, AesGcmFailTagTest,
    testing::ValuesIn(aes_gcm_fail_tag_params));
