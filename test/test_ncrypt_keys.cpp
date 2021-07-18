
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

#include "test_ncrypt.h"
#include "test_ncrypt_ossl.h"

#include <openssl/rsa.h> // for padding definitions

#include <list>

// Test Fixture for all load-related tests
// The parameter to the test is the name of the Windows Certificate Store

class KeysTest :
    public ncrypt_testing::Test,
    public testing::WithParamInterface<const char*>
{
public:
    KeysTest() {}
protected:
    void SetUp() override
    {
        std::list<std::string> pkey_ids;
        // Open the store
        const char *store_var = GetParam();
        std::string store_name = CertStoreUriFromEnv(store_var);
        ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
            store_name.c_str(), NULL, NULL, NULL, NULL));
        OSSL_ASSERT_TRUE(ctx);
        // Only interested in keys here
        OSSL_ASSERT_EQ(1, OSSL_STORE_expect(ctx.get(), OSSL_STORE_INFO_PKEY));

        // OSSL_STORE_eof() simulates file semantics for any repository to signal
        // that no more data can be expected. Note that load() needs to be run
        // before EOF can be detected.
        do {
            ncrypt_testing::unique_OSSL_STORE_INFO info(OSSL_STORE_load(ctx.get()));
            OSSL_ASSERT_NE(1, OSSL_STORE_error(ctx.get()));
            if (info) {
                const char* name;
                const char* desc;
                OSSL_ASSERT_EQ(OSSL_STORE_INFO_NAME,
                    OSSL_STORE_INFO_get_type(info.get()));
                OSSL_ASSERT_NE(nullptr, name = OSSL_STORE_INFO_get0_NAME(info.get()));
                OSSL_ASSERT_NE(nullptr, desc = OSSL_STORE_INFO_get0_NAME_description(info.get()));
                pkey_ids.push_back(name);
            }
            else {
                // Expecting to arrive here only at eof
                OSSL_ASSERT_EQ(1, OSSL_STORE_eof(ctx.get()));
            }
        } while (OSSL_STORE_eof(ctx.get()) != 1);
        // Fail if we did not find any usable keys
        ASSERT_NE(0, pkey_ids.size());

        // Got the list of all key names, lets load them all
        for (std::string pkey_id : pkey_ids) {
            // Open the store
            ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
                pkey_id.c_str(), NULL, NULL, NULL, NULL));
            OSSL_ASSERT_TRUE(ctx);
            // Only interested in keys here
            OSSL_ASSERT_EQ(1, OSSL_STORE_expect(ctx.get(), OSSL_STORE_INFO_PKEY));
            // Do the actual loading of the cert
            ncrypt_testing::unique_OSSL_STORE_INFO info(OSSL_STORE_load(ctx.get()));
            OSSL_ASSERT_NE(1, OSSL_STORE_error(ctx.get()));
            OSSL_ASSERT_TRUE(info);
            // Double check it all looks good
            OSSL_ASSERT_EQ(OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_get_type(info.get()));
            std::shared_ptr<EVP_PKEY> pkey(OSSL_STORE_INFO_get1_PKEY(info.get()), EVP_PKEY_free);
            OSSL_ASSERT_TRUE(pkey);
            pkeys_.push_back(pkey);
        }
    }

    std::list<std::shared_ptr<EVP_PKEY>> pkeys_;
};

#define MESSAGE "12345678901234567890123456789012"
#define MESSAGE_LEN (sizeof(MESSAGE)-1)

TEST_P(KeysTest, SignVerify)
{
    // Walk over all previously loaded keys
    for (std::shared_ptr<EVP_PKEY> pkey : pkeys_)
    {
        // "Standard" padding first, let OpenSSL figure it out
        {
            ncrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
            OSSL_ASSERT_TRUE(md_sign_ctx);
            const EVP_MD *md_type = EVP_sha256();
            OSSL_ASSERT_NE(nullptr, md_type);

            // Sign using the key just loaded
            OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(), NULL,
                md_type, NULL, pkey.get()));
            OSSL_ASSERT_EQ(1, EVP_DigestSignUpdate(md_sign_ctx.get(), MESSAGE,
                MESSAGE_LEN));
            size_t signature_len;
            OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(), NULL,
               &signature_len));
            std::vector<unsigned char> signature(signature_len);
            OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(),
                &signature[0], &signature_len));
            signature.resize(signature_len);

            // Verify the signature using the same key
            ncrypt_testing::unique_EVP_MD_CTX md_verify_ctx(EVP_MD_CTX_new());
            OSSL_ASSERT_TRUE(md_verify_ctx);
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyInit(md_verify_ctx.get(), NULL,
                md_type, NULL, pkey.get()));
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyUpdate(md_verify_ctx.get(),
                MESSAGE, MESSAGE_LEN));
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyFinal(md_verify_ctx.get(),
                &signature[0], signature.size()));
        }

        // For RSA, use PSS padding next
        if (EVP_PKEY_base_id(pkey.get()) == EVP_PKEY_RSA) {
            ncrypt_testing::unique_EVP_MD_CTX md_sign_ctx(EVP_MD_CTX_new());
            OSSL_ASSERT_TRUE(md_sign_ctx);
            const EVP_MD *md_type = EVP_sha256();
            OSSL_ASSERT_NE(nullptr, md_type);

            // Sign using the key just loaded, using PSS padding
            // No automatic memory management for this ctx because it gets
            // destroyed by ossl when the md ctx is destroyed
            EVP_PKEY_CTX *p_sign_ctx = NULL;
            OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(), &p_sign_ctx,
                md_type, NULL, pkey.get()));
            OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_padding(p_sign_ctx,
               RSA_PKCS1_PSS_PADDING));
            // Not changing any of the PSS parameters here -- need to add tests
            // for that
            OSSL_ASSERT_EQ(1, EVP_DigestSignInit(md_sign_ctx.get(), NULL,
                md_type, NULL, pkey.get()));
            OSSL_ASSERT_EQ(1, EVP_DigestSignUpdate(md_sign_ctx.get(), MESSAGE,
                MESSAGE_LEN));
            size_t signature_len;
            OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(), NULL,
               &signature_len));
            std::vector<unsigned char> signature(signature_len);
            OSSL_ASSERT_EQ(1, EVP_DigestSignFinal(md_sign_ctx.get(), &signature[0],
                &signature_len));
            signature.resize(signature_len);

            // Verify the signature using the same key
            ncrypt_testing::unique_EVP_MD_CTX md_verify_ctx(EVP_MD_CTX_new());
            OSSL_ASSERT_TRUE(md_verify_ctx);
            // No automatic memory management for this ctx because it gets
            // destroyed by ossl when the md ctx is destroyed
            EVP_PKEY_CTX *p_vfy_ctx = NULL;
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyInit(md_verify_ctx.get(),
                &p_vfy_ctx, md_type, NULL, pkey.get()));
            OSSL_ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_padding(
                p_vfy_ctx, RSA_PKCS1_PSS_PADDING));
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyUpdate(md_verify_ctx.get(),
                MESSAGE, MESSAGE_LEN));
            // Verification is expected to succeed
            OSSL_ASSERT_EQ(1, EVP_DigestVerifyFinal(md_verify_ctx.get(),
               &signature[0], signature.size()));
        }
    }
}

INSTANTIATE_TEST_CASE_P(KeysTests, KeysTest,
    testing::Values("GTEST_N_KEY_STORE_URI"));
