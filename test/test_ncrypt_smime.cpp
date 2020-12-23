
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

#include <list>

// Test Fixture for all certifcate-key-pair-related tests
// The parameter to the test is the name of the Windows Certificate Store

// X509 certificate and private key will be stored together in a pair
using cert_key_pair = std::pair<std::shared_ptr<X509>, std::shared_ptr<EVP_PKEY>>;

class CertsKeysTest :
    public ncrypt_testing::Test,
    public testing::WithParamInterface<const char *>
{
public:
    CertsKeysTest() {}
protected:
    void SetUp() override
    {
        std::list<std::string> pkey_ids;
        // Open the store
        const char* store_name = GetParam();
        ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
            store_name, NULL, NULL, NULL, NULL));
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

        // Got the list of all key names, lets load them all
        for (std::string pkey_id : pkey_ids) {
            // First load the cert
            std::string cert_uri = pkey_id + "?object-kind=cert";
            // Open the store
            ncrypt_testing::unique_OSSL_STORE_CTX cert_ctx(OSSL_STORE_open(
                cert_uri.c_str(), NULL, NULL, NULL, NULL));
            OSSL_ASSERT_TRUE(cert_ctx);
            // Do the actual loading of the cert
            ncrypt_testing::unique_OSSL_STORE_INFO cert_info(OSSL_STORE_load(cert_ctx.get()));
            OSSL_ASSERT_NE(1, OSSL_STORE_error(cert_ctx.get()));
            OSSL_ASSERT_TRUE(cert_info);
            // Double check it all looks good
            OSSL_ASSERT_EQ(OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_get_type(cert_info.get()));
            std::shared_ptr<X509> cert(OSSL_STORE_INFO_get1_CERT(cert_info.get()), X509_free);
            OSSL_ASSERT_TRUE(cert);

            // Then load the key
            std::string pkey_uri = pkey_id + "?object-kind=pkey";
            // Open the store
            ncrypt_testing::unique_OSSL_STORE_CTX pkey_ctx(OSSL_STORE_open(
                pkey_uri.c_str(), NULL, NULL, NULL, NULL));
            // Do the actual loading of the cert
            ncrypt_testing::unique_OSSL_STORE_INFO pkey_info(OSSL_STORE_load(pkey_ctx.get()));
            OSSL_ASSERT_NE(1, OSSL_STORE_error(pkey_ctx.get()));
            OSSL_ASSERT_TRUE(pkey_info);
            // Double check it all looks good
            OSSL_ASSERT_EQ(OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_get_type(pkey_info.get()));
            std::shared_ptr<EVP_PKEY> pkey(OSSL_STORE_INFO_get1_PKEY(pkey_info.get()), EVP_PKEY_free);
            OSSL_ASSERT_TRUE(pkey);

            // Create the pair and push it to the list
            cert_key_pair pair(cert, pkey);
            cert_keys_.push_back(pair);
        }
    }

    std::list<cert_key_pair> cert_keys_;
};

#define MESSAGE "12345678901234567890123456789012"
#define MESSAGE_LEN (sizeof(MESSAGE)-1)

TEST_P(CertsKeysTest, SimpleSmime)
{
    // Walk over all previously loaded cert/key paris
    for (cert_key_pair pair : cert_keys_)
    {
        // Make a bit more readable
        X509* signer_cert = pair.first.get();
        EVP_PKEY* signer_pkey = pair.second.get();

        // Read the data to be signed into a BIO
        ncrypt_testing::unique_BIO bio_data(BIO_new(BIO_s_mem()));
        OSSL_ASSERT_TRUE(bio_data);
        OSSL_ASSERT_EQ(MESSAGE_LEN, BIO_write(bio_data.get(), MESSAGE, MESSAGE_LEN));

        // Sign the data. Have to use a multi-phased approach since SHA256 is required
        // Initial PKCS7 object
        int flags_in = PKCS7_TEXT | PKCS7_DETACHED | PKCS7_NOATTR
            | PKCS7_PARTIAL | PKCS7_STREAM;
        ncrypt_testing::unique_PKCS7 p7(PKCS7_sign(NULL, NULL, NULL,
            bio_data.get(), flags_in));

        // Add signer which will do the signing
        const EVP_MD* sign_md = EVP_sha256();
        OSSL_ASSERT_NE(nullptr, sign_md);
        const PKCS7_SIGNER_INFO* signer_info = PKCS7_sign_add_signer(
            p7.get(), signer_cert, signer_pkey, sign_md, flags_in);
        OSSL_ASSERT_NE(nullptr, signer_info);

        // Write the resulting PKCS7 structure to the out bio
        ncrypt_testing::unique_BIO bio_result(BIO_new(BIO_s_mem()));
        OSSL_ASSERT_TRUE(bio_result);
        OSSL_ASSERT_EQ(1, SMIME_write_PKCS7(bio_result.get(), p7.get(),
            bio_data.get(), flags_in));

        // Verify the contents of the BIO just created
        int flags_out = PKCS7_TEXT | PKCS7_DETACHED | PKCS7_NOVERIFY | PKCS7_NOINTERN;
        ncrypt_testing::unique_BIO bio_final(BIO_new(BIO_s_mem()));
        OSSL_ASSERT_TRUE(bio_final);

        // Setup the PKCS7 structure for verification
        ncrypt_testing::unique_X509_stack certificates(sk_X509_new_null());
        OSSL_ASSERT_TRUE(certificates);
        OSSL_ASSERT_NE(0, sk_X509_push(certificates.get(), signer_cert));
        BIO* bio_temp = NULL;
        ncrypt_testing::unique_PKCS7 p7_verify(SMIME_read_PKCS7(bio_result.get(), &bio_temp));
        ncrypt_testing::unique_BIO bio_cont(bio_temp);
        OSSL_ASSERT_TRUE(p7_verify);
        ASSERT_TRUE(bio_cont);

        // Do the verification
        OSSL_ASSERT_EQ(1, PKCS7_verify(p7_verify.get(), certificates.get(),
            NULL, bio_cont.get(), bio_final.get(), flags_out));

        // Compare the verified contents with the signed contents
        const char* bio_final_bytes;
        // Appent terminator for string equality
        OSSL_ASSERT_EQ(sizeof(""), BIO_write(bio_final.get(), "", sizeof("")));
        OSSL_ASSERT_LT(0, BIO_get_mem_data(bio_final.get(), &bio_final_bytes));
        ASSERT_STREQ(bio_final_bytes, MESSAGE);
    }
}

INSTANTIATE_TEST_CASE_P(CertsKeysTests, CertsKeysTest,
    testing::Values("cert:/CurrentUser/My/"));
