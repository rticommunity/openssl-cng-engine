
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

// Test Fixture for all certificate-related tests
// The parameter to the test is the name of the Windows Certificate Store

class CertificatesTest :
    public ncrypt_testing::Test,
    public testing::WithParamInterface<const char *>
{
public :
    CertificatesTest() {}
protected:
    void SetUp() override
    {
        std::list<std::string> cert_ids;
        // Open the store
        const char *store_var = GetParam();
        std::string store_name = CertStoreUriFromEnv(store_var);
        ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
            store_name.c_str(), NULL, NULL, NULL, NULL));
        OSSL_ASSERT_TRUE(ctx);
        // Only interested in certificates here
        OSSL_ASSERT_EQ(1, OSSL_STORE_expect(ctx.get(), OSSL_STORE_INFO_CERT));

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
                cert_ids.push_back(name);
            } else {
                // Expecting to arrive here only at eof
                OSSL_ASSERT_EQ(1, OSSL_STORE_eof(ctx.get()));
            }
        } while (OSSL_STORE_eof(ctx.get()) != 1);
        // Fail if we did not find any usable certificates
        ASSERT_NE(0, cert_ids.size());

        for (std::string cert_id : cert_ids) {
            // Open the store
            ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
                cert_id.c_str(), NULL, NULL, NULL, NULL));
            OSSL_ASSERT_TRUE(ctx);
            // Only interested in certificates here
            OSSL_ASSERT_EQ(1, OSSL_STORE_expect(ctx.get(), OSSL_STORE_INFO_CERT));
            // Do the actual loading of the cert
            ncrypt_testing::unique_OSSL_STORE_INFO info(OSSL_STORE_load(ctx.get()));
            OSSL_ASSERT_NE(1, OSSL_STORE_error(ctx.get()));
            OSSL_ASSERT_TRUE(info);
            // Double check it all looks good
            OSSL_ASSERT_EQ(OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_get_type(info.get()));

            // Get the cert
            std::shared_ptr<X509> cert(OSSL_STORE_INFO_get1_CERT(info.get()), X509_free);
            OSSL_ASSERT_TRUE(cert);
            // and store it
            certs_.push_back(cert);
        }
    }

    std::list<std::shared_ptr<X509>> certs_;
};


#define CNG_STORE_CMD_VERIFY_CERT  OSSL_STORE_C_CUSTOM_START

TEST_P(CertificatesTest, Verify)
{
    for (std::shared_ptr<X509> cert : certs_) {
        // Verify the cert in the store
        ncrypt_testing::unique_X509_STORE_CTX x509_store_ctx(X509_STORE_CTX_new());
        OSSL_ASSERT_TRUE(x509_store_ctx);
        ncrypt_testing::unique_X509_STORE x509_store(X509_STORE_new());
        OSSL_ASSERT_TRUE(x509_store);
        OSSL_ASSERT_EQ(1, X509_STORE_CTX_init(x509_store_ctx.get(),
            x509_store.get(), cert.get(), NULL));
        // Open the store for verification
        const char *store_var = GetParam();
        std::string store_name = CertStoreUriFromEnv(store_var);
        ncrypt_testing::unique_OSSL_STORE_CTX ctx(OSSL_STORE_open(
            store_name.c_str(), NULL, NULL, NULL, NULL));
        OSSL_ASSERT_TRUE(ctx);
        // Do the actual verififcation
        int ctrl_result;
        OSSL_ASSERT_EQ(1, OSSL_STORE_ctrl(ctx.get(),
            CNG_STORE_CMD_VERIFY_CERT, x509_store_ctx.get(),
            &ctrl_result));
    }
}

INSTANTIATE_TEST_CASE_P(CertificatesTests, CertificatesTest,
    testing::Values("GTEST_N_CERT_STORE_URI"));
