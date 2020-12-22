
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

#include <openssl/pem.h>
#include <openssl/err.h>


// Parameters for this type of test
struct SmimeParams {
    const char* signer_private_key_pem;
    const char* siger_certificate_pem;
    const char* data_to_be_signed;
};

static const SmimeParams smime_params[] = {
{
    // signer_private_key_pem
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfJb+j6yYc4bi/sWj\n"
    "xrikIpIK2JsNloJ3LPefMdSjbsuhRANCAATfpZq/hJ5Cf7BjWdKpiJpHKckuibV/\n"
    "zEM0TvlZQuegeDBgs/daX7mn3CCb9UyKbcFisxKyDQwT/qmmMj+0qjin\n"
    "-----END PRIVATE KEY-----",

    // signer_certificate_pem
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB8DCCAZcCCQCUZFfPX22tXTAJBgcqhkjOPQQBMIGAMQswCQYDVQQGEwJVUzEL\n"
    "MAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMR4wHAYDVQQKDBVSZWFs\n"
    "IFRpbWUgSW5ub3ZhdGlvbnMxDzANBgNVBAMMBlJUSSBDQTEdMBsGCSqGSIb3DQEJ\n"
    "ARYOc2VjdXJlQHJ0aS5jb20wHhcNMTUwNTAyMDAyMTA1WhcNMTgwNTAxMDAyMTA1\n"
    "WjCBgDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBD\n"
    "bGFyYTEeMBwGA1UECgwVUmVhbCBUaW1lIElubm92YXRpb25zMQ8wDQYDVQQDDAZS\n"
    "VEkgQ0ExHTAbBgkqhkiG9w0BCQEWDnNlY3VyZUBydGkuY29tMFkwEwYHKoZIzj0C\n"
    "AQYIKoZIzj0DAQcDQgAE36Wav4SeQn+wY1nSqYiaRynJLom1f8xDNE75WULnoHgw\n"
    "YLP3Wl+5p9wgm/VMim3BYrMSsg0ME/6ppjI/tKo4pzAJBgcqhkjOPQQBA0gAMEUC\n"
    "IEtx+9+FoatbR1cjJUowOBgW6VpmcyzEFiQCkjemRePmAiEA1WVuM9IpMsWaksqz\n"
    "9KAp0SmD0E2WHD7QI3hCTdGsHNM=\n"
    "-----END CERTIFICATE-----",

    //data_to_be_signed
    "This is the data to be signed"
}
// More to follow...
};


class SmimeTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<SmimeParams>
{
public:
    SmimeTest()
    {
        SmimeParams params = GetParam();

        // Read private key
        bcrypt_testing::unique_BIO bio_key(BIO_new(BIO_s_mem()));
        if (!bio_key) throw bcrypt_testing::ossl_error();
        int keylen = (int)strlen(params.signer_private_key_pem);
        if (keylen != BIO_write(bio_key.get(), params.signer_private_key_pem,
            keylen)) throw bcrypt_testing::ossl_error();
        bcrypt_testing::unique_EC_KEY ec_key(PEM_read_bio_ECPrivateKey(
            bio_key.get(), NULL, NULL, NULL));
        if (!ec_key) throw bcrypt_testing::ossl_error();
        bcrypt_testing::unique_EVP_PKEY private_key(EVP_PKEY_new());
        if (!private_key) throw bcrypt_testing::ossl_error();
        if (EVP_PKEY_set1_EC_KEY(private_key.get(), ec_key.get()) != 1)
            throw bcrypt_testing::ossl_error();

        // Get Certificate for signing the hash
        bcrypt_testing::unique_BIO bio_cert(BIO_new(BIO_s_mem()));
        if (!bio_cert) throw bcrypt_testing::ossl_error();
        int certlen = (int)strlen(params.siger_certificate_pem);
        if (certlen != BIO_write(bio_cert.get(), params.siger_certificate_pem,
            certlen)) throw bcrypt_testing::ossl_error();
        bcrypt_testing::unique_X509 certificate(
            PEM_read_bio_X509(bio_cert.get(), NULL, NULL, NULL));
        if (!certificate) throw bcrypt_testing::ossl_error();

        // Initialize members from them
        private_key_ = std::move(private_key);
        certificate_ = std::move(certificate);
        to_be_signed_ = params.data_to_be_signed;
    }

    bcrypt_testing::unique_EVP_PKEY private_key_;
    bcrypt_testing::unique_X509 certificate_;
    const char *to_be_signed_;
};


TEST_P(SmimeTest, SimpleSmime)
{
    // Read the data to be signed into a BIO
    bcrypt_testing::unique_BIO bio_data(BIO_new(BIO_s_mem()));
    OSSL_ASSERT_TRUE(bio_data);
    int data_len = (int)strlen(to_be_signed_);
    OSSL_ASSERT_EQ(data_len, BIO_write(bio_data.get(), to_be_signed_, data_len));

    // Sign the data. Have to use a multi-phased approach since SHA256 is required
    // Initial PKCS7 object
    int flags_in = PKCS7_TEXT | PKCS7_DETACHED | PKCS7_NOATTR
        | PKCS7_PARTIAL| PKCS7_STREAM;
    bcrypt_testing::unique_PKCS7 p7(PKCS7_sign(NULL, NULL, NULL,
        bio_data.get(), flags_in));

    // Add signer which will do the signing
    const EVP_MD *sign_md = EVP_sha256();
    OSSL_ASSERT_NE(nullptr, sign_md);
    const PKCS7_SIGNER_INFO *signer_info = PKCS7_sign_add_signer(
        p7.get(), certificate_.get(), private_key_.get(), sign_md, flags_in);
    OSSL_ASSERT_NE(nullptr, signer_info);

    // Write the resulting PKCS7 structure to the out bio
    bcrypt_testing::unique_BIO bio_result(BIO_new(BIO_s_mem()));
    OSSL_ASSERT_TRUE(bio_result);
    OSSL_ASSERT_EQ(1, SMIME_write_PKCS7(bio_result.get(), p7.get(),
        bio_data.get(), flags_in));

    // Verify the contents of the BIO just created
    int flags_out = PKCS7_TEXT | PKCS7_DETACHED | PKCS7_NOVERIFY | PKCS7_NOINTERN;
    bcrypt_testing::unique_BIO bio_final(BIO_new(BIO_s_mem()));
    OSSL_ASSERT_TRUE(bio_final);

    // Setup the PKCS7 structure for verification
    bcrypt_testing::unique_X509_stack certificates(sk_X509_new_null());
    OSSL_ASSERT_TRUE(certificates);
    OSSL_ASSERT_NE(0, sk_X509_push(certificates.get(), certificate_.get()));
    BIO* bio_temp = NULL;
    bcrypt_testing::unique_PKCS7 p7_verify(SMIME_read_PKCS7(bio_result.get(), &bio_temp));
    bcrypt_testing::unique_BIO bio_cont(bio_temp);
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
    ASSERT_STREQ(bio_final_bytes, to_be_signed_);
}

INSTANTIATE_TEST_CASE_P(SmimeTests, SmimeTest,
    testing::ValuesIn(smime_params));
