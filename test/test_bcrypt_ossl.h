
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

#pragma once

#include <string>
#include <memory>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/store.h>

namespace bcrypt_testing {

std::string GetOpenSSLErrors();

class ossl_error : public std::runtime_error
{
public:
    ossl_error() : runtime_error(GetOpenSSLErrors()) {};
};

// All relevant OpenSSL types have this signature for their free function
template<class T>
using free_func = void (*)(T*);

template<class T, free_func<T> ff>
using unique_ptr = std::unique_ptr< T, std::integral_constant<free_func<T>, ff> >;

// Unique pointer versions of OpenSSL "raw" C-pointers
// Add more types as you need them
using unique_EVP_PKEY = unique_ptr<EVP_PKEY, EVP_PKEY_free>;
using unique_EVP_PKEY_CTX = unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using unique_EVP_CIPHER_CTX = unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;
using unique_EVP_MD_CTX = unique_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
using unique_RSA = unique_ptr<RSA, RSA_free>;
using unique_DH = unique_ptr<DH, DH_free>;
using unique_EC_KEY = unique_ptr<EC_KEY, EC_KEY_free>;
using unique_EC_GROUP = unique_ptr<EC_GROUP, EC_GROUP_free>;
using unique_EC_POINT = unique_ptr<EC_POINT, EC_POINT_free>;
using unique_ECDSA_SIG = unique_ptr<ECDSA_SIG, ECDSA_SIG_free>;
using unique_BIGNUM = unique_ptr<BIGNUM, BN_free>;
using unique_BN_CTX = unique_ptr<BN_CTX, BN_CTX_free>;
using unique_BIO = unique_ptr<BIO, BIO_free_all>;
using unique_X509 = unique_ptr<X509, X509_free>;
using unique_X509_stack = unique_ptr<STACK_OF(X509), sk_X509_free>;
using unique_PKCS7 = unique_ptr<PKCS7, PKCS7_free>;
using unique_OSSL_STORE_INFO = unique_ptr<OSSL_STORE_INFO, OSSL_STORE_INFO_free>;


// Handles are slightly different, they do not have a free func but close func
template<class T>
using close_func = int (*)(T*);

template<class T, close_func<T> cf>
using unique_handle = std::unique_ptr< T, std::integral_constant<close_func<T>, cf> >;

using unique_OSSL_STORE_CTX = unique_handle<OSSL_STORE_CTX, OSSL_STORE_close>;

} // namespace bcrypt_testing

#define OSSL_ASSERT_TRUE(val) ASSERT_TRUE(val) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_EQ(val1, val2) ASSERT_EQ(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_NE(val1, val2) ASSERT_NE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_LT(val1, val2) ASSERT_LT(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_LE(val1, val2) ASSERT_LE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_GT(val1, val2) ASSERT_GT(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_ASSERT_GE(val1, val2) ASSERT_GE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()

#define OSSL_EXPECT_TRUE(val) EXPECT_TRUE(val) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_EQ(val1, val2) EXPECT_EQ(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_NE(val1, val2) EXPECT_NE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_LT(val1, val2) EXPECT_LT(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_LE(val1, val2) EXPECT_LE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_GT(val1, val2) EXPECT_GT(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
#define OSSL_EXPECT_GE(val1, val2) EXPECT_GE(val1, val2) << bcrypt_testing::GetOpenSSLErrors()
