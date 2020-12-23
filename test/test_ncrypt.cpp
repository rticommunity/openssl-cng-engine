
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

/* For detecting memory leaks in the case that _DEBUG has been defined */
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include <algorithm>
#include <iterator>

#include <openssl/engine.h>

// We depend on the following openssl library,
// but it is not specified in their header files
#pragma comment(lib, "libcrypto.lib")

namespace ncrypt_testing {

// ----------------------------------------------------------------------------
//
// CngTest environment for OpenSSL
//
// ----------------------------------------------------------------------------

// Set to false if any of the tests had a failure
static bool S_no_failure = true;

class Environment : public ::testing::Environment {
public:
    ~Environment() override {}

    // Override this to define how to set up the environment.
    void SetUp() override
    {
#ifdef _DEBUG
        /* Debugging memory usage */
        _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);
#endif
        // Record memory usage before running the test
        _CrtMemCheckpoint(&start_mem_);

        // Initialize OpenSSL
        OSSL_ASSERT_EQ(1, OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL));
    }

    // Override this to define how to tear down the environment.
    void TearDown() override
    {
#ifndef NDEBUG
        _CrtMemState end_mem;
#endif
        _CrtMemState diff_mem;

        // Tear down OpenSSL. Normally this is not needed, but we do it to get
        // the full picture of memory usage. No unfreed blocks are epxected.
        // After this, OpenSSL can not be (re-)initialized in this process.
        OPENSSL_cleanup();

        // Memory leak checks only make sense if no failure has occured
        if (S_no_failure) {
            // Record memory usage after running the test
            _CrtMemCheckpoint(&end_mem);
            // Check for memory leaks
            if (_CrtMemDifference(&diff_mem, &start_mem_, &end_mem)) {
                // Workaround for known Google Test 1.8.1 result
                size_t known_sizes[_MAX_BLOCKS] = { 0, 8, 2324, 0, 0 };
                if (std::equal(std::begin(known_sizes), std::end(known_sizes),
                    std::begin(diff_mem.lSizes)))
                {
                    std::cout
                        << "--- Ignoring known false positive memleak from gtest 1.8.1"
                        << std::endl;
                }
                else {
                    _CrtMemDumpAllObjectsSince(&start_mem_);
                    FAIL();
                }
            }
        }
    }

private:
    _CrtMemState start_mem_;
};

// ----------------------------------------------------------------------------
//
// CngTest class implementation
//
// ----------------------------------------------------------------------------

// Name of the DDL to load
static const char* ENGINE_NAME = "engine-ncrypt";
// Need this static object around for proper setting up and tearing down
static ENGINE* S_engine = nullptr;

Test::~Test()
{
    S_no_failure &= !HasFailure();
}

void Test::SetUpTestCase()
{
    ENGINE* e;
    //const EVP_MD* sha256_md;

    // Load the engine
    OSSL_ASSERT_NE(nullptr, e = ENGINE_by_id("dynamic"));
    OSSL_ASSERT_EQ(1, ENGINE_ctrl_cmd_string(e, "SO_PATH", ENGINE_NAME, 0));
    OSSL_ASSERT_EQ(1, ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0));
    OSSL_ASSERT_EQ(1, ENGINE_ctrl_cmd_string(e, "debug_level", "1", 0));
    OSSL_ASSERT_EQ(1, ENGINE_init(e));
    OSSL_ASSERT_EQ(1, ENGINE_add(e));
    OSSL_ASSERT_EQ(1, ENGINE_set_default(e, ENGINE_METHOD_ALL));
    // Make sure SHA-256 is available
    //OSSL_ASSERT_NE(nullptr, (sha256_md = ENGINE_get_digest(e, NID_sha256)));
    //OSSL_ASSERT_EQ(1, EVP_add_digest(sha256_md));
    // Engine's structural refcount has been upped by ENGINE_by_id, lower it
    OSSL_ASSERT_EQ(1, ENGINE_free(e));
    // Keep the engine around for tearing down, possibly expose it to derived
    // classes in the future
    S_engine = e;
}

void Test::TearDownTestCase()
{
    // Remove engine, if needed
    if (nullptr != S_engine) {
        ENGINE* e = S_engine;
        S_engine = NULL;
        // Would be nice if ENGINE_set_default(NULL, ENGINE_METHOD_ALL)
        //   did all these, but we have to do them manually
        ENGINE_unregister_pkey_meths(e);
        ENGINE_unregister_ciphers(e);
        ENGINE_unregister_digests(e);
        ENGINE_unregister_EC(e);
        ENGINE_unregister_RAND(e);
        OSSL_EXPECT_EQ(1, ENGINE_remove(e));
        OSSL_EXPECT_EQ(1, ENGINE_finish(e));
    }

    // Check if any error messages have been ignored
    OSSL_EXPECT_EQ(ncrypt_testing::GetOpenSSLErrors(), "")
        << "OpenSSL errors have been ignored";
}

} // namespace ncrypt_testing

// ----------------------------------------------------------------------------
//
// Main
//
// ----------------------------------------------------------------------------

int main(
    int argc,
    char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    testing::AddGlobalTestEnvironment(new ncrypt_testing::Environment);
    return RUN_ALL_TESTS();
}
