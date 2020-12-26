
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

#include "gtest/gtest.h"
#include <optional>

namespace ncrypt_testing {

// Test fixture that includes memory leak detection and OpenSSL init/deinit
class Test : public testing::Test
{
public:
    ~Test() override;
    // These have to be public because this class is used in TEST_P
    static void SetUpTestCase();
    static void TearDownTestCase();
    // Configured name for cert store to use
    std::string CertStoreUriFromEnv(const std::string &var_name);
};

} // namespace ncrypt_testing
