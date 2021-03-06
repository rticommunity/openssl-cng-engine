
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

namespace bcrypt_testing {

// Test fixture that includes memory leak detection and OpenSSL init/deinit
class Test : public testing::Test
{
public:
    Test();
    ~Test() override;
    // These have to be public because this class is used in TEST_P
    static void SetUpTestCase();
    static void TearDownTestCase();
protected:
    bool doing_builtin();
};

// Crypto types and convenience functions
using Number = std::vector<unsigned char>; // key, IV, tag
using Bytes = std::vector<unsigned char>; // plaintext, ciphertext

// return unfilled optionals if input is invalid
std::optional<Number> number_from_string(const std::string &str); // non-empty hexstring
std::optional<Bytes> bytes_from_string(const std::string &str); // hexstring

// Convenience macros, use them for OpenSSL test results only, when deriving
// from the above test fixture
// Add more if you need them...

} // namespace bcrypt_testing
