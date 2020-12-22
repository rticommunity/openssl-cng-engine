
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

#include "test_ncrypt_ossl.h"

#include <openssl/err.h>

std::string
ncrypt_testing::GetOpenSSLErrors()
{
    std::string result;
    unsigned long ossl_err;

    ossl_err = ERR_get_error();
    while (ossl_err != 0) {
        // Not thread safe, but convenient
        result = result + "\n" + ERR_error_string(ossl_err, NULL);
        ossl_err = ERR_get_error();
    }
    return result;
}
