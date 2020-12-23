
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

#include "test_bcrypt_ossl.h"

#include <openssl/err.h>

#include <iostream>
#include <sstream>

std::string
bcrypt_testing::GetOpenSSLErrors()
{
    std::stringstream ss;
    unsigned long ossl_err;
    bool first = true;
    char buf[500];
    const char *e_file = NULL;
    int e_line;
    const char *e_data = NULL;
    int e_flags;

    while (0 != (ossl_err = ERR_get_error_line_data(
        &e_file, &e_line, &e_data, &e_flags)))
    {
        ERR_error_string_n(ossl_err, buf, sizeof(buf));
        if (!first) ss << std::endl;
        ss << e_file << "(" << e_line << "): " << buf;
        if ((e_flags & ERR_TXT_STRING) && (NULL != e_data)) {
            ss << ", " << e_data;
        }
        first = false;
    }
    return ss.str();
}
