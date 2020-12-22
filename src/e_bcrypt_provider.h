/*
 * (c) 2020 Copyright, Real-Time Innovations, Inc. (RTI)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/* Functions for internal use within the EVP BCrypt lib only */

#include "c_cmn_win.h"

/* Intended to be used in conjunction with InitOnceExecuteOnce and friends */
enum bcrypt_algorithm {
    B_AES_GCM_ALG,
    B_DH_ALG,
    B_ECDH_P256_ALG,
    B_ECDH_P384_ALG,
    B_ECDH_P521_ALG,
    B_ECDSA_P256_ALG,
    B_ECDSA_P384_ALG,
    B_ECDSA_P521_ALG,
    B_HMAC_SHA1_ALG,
    B_HMAC_SHA256_ALG,
    B_HMAC_SHA384_ALG,
    B_HMAC_SHA512_ALG,
    B_RNG_ALG,
    B_RSA_ALG,
    B_SHA1_ALG,
    B_SHA256_ALG,
    B_SHA384_ALG,
    B_SHA512_ALG
};

BOOL CALLBACK
alg_provider_open(PINIT_ONCE initOnce,
                  PVOID algorithm_ptr, /* enum bcrypt_algorithm* */
                  LPVOID *handle_out /* BCRYPT_ALG_HANDLE* */);

WCHAR const *
alg_provider_name(enum bcrypt_algorithm alg_kind);
