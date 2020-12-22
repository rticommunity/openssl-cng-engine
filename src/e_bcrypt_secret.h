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

/* Older windows versions do not support raw key agreement. That is a problem
 * because OpenSSL expects it. If raw DH is not available, an appropriate SHA
 * is selected. However, this will break interoperability between engines that
 * do support raw and those that don't. It is probably time to upgrade! */
#ifndef B_NO_RAW_SECRET
#ifndef BCRYPT_KDF_RAW_SECRET
#define B_NO_RAW_SECRET 1
#else
#define B_NO_RAW_SECRET 0
#endif
#endif

#if B_NO_RAW_SECRET
#pragma message(                                                               \
    "Warning: Key agreement raw mode not supported for this Windows version")

int
secret_derive(BCRYPT_KEY_HANDLE h_my_private_key,
              BCRYPT_KEY_HANDLE h_other_public_key, int magic, PUCHAR *key_out,
              ULONG *len_out);

#else /* B_NO_RAW_SECRET */

int
secret_derive(BCRYPT_KEY_HANDLE h_my_private_key,
              BCRYPT_KEY_HANDLE h_other_public_key, PUCHAR *key_out,
              ULONG *len_out);

#endif /* B_NO_RAW_SECRET */