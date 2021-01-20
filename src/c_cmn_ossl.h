/*
 * (c) 2020-2021 Copyright, Real-Time Innovations, Inc. (RTI)
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

#include "c_cmn_win.h" /* Required to avoid warnings in ossl header files */
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

/* Get rid of this construct after OpenSSL bug is fixed */
/* See https://github.com/openssl/openssl/issues/13797 */
#ifndef OSSL_INITIALIZES_ENGINE
#define OSSL_INITIALIZES_ENGINE 0
#endif
