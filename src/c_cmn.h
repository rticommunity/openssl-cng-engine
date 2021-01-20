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

/* Windows-specific includes and definitions */
#include "c_cmn_dbg.h"
#include "c_cmn_ossl.h"
#include "c_cmn_win.h"

#define CMN_UNUSED(p) UNREFERENCED_PARAMETER(p)

#define CMN_malloc(n)            OPENSSL_malloc(n)
#define CMN_zalloc(n)            OPENSSL_zalloc(n)
#define CMN_realloc(p, n)        OPENSSL_realloc(p, n)
#define CMN_free(p)              OPENSSL_free(p)
#define CMN_memcpy(dst, src, n)  memcpy((dst), (src), (n))
#define CMN_memset(dst, val, n)  memset((dst), (val), (n))
#define CMN_strdup(str)          OPENSSL_strdup(str)
#define CMN_strnlen(str, n)      strnlen_s(str, n)
#define CMN_strncpy(dst, src, n) strncpy_s(dst, n + 1, src, n)
