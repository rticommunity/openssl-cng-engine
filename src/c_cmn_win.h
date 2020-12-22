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

#include <sdkddkver.h>

/* For detecting memory leaks, in case of debug build */
#define _CRTDBG_MAP_ALLOC

/* Windows headers cause warnings, depending on the SDK */

/* SDK 10.0.19041.0 */
#ifdef NTDDI_WIN10_VB
#if NTDDI_VERSION == NTDDI_WIN10_VB

/* Clean compilation, for a change :-) */
#include <crtdbg.h>
#include <assert.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#undef WIN32_LEAN_AND_MEAN

#endif
#endif

/* SDK 10.0.18362.0 */
#ifdef NTDDI_WIN10_19H1
#if NTDDI_VERSION == NTDDI_WIN10_19H1

#include <crtdbg.h>
#include <assert.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#pragma warning(push)
/* 4255: 'function' : no function prototype given: converting '()' to '(void)' */
#pragma warning(disable : 4255)
#include <Windows.h>
#pragma warning(pop)
#undef WIN32_NO_STATUS
#undef WIN32_LEAN_AND_MEAN

#endif
#endif

/* SDK 10.0.17763.0 */
#if defined NTDDI_WIN10_RS5
#if NTDDI_VERSION == NTDDI_WIN10_RS5

#pragma warning(push)
/* 4255: 'function' : no function prototype given: converting '()' to '(void)' */
/* 4668: 'symbol' is not defined as a preprocessor macro,
         replacing with '0' for 'directives' */
#pragma warning(disable : 4255 4668)
/* Anything that includes corecrt.h emits C4668 */
#include <crtdbg.h>
#include <assert.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#undef WIN32_LEAN_AND_MEAN
#pragma warning(pop)

#endif
#endif

#include <synchapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

#define NCRYPT_NULL       (NCRYPT_KEY_HANDLE)0
#define NT_FAILED(Status) (((NTSTATUS)(Status)) < 0)

#ifndef CMN_THIS_FILE
#pragma message("Definition of CMN_THIS_FILE for error information is missing")
#define CMN_THIS_FILE "<?>"
#endif

/* A convenience macro for checking NT return values
 * Note that this relies on the following conventions:
 * -  the function has a label to goto in case of problems, called done */

const char *
c_cmn_win_status_string(NTSTATUS status);

/* When done, free the result with CMN_free */
LPSTR
cmn_win_wstr_to_str_utf8(WCHAR const *wstr);

/* When done, free the result with CMN_free */
LPWSTR
cmn_win_str_to_wstr_utf8(char const *str);
