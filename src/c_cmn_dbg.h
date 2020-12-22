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

#include "c_cmn_win.h"

#if defined(_DEBUG) == defined(NDEBUG)
#error Exactly one of _DEBUG and NDEBUG needs to be defined
#endif

#ifdef _DEBUG

#include <inttypes.h>

/*  below 0 means complete silence
 *  0 means errors only
 *  1 means also emit warnings
 *  2 means also emit API call tracing
 *  3 and up means also emit full function tracing
 * Default: level 0
 * Note: this function is not thread safe and will set the level for all
 *       threads that use the debug facilities */
void
c_cmn_dbg_set_threshold(int level);

int
c_cmn_dbg_trace_enter(const char *func_name);

int
c_cmn_dbg_trace_leave(const char *func_name);

int
c_cmn_dbg_api_enter(const char *func_name);

int
c_cmn_dbg_api_leave(const char *func_name);

int
c_cmn_dbg_warning(const char *format, ...);

int
c_cmn_dbg_error(const char *format, ...);

/* The typical way to use the tracing functions is via these macros */

#define CMN_DBG_STR(x)      #x
#define CMN_DBG_TOSTRING(x) CMN_DBG_STR(x)

/* Version of AT for tracing purpose */
#define CMN_DBG_AT                                                             \
    __FUNCTION__ "() " CMN_THIS_FILE ":" CMN_DBG_TOSTRING(__LINE__)
/* Version of AT for errors/warnings, clickable in VS */
#define CMN_DBG_AT_VS __FILE__ "(" CMN_DBG_TOSTRING(__LINE__) ")"

#define CMN_DBG_TRACE_ENTER c_cmn_dbg_trace_enter(CMN_DBG_AT)
#define CMN_DBG_TRACE_LEAVE c_cmn_dbg_trace_leave(CMN_DBG_AT)
#define CMN_DBG_API_ENTER   c_cmn_dbg_api_enter(CMN_DBG_AT)
#define CMN_DBG_API_LEAVE   c_cmn_dbg_api_leave(CMN_DBG_AT)

/* Works only with literal strings for the format */
#define CMN_DBG_WARNING(format, ...)                                           \
    c_cmn_dbg_warning(CMN_DBG_AT_VS ": warning: " format, __VA_ARGS__)
#define CMN_DBG_ERROR(format, ...)                                             \
    c_cmn_dbg_error(CMN_DBG_AT_VS ": error: " format, __VA_ARGS__)

#define CMN_DBG_PRECOND(cond)                                                  \
    ((cond) || CMN_DBG_ERROR("Precond not met in " CMN_DBG_AT ": ", #cond));   \
    assert(cond)
#define CMN_DBG_PRECOND_NOT_NULL(var)                                          \
    (((var) != NULL) ||                                                        \
     CMN_DBG_ERROR("Non-null precond not met in " CMN_DBG_AT ": ", #var));     \
    assert((var) != NULL)
#define CMN_DBG_ASSERT(cond)                                                   \
    ((cond) || CMN_DBG_ERROR("Assertion failed in " CMN_DBG_AT ": ", #cond));  \
    assert(cond)
#define CMN_DBG_ASSERT_NOT_NULL(var)                                           \
    (((var) != NULL) ||                                                        \
     CMN_DBG_ERROR("Non-null assertion failed in " CMN_DBG_AT ": ", #var));    \
    assert(((var) != NULL))

#endif /* _DEBUG */

#ifdef NDEBUG

#define CMN_DBG_NOOP (void)0

#define CMN_DBG_TRACE_ENTER          CMN_DBG_NOOP
#define CMN_DBG_TRACE_LEAVE          CMN_DBG_NOOP
#define CMN_DBG_API_ENTER            CMN_DBG_NOOP
#define CMN_DBG_API_LEAVE            CMN_DBG_NOOP
#define CMN_DBG_WARNING(format, ...) CMN_DBG_NOOP
#define CMN_DBG_ERROR(format, ...)   CMN_DBG_NOOP

#define CMN_DBG_PRECOND(cond)         assert(cond)
#define CMN_DBG_ASSERT(cond)          assert(cond)
#define CMN_DBG_PRECOND_NOT_NULL(var) assert((var) != NULL)
#define CMN_DBG_ASSERT_NOT_NULL(var)  assert((var) != NULL)

#endif /* NDEBUG */
