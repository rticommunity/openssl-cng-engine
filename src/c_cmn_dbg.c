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

#define CMN_THIS_FILE "src/c_cmn_dbg.c"

/* Interface */
#include "c_cmn_dbg.h"

#ifdef _DEBUG

/* Implementation */
#include "c_cmn.h"
#include <stdio.h> /* For vsnprintf_s */
#include <stdbool.h>

#define DBG_LEVEL_MIN            (-1)
#define DBG_LEVEL_ERROR          (0)
#define DBG_LEVEL_WARNING        (1)
#define DBG_LEVEL_API            (2)
#define DBG_LEVEL_TRACE          (3)
#define DBG_LEVEL_THRESH_DEFAULT DBG_LEVEL_ERROR

#define DBG_LENGTH_MAX (400)

static int S_level_thresh = DBG_LEVEL_THRESH_DEFAULT;

static void
dbg_vprintf(const char *format, va_list arglist)
{
    char buf[DBG_LENGTH_MAX + 3]; /* Additional space for CR/LF */
    char *p;
    int pos;

    pos = vsnprintf_s(buf, DBG_LENGTH_MAX, _TRUNCATE, format, arglist);
    if (0 > pos)
        pos = DBG_LENGTH_MAX;

    /* Strip off spaces at the end */
    p = &buf[pos - 1];
    while ((p >= buf) && isspace(*p)) {
        *p = '\0';
        p = &p[-1];
    }
    p = &p[1];

    /* and make sure there is a CR/LF at the end */
    p[0] = '\r';
    p[1] = '\n';
    p[2] = '\0';

    /* Send the result to the debug facility */
    OutputDebugString(buf);
}

static int
dbg_printf(int level, const char *format, ...)
{
    int result = 0;
    if (S_level_thresh >= level) {
        va_list args;
        va_start(args, format);
        dbg_vprintf(format, args);
        va_end(args);
        result = 1;
    }
    return result;
}

void
c_cmn_dbg_set_threshold(int level)
{
    S_level_thresh = level;
}

int
c_cmn_dbg_trace_enter(const char *func_name)
{
    return dbg_printf(DBG_LEVEL_TRACE, "   --> %s", func_name);
}

int
c_cmn_dbg_trace_leave(const char *func_name)
{
    dbg_printf(DBG_LEVEL_TRACE, "  <--  %s", func_name);
    return 0;
}

int
c_cmn_dbg_api_enter(const char *func_name)
{
    return dbg_printf(DBG_LEVEL_API, "[\n  %s", func_name);
}

int
c_cmn_dbg_api_leave(const char *func_name)
{
#if 0
    UNREFERENCED_PARAMETER(func_name);
    return dbg_printf(DBG_LEVEL_API, "]");
#else
    return dbg_printf(DBG_LEVEL_API, "  %s\n]", func_name);
#endif
}

int
c_cmn_dbg_warning(const char *format, ...)
{
    int result = 0;
    if (S_level_thresh >= DBG_LEVEL_WARNING) {
        va_list args;
        va_start(args, format);
        dbg_vprintf(format, args);
        va_end(args);
        result = 1;
    }
    return result;
}

int
c_cmn_dbg_error(const char *format, ...)
{
    int result = 0;
    if (S_level_thresh >= DBG_LEVEL_ERROR) {
        va_list args;
        va_start(args, format);
        dbg_vprintf(format, args);
        va_end(args);
        result = 1;
    }
    return result;
}

#endif /* _DEBUG */
