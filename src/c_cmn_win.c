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

#define CMN_THIS_FILE "src/c_cmn_win.c"

/* Interface */
#include "c_cmn_win.h"

/* Implementation */
#include "c_cmn.h"
#include "c_cmn_dbg.h"
#include <ntstatus.h>
#include <stdbool.h>

/* Keep it stupid simple, since we are only interested in a small
 *   subset of possible status values and having a table with
 *   const char *s avoids the need for memory allocation/release */

/* clang-format off */
static
const struct error_info_st {
    int value;
    const char *descr;
} error_infos[] = {

    /* From ntstatus.h */
    {STATUS_UNSUCCESSFUL,        "The requested operation was unsuccessful."},
    {STATUS_INVALID_HANDLE,      "An invalid HANDLE was specified."},
    {STATUS_INVALID_PARAMETER,   "An invalid parameter was passed to a service or function."},
    {STATUS_NOT_SUPPORTED,       "The request is not supported."},
    {STATUS_INVALID_SIGNATURE,   "The cryptographic signature is invalid."},
    {STATUS_AUTH_TAG_MISMATCH,   "The computed authentication tag did not match the input authentication tag."},
    {STATUS_INVALID_BUFFER_SIZE, "The size of the buffer is invalid for the specified operation."},
    {STATUS_HEAP_CORRUPTION,     "A heap has been corrupted."},

    /* From winerror.h */
    {NTE_BAD_FLAGS,         "Invalid flags specified."},
    {NTE_INVALID_HANDLE,    "The supplied handle is invalid."},
    {NTE_INVALID_PARAMETER, "The parameter is incorrect."},
    {CRYPT_E_PENDING_CLOSE, "Final closure is pending until additional frees or closes."},

    /* From nterror.h */
    {NTE_NO_MEMORY,      "Insufficient memory available for the operation."},
    {NTE_NO_MORE_ITEMS,  "No more data is available."},
    {NTE_BAD_KEYSET,     "Keyset does not exist"},
    {NTE_SILENT_CONTEXT, "Provider could not perform the action since the context was acquired as silent."},

    /* Sentinel, keep at the end */
    {-1, "<Unknown>"}
};
/* clang-format on */

const char *
c_cmn_win_status_string(NTSTATUS status)
{
    bool found = false;
    const struct error_info_st *info;

    info = &error_infos[0];
    while (!found && !(info->value == -1)) {
        found = (info->value == status);
        if (!found)
            info++;
    }

    return info->descr;
}

LPSTR
cmn_win_wstr_to_str_utf8(WCHAR const *wstr)
{
    LPSTR result = NULL;
    LPSTR mbstr = NULL;
    int buflen;
    int mblen;

    buflen = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (buflen == 0) {
        CMN_DBG_ERROR("WideCharToMultiByte, errno is %d", GetLastError());
        goto done;
    }

    mbstr = CMN_malloc(buflen);
    if (mbstr == NULL) {
        CMN_DBG_ERROR("Allocation of %d bytes failed", buflen);
        goto done;
    }

    mblen =
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, mbstr, buflen, NULL, NULL);
    if (mblen == 0) {
        CMN_DBG_ERROR("WideCharToMultiByte, errno is %d", GetLastError());
        goto done;
    }
    CMN_DBG_ASSERT(mblen == buflen);

    result = mbstr;

done:
    if (result == NULL) {
        CMN_free(mbstr);
    }
    return result;
}

LPWSTR
cmn_win_str_to_wstr_utf8(char const *str)
{
    LPWSTR result = NULL;
    LPWSTR wcstr = NULL;
    int buflen;
    int wclen;

    buflen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (buflen == 0) {
        CMN_DBG_ERROR("MultiByteToWideChar, errno is %d", GetLastError());
        goto done;
    }

    wcstr = CMN_malloc(buflen);
    if (wcstr == NULL) {
        CMN_DBG_ERROR("Allocation of %d bytes failed", buflen);
        goto done;
    }

    wclen = MultiByteToWideChar(CP_UTF8, 0, str, -1, wcstr, buflen);
    if (wclen == 0) {
        CMN_DBG_ERROR("MultiByteToWideChar, errno is %d", GetLastError());
        goto done;
    }
    CMN_DBG_ASSERT(wclen == buflen);

    result = wcstr;

done:
    if (result == NULL) {
        CMN_free(wcstr);
    }
    return result;
}
