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

#define CMN_THIS_FILE "src/engine_bcrypt.c"

#include "c_cmn.h"
#include "e_bcrypt.h"

/* We depend on the following libraries */
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcrypto.lib")

static int
bcrypt_evp_bind_helper(ENGINE *engine, const char *engine_id)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    /* If engine_id is given, make sure it's the correct one */
    if ((engine_id != NULL) && (strcmp(engine_id, bcrypt_evp_id) != 0)) {
        CMN_DBG_ERROR("Can not bind engine \"%s\", only know \"%s\"", engine_id,
                      bcrypt_evp_id);
        goto done;
    }

    if (bcrypt_evp_bind(engine) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bcrypt_evp_bind_helper)
