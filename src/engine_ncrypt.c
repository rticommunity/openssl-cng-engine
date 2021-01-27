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

#define CMN_THIS_FILE "src/engine_ncrypt.c"

/* Implementation */
#include <stdbool.h>
#include "c_cmn.h"
#include "s_ncrypt.h"
#include "openssl/engine.h"

/* We depend on the following libraries */
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcrypto.lib")

static int
ncrypt_store_bind_helper(ENGINE *engine, const char *engine_id)
{
    CMN_DBG_TRACE_ENTER;

    int result = 0;

    /* If engine_id is given, make sure it's the correct one */
    if ((engine_id != NULL) && (strcmp(engine_id, ncrypt_store_id) != 0)) {
        CMN_DBG_ERROR("Can not bind engine \"%s\", only know \"%s\"", engine_id,
                      ncrypt_store_id);
        goto done;
    }

    if (ncrypt_store_bind(engine) != 1)
        goto done;

    result = 1;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(ncrypt_store_bind_helper)

/* -------------------------------------------------- *
 * - External helper function for cert verification - *
 * -------------------------------------------------- */

const char *STORE_URI = "cert:/LocalMachine/My/";

OPENSSL_EXPORT
int
e_ncrypt_x509_verify_helper(X509_STORE_CTX *x509_store_ctx)
{
    CMN_DBG_API_ENTER;

    int result = 0;
    int ctrl_result = 0;
    OSSL_STORE_CTX *ossl_store_ctx = NULL;

    /* Get context from OSSL_STORE */
    ossl_store_ctx = OSSL_STORE_open(STORE_URI, NULL, NULL, NULL, NULL);
    if (ossl_store_ctx == NULL) {
        CMN_DBG_ERROR("Can not open store with URI %s", STORE_URI);
        goto done;
    }

    if (OSSL_STORE_ctrl(ossl_store_ctx, NCRYPT_CMD_VERIFY_CERT, x509_store_ctx,
                        &ctrl_result) != 1) {
        CMN_DBG_ERROR("Unable to verify certificate");
        goto done;
    }

    result = ctrl_result;

done:
    OSSL_STORE_close(ossl_store_ctx);

    CMN_DBG_API_LEAVE;
    return result;
}
