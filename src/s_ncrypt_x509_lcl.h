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
#include "c_cmn_ossl.h"
#include <stdbool.h>

X509 *
ncrypt_x509_new(PCCERT_CONTEXT cert_ctx);

void
ncrypt_x509_free(X509 *x509_cert);

/* Helper functions */

/* Get a handle of the private key associated with this certificate */
bool
ncrypt_x509_certificate_to_key(PCCERT_CONTEXT cert_ctx,
                               NCRYPT_KEY_HANDLE *hkey_out);

/* Verify the certificate using the provided cert store */
bool
ncrypt_x509_verify_cert(HCERTSTORE store_handle, X509_STORE_CTX *x509_store_ctx,
                        int *result_out);
