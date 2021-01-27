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

/* suppress warning about _snprintf_s not getting inlined */
#pragma warning(push)
#pragma warning(disable : 4710)
#include <openssl/store.h> /* For CTRL values */
#pragma warning(pop)

/* This engine implements a store that supports loading of objects
 *   referenced via the cng scheme */

#ifdef __cplusplus
extern "C" {
#endif

extern const char *ncrypt_store_id;

/* Support for dynamically loadable engines */
int
ncrypt_store_bind(ENGINE *engine);

/* Support for statically linked engines */
void
engine_load_ncrypt_store(void);

#ifdef __cplusplus
}
#endif

/* Commands implemented by the store */
/* NCRYPT_CMD_VERIFY_CERT: uses CNG functions to verify a certificate,
 *   with the Windows CertStore as the trust base. This is the same
 *   CertStore that was opened when opening the OSSL_STORE.
 *   This is similar to the X509_verify_cert function, and its prototype
 *   is modeled after that.
 * Usage: STORE_ctrl(store_ctx, STORE_CMD_VERIFY_CERT,
 *                   X509_STORE_CTX *ctx, int *result) */

#define NCRYPT_CMD_VERIFY_CERT OSSL_STORE_C_CUSTOM_START

/* Elements that make up the URI */

/* The URI aligns with the PowerShell Cert provider, exposing
 * the certificate namespace as the cert: drive, like
 * cert:\LocalMachine\My to reference an entire store or
 * cert:\LocalMachine\My\123456 to reference a single element.
 * This path can optionally be followed by a ? followed by
 * ;-separated name-value pairs for querying.
 * Front slashes are allowed too. */

#define NCRYPT_SCHEME "cert"

/* Store type recognized values */
#define NCRYPT_STORAGE_KIND_VAL_CURRENT_USER  "CurrentUser"
#define NCRYPT_STORAGE_KIND_VAL_LOCAL_MACHINE "LocalMachine"

typedef enum {
    NCRYPT_STORAGE_KIND_UNKNOWN,
    NCRYPT_STORAGE_KIND_CURRENT_USER,
    NCRYPT_STORAGE_KIND_LOCAL_MACHINE
} ncrypt_storage_kind;

/* Object kind element name for querying particular types of objects */
#define NCRYPT_OBJECT_KIND_ELMT "object-kind"
/* Object kind recognized values */
#define NCRYPT_OBJECT_KIND_VAL_PKEY   "pkey"
#define NCRYPT_OBJECT_KIND_VAL_PARAMS "parms"
#define NCRYPT_OBJECT_KIND_VAL_CERT   "cert"
#define NCRYPT_OBJECT_KIND_VAL_CRL    "crl"
/* There is no alias for NAME */

typedef enum {
    NCRYPT_OBJECT_KIND_UNKNOWN,
    NCRYPT_OBJECT_KIND_NAME,
    NCRYPT_OBJECT_KIND_PKEY,
    NCRYPT_OBJECT_KIND_PARAMS,
    NCRYPT_OBJECT_KIND_CERT,
    NCRYPT_OBJECT_KIND_CRL
} ncrypt_object_kind;

/* Distinguished name element name for querying by DN */
#define NCRYPT_DN_ELMT "distinguished-name"

/* NCrypt can use different types of key storage providers */
/* Storage provider element name */
#define NCRYPT_PROVIDERNAME_ELMT "provider-name"
/* Storage provider recognized values */
#define NCRYPT_PROVIDERNAME_VAL_DEFAULT       "default"
#define NCRYPT_PROVIDERNAME_VAL_MS            "ms"
#define NCRYPT_PROVIDERNAME_VAL_MS_SMART_CARD "ms-smart-card"
#define NCRYPT_PROVIDERNAME_VAL_MS_PLATFORM   "ms-platform"
/* Non-MS values are allowed too, then the full name is required */
