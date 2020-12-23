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

#include <stdbool.h>

/* Format: cert:\<storage_kind>\<store_name>[\object_name] */
/* Return value is false if parsing failed, true otherwise.
 *   If parsing succeeds, the three out parameters will
 *   contain zero-terminated values. For object_name, 
 *   the returned value is possibly the empty string. */

struct ncrypt_uri_cracked_st {
    char *storage_kind_alias;
    char *store_name;
    char *object_id;
    char *object_kind;
};

#define ncrypt_uri_cracked_INITIALIZER                                         \
    {                                                                          \
        .storage_kind_alias = NULL, .store_name = NULL, .object_id = NULL,     \
        .object_kind = NULL                                                    \
    }

void
ncrypt_uri_cracked_finalize(struct ncrypt_uri_cracked_st cracked_inout);

bool
ncrypt_uri_crack(const char *uri, struct ncrypt_uri_cracked_st *cracked_out);

bool
ncrypt_uri_uncrack(const char *storage_kind_alias, const char *store_name,
                   const char *object_id, char **uri_out);

/* Return value is false if parsing failed, true otherwise.
 *   If parsing succeeds, value will contain the zero - terminated
 * value string if it was found, or a copy of the default_value
 *   if it was not found.The latter is allowed to be NULL.
 *   If it is not NULL, the string needs to be freed by the caller. */

bool
ncrypt_uri_lookup_value(const char *uri, const char *name,
                        const char *value_default, char **value_out);

/* Return value is false if parsing failed, true otherwise.
 *   If parsing succeeds, value will contain the zero - terminated
 * value string if it was found, or a copy of the default_value
 *   if it was not found.The latter is allowed to be NULL.
 *   If it is not NULL, the string needs to be freed by the caller. */

bool
ncrypt_uri_lookup_query_value(const char *uri, const char *name,
                              const char *value_default,
                              char **value /* out */);
