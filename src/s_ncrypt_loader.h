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

#include "c_cmn_win.h" /* Required to avoid warning in ossl header */
#include <openssl/engine.h>
#include <openssl/store.h>

/* Constructor for the store loader that supports the 'cert:' scheme */
OSSL_STORE_LOADER *
s_ncrypt_loader_new(ENGINE *engine);

/* Destructor */
void
s_ncrypt_loader_free(OSSL_STORE_LOADER *self, ENGINE *engine);
