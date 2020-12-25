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

#define CMN_THIS_FILE "src/s_ncrypt_uri.c"

/* Interface */
#include "s_ncrypt_uri_lcl.h"

/* Implementation */
/* suppress warning about _snprintf_s not getting inlined */
#pragma warning(push)
#pragma warning(disable : 4710)
#include "c_cmn.h"
#pragma warning(pop)

#include "s_ncrypt.h"
#include "s_ncrypt_err.h"

/* Functionality for parsing URI
 * The URI should be prefixed with cng:
 *   then it is followed by a number of name-value pairs,
 *   separated by semicolons.
 *   This can be followed by ? with again a number of name-value pairs.
 *   The latter are the query elements.
 * Return value is false if parsing failed, true otherwise.
 *   If parsing succeeds, value will contain the zero-terminated
 *   value string if it was found, or a copy of the default_value
 *   if it was not found. The latter is allowed to be NULL.
 *   If it is not NULL, the string needs to be freed by the caller. */

#define URI_SCHEME_SEP  ":"
#define URI_QUERY_SEP   "?"
#define URI_ELEMENT_SEP ";"
#define URI_NAMEVAL_SEP "="
#define URI_PREFIX      NCRYPT_SCHEME URI_SCHEME_SEP

/* Note: looking up "cert" is possible. It is the value straight after
 *       the cert: URI scheme identifier */
/* Note: the maximum length for values is MAX_PATH, otherwise failure */
static bool
do_lookup(const char *uri, const char *name, bool is_query_element,
          const char *value_default, /* no default if set to NULL */
          char **value /* out */)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    unsigned int nof_found;
    char *uri_start = NULL;
    char *element_start = NULL;
    char *next_element_start = NULL;
    char *query_start = NULL;
    const char *value_found;
    char *result_start;

    /* URI has to start with the right prefix */
    if (strncmp(uri, URI_PREFIX, sizeof(URI_PREFIX) - 1) != 0) {
        S_NCRYPT_err(do_lookup, R_INCORRECT_USAGE,
                     "Looking up certificate with unknown URI prefix");
        goto done;
    }

    /* Make a copy to be used for parsing */
    uri_start = CMN_strdup(uri);
    if (uri_start == NULL) {
        S_NCRYPT_err(do_lookup, R_MALLOC_FAILED, "Duplicating URI");
        goto done;
    }

    /* Make the sheme identifier a name for a value */
    uri_start[sizeof(NCRYPT_SCHEME) - 1] = URI_NAMEVAL_SEP[0];
    /* Split off query part (if it is present) */
    strtok_s(uri_start, URI_QUERY_SEP, &query_start);
    /* Start at the query side or after the prefix */
    element_start = (is_query_element ? query_start : uri_start);

    /* element_start now points to the proper part, split it up
     * in name-value pairs */
    nof_found = 0;
    value_found = NULL;
    while ((element_start != NULL) && (*element_start != '\0')) {
        char *value_start;
        char *name_start;
        /* Split off name-value-pair*/
        strtok_s(element_start, URI_ELEMENT_SEP, &next_element_start);
        /* Split off name/value pair */
        value_start = NULL;
        name_start = strtok_s(element_start, URI_NAMEVAL_SEP, &value_start);
        if (strcmp(name_start, name) == 0) {
            value_found = value_start;
            nof_found++;
        }
        element_start = next_element_start;
    }
    if (nof_found > 1) {
        S_NCRYPT_err(do_lookup, R_INCORRECT_USAGE, "Looking up malformed URI");
        CMN_DBG_ERROR("Name \"%s\" found more than once in URI \"%s\"", name,
                      uri);
        goto done;
    }
    if (value_found == NULL) {
        value_found = value_default;
    }
    /* NULL is allowed for value_default, in which case this one is true */
    if (value_found == NULL) {
        result_start = NULL;
    } else {
        /* Value found has a size limitation */
        if (CMN_strnlen(value_found, MAX_PATH) == MAX_PATH) {
            S_NCRYPT_err(do_lookup, R_INCORRECT_USAGE,
                         "Looking up URI with path too long");
            CMN_DBG_ERROR("Value length for \"%s\" exceeds MAX_PATH (%d)", name,
                          MAX_PATH);
            goto done;
        }
        result_start = CMN_strdup(value_found);
        if (result_start == NULL) {
            S_NCRYPT_err(do_lookup, R_MALLOC_FAILED, "Duplicating result");
            goto done;
        }
    }

    *value = result_start;
    result = true;

done:
    CMN_free(uri_start);
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* One-liner functions in stead of macros... */
static bool
uri_is_empty(const char *p)
{
    return (p == NULL) || (*p == '\0');
}

static bool
uri_is_dirsep(const char *p)
{
    return (p != NULL) && ((*p == '\\') || (*p == '/'));
}

/* Look for the next dir separator, starting at 'start' until found or
 * nul-terminator encountered. In the latter case, a pointer to that
 * nul-terminator is returned. Returns NULL if start is NULL.
 * Otherwise, the result points to the next separator. */
static const char *
uri_find_next_dirsep(const char *start)
{
    const char *result = start;

    while (!uri_is_empty(result) && !uri_is_dirsep(result))
        result++;

    return result;
}

/* Return a newly allocated, nul-terminated string that contains the
 * characters that reside in between start and end. Returns NULL if
 * at least one of start and end is NULL. If a nul-terminator exists
 * in between start and end, then the copy will be made up to there.
 * Also, if the distance between start and end is less than one or
 * larger than MAX_PATH then NULL is returned.
 * The caller is required to CMN_free the result. */
static bool
uri_duplicate_between(const char *start, const char *end, char **str_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    char *str = NULL;
    const char *copy_start;
    ptrdiff_t diff;
    size_t len;

    CMN_DBG_PRECOND_NOT_NULL(start);
    CMN_DBG_PRECOND_NOT_NULL(end);
    CMN_DBG_PRECOND_NOT_NULL(str_out);
    CMN_DBG_PRECOND((end - start) > 0);
    CMN_DBG_PRECOND((end - start) < MAX_PATH);

    copy_start = start + 1;
    diff = end - copy_start;
    len = diff;
    if (len > 0) {
        errno_t retval;
        str = CMN_malloc(len + 1);
        if (str == NULL) {
            S_NCRYPT_err(uri_duplicate_between, R_MALLOC_FAILED, "Parsing URI");
            goto done;
        }
        retval = CMN_strncpy(str, copy_start, len);
        if (retval != 0) {
            S_NCRYPT_err(uri_duplicate_between, R_INTERNAL_ERROR,
                         "Copying URI");
            CMN_DBG_ERROR("CMN_strncpy failed with errno %d", retval);
            goto done;
        }
    }

    *str_out = str;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        CMN_free(str);
    }

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* ---------------- */
/* Public functions */
/* ---------------- */

void
ncrypt_uri_cracked_finalize(struct ncrypt_uri_cracked_st cracked_inout)
{
    CMN_free(cracked_inout.storage_kind_alias);
    CMN_free(cracked_inout.store_name);
    CMN_free(cracked_inout.object_id);
    CMN_free(cracked_inout.object_kind);
}

bool
ncrypt_uri_crack(const char *uri, struct ncrypt_uri_cracked_st *cracked_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;
    struct ncrypt_uri_cracked_st cracked = ncrypt_uri_cracked_INITIALIZER;
    char *cert_path = NULL;
    const char *sep1, *sep2, *sep3, *sep4;

    CMN_DBG_PRECOND_NOT_NULL(uri);
    CMN_DBG_PRECOND_NOT_NULL(cracked_out);

    /* Get the value for the path by looking up the value of "cert" */
    if (!do_lookup(uri, NCRYPT_SCHEME, false, NULL, &cert_path) ||
        uri_is_empty(cert_path))
        goto done;

    /* Look for optional querying field for object kind */
    if (!do_lookup(uri, NCRYPT_OBJECT_KIND_ELMT, true, NULL,
                   &cracked.object_kind))
        goto done;

    sep1 = uri_find_next_dirsep(cert_path);
    /* Actually the start of cert_path should be a separator */
    if (sep1 != cert_path) {
        S_NCRYPT_err(ncrypt_uri_crack, R_INCORRECT_USAGE, "Parsing URI");
        CMN_DBG_ERROR("Malformed certstore path \"%s\", expected form is "
                      "\"\\<storage_kind>\\<store_name>[\\object_name]\\\"",
                      cert_path);
        goto done;
    }

    sep2 = uri_find_next_dirsep(sep1 + 1);
    /* A separator should be found */
    if (uri_is_empty(sep2)) {
        S_NCRYPT_err(ncrypt_uri_crack, R_INCORRECT_USAGE, "Parsing URI");
        CMN_DBG_ERROR("Malformed certstore path \"%s\", expected form is "
                      "\"\\<storage_kind>\\<store_name>[\\object_name]\\\"",
                      cert_path);
        goto done;
    }

    /* And get those contents in between */
    if (!uri_duplicate_between(sep1, sep2, &cracked.storage_kind_alias))
        goto done;

    sep3 = uri_find_next_dirsep(sep2 + 1);
    /* sep3 either points to separator, or to end of string */
    if (!uri_duplicate_between(sep2, sep3, &cracked.store_name))
        goto done;

    /* Separator is not required to be found, but if it is, and it was
     * not the last character in the uncracked then... */
    if (!uri_is_empty(sep3)) {
        /* ... goto to next dirsep or end of string */
        sep4 = uri_find_next_dirsep(sep3 + 1);
        /* (actually, next dirsep should not be found) */
        if (!uri_is_empty(sep4)) {
            S_NCRYPT_err(ncrypt_uri_crack, R_INCORRECT_USAGE, "Parsing URI");
            CMN_DBG_ERROR("Malformed certstore path \"%s\", expected form is "
                          "\"\\<storage_kind>\\<store_name>[\\object_name]\\\"",
                          cert_path);
            goto done;
        }

        if (!uri_duplicate_between(sep3, sep4, &cracked.object_id))
            goto done;
    }

    *cracked_out = cracked;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        ncrypt_uri_cracked_finalize(cracked);
    }

    CMN_free(cert_path);

    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* suppress warning about _snprintf_s not getting inlined */
#pragma warning(push)
#pragma warning(disable : 4710)
bool
ncrypt_uri_uncrack(const char *storage_kind_alias, const char *store_name,
                   const char *object_id, char **uri_out)
{
    bool result = false;
    char *uri = NULL;
    char uncracked[MAX_PATH];

    CMN_DBG_PRECOND_NOT_NULL(storage_kind_alias);
    CMN_DBG_PRECOND_NOT_NULL(store_name);

    /* For now, the object_kind member is ignored. That may change */
    if (object_id == NULL) {
        if (_snprintf_s(uncracked, _countof(uncracked), _TRUNCATE, "%s/%s/%s",
                        URI_PREFIX, storage_kind_alias, store_name) == -1) {
            S_NCRYPT_err(ncrypt_uri_uncrack, R_INCORRECT_USAGE,
                         "Composing URI, path too long?");
            goto done;
        }
    } else {
        if (_snprintf_s(uncracked, _countof(uncracked), _TRUNCATE,
                        "%s/%s/%s/%s", URI_PREFIX, storage_kind_alias,
                        store_name, object_id) == -1) {
            S_NCRYPT_err(ncrypt_uri_uncrack, R_INCORRECT_USAGE,
                         "Composing URI, path too long?");
            goto done;
        }
    }

    uri = CMN_strdup(uncracked);
    if (uri == NULL) {
        S_NCRYPT_err(ncrypt_uri_uncrack, R_INCORRECT_USAGE,
                     "Duplicating result");
        goto done;
    }

    *uri_out = uri;
    result = true;

done:
    /* Roll back if needed */
    if (!result) {
        CMN_free(uri);
    }
    return result;
}
#pragma warning(pop)

/* TODO: make this work for UTF8 unicode strings */
bool
ncrypt_uri_lookup_value(
    const char *uri, const char *name,
    const char *value_default, /* no default if this is NULL */
    char **value_out)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;

    CMN_DBG_PRECOND_NOT_NULL(uri);
    CMN_DBG_PRECOND_NOT_NULL(name);
    CMN_DBG_PRECOND_NOT_NULL(value_out);

    if (!do_lookup(uri, name, false, value_default, value_out))
        goto done;

    result = true;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}

/* TODO: make this work for UTF8 unicode strings */
bool
ncrypt_uri_lookup_query_value(const char *uri, const char *name,
                              const char *value_default, char **value /* out */)
{
    CMN_DBG_TRACE_ENTER;

    bool result = false;

    CMN_DBG_PRECOND_NOT_NULL(uri);
    CMN_DBG_PRECOND_NOT_NULL(name);
    CMN_DBG_PRECOND_NOT_NULL(value);

    if (!do_lookup(uri, name, true, value_default, value))
        goto done;

    result = true;

done:
    CMN_DBG_TRACE_LEAVE;
    return result;
}
