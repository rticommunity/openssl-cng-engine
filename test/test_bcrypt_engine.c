/* This source file includes some functions in this header file */
#include "e_cng_test.h"

/* Includes required for implementation */
/* Ignore some warnings from OpenSSL code */
#pragma warning(push)
#pragma warning(disable: 4255) /* no function prototype given */
#pragma warning(disable: 4668) /* is not defined as a preprocessor macro */
#include <openssl/engine.h>
#pragma warning(pop)


static ENGINE *S_engine = NULL;

static int engine_set_trace_level(int level)
{
    int result = 0;
    char buf[32];

    _snprintf_s(buf, 32, _TRUNCATE, "%d", level);
    if (!ENGINE_ctrl_cmd_string(S_engine, "trace_level", buf, 0)) {
        CNG_TEST_LOG_ERROR("ENGINE_ctrl_cmd_string(trace_level) failed");
        goto done;
    }
    result = 1;
done:
    CNG_TEST_LOG_INFO("Leaving ENGINE set trace level test, result = %d", result);
    return result;
}

int 
e_cng_test_engine_trace_off(void)
{
    int result;

    CNG_TEST_LOG_INFO("Entering ENGINE switch off trace test");

    result = engine_set_trace_level(0);

    CNG_TEST_LOG_INFO("Leaving ENGINE switch off trace test, result = %d", result);
    return result;
}


int
e_cng_test_engine_trace_on(void)
{
    int result;

    CNG_TEST_LOG_INFO("Entering ENGINE switch on trace test");

    result = engine_set_trace_level(1);

    CNG_TEST_LOG_INFO("Leaving ENGINE switch on trace test, result = %d", result);
    return result;
}

int
e_cng_test_engine_trace_file(void)
{
    int result = 0;

    CNG_TEST_LOG_INFO("Entering ENGINE switch on trace file test");

    if (!ENGINE_ctrl_cmd_string(S_engine, "trace_file", "e_cng_test.log", 0)) {
        CNG_TEST_LOG_ERROR("ENGINE_ctrl_cmd_string(trace_file) failed");
        goto done;
    }
    result = 1;
done:

    CNG_TEST_LOG_INFO("Leaving ENGINE switch on trace file test, result = %d", result);
    return result;
}

int
e_cng_test_engine_load(void)
{
#define ENGINE_NAME "cng"
    int result = 0;
    const EVP_MD *sha256_md = NULL;

    CNG_TEST_LOG_INFO("Entering Load ENGINE test");

    S_engine = ENGINE_by_id("dynamic");
    if (NULL == S_engine) {
        CNG_TEST_LOG_ERROR("ENGINE_by_id(\"dynamic\") failed");
        goto done;
    }

    if (!ENGINE_ctrl_cmd_string(S_engine, "SO_PATH", ENGINE_NAME, 0)) {
        CNG_TEST_LOG_ERROR("ENGINE_ctrl_cmd_string(\"SO_PATH\", \""ENGINE_NAME"\") failed");
        goto done;
    }

    if (!ENGINE_ctrl_cmd_string(S_engine, "LOAD", NULL, 0)) {
        CNG_TEST_LOG_ERROR("ENGINE_ctrl_cmd_string(\"LOAD\") failed");
        goto done;
    }

    ENGINE_init(S_engine);

    if (!ENGINE_add(S_engine)) {
        CNG_TEST_LOG_ERROR("ENGINE_add(\""ENGINE_NAME"\") failed");
        goto done;
    }

    if (!ENGINE_set_default(S_engine, ENGINE_METHOD_ALL)) {
        CNG_TEST_LOG_ERROR("ENGINE_set_default(ENGINE_METHOD_ALL) failed");
        goto done;
    }

    sha256_md = ENGINE_get_digest(S_engine, NID_sha256);
    EVP_add_digest(sha256_md);

    /* Engine's structureal refcount has been upped by ENGINE_by_id, lower it */
    ENGINE_free(S_engine);

    result = 1;
#undef ENGINE_NAME

done:
    CNG_TEST_LOG_INFO("Leaving Load ENGINE test, result = %d", result);
    return result;
}

int
e_cng_test_engine_cleanup(void)
{
    if (NULL != S_engine) {
        ENGINE_unregister_ciphers(S_engine);
        ENGINE_unregister_digests(S_engine);
        ENGINE_unregister_EC(S_engine);
        ENGINE_unregister_RAND(S_engine);
        ENGINE_remove(S_engine);
        ENGINE_finish(S_engine);
        S_engine = NULL;
    }
    e_cng_test_log_cleanup();

    return 1;
}