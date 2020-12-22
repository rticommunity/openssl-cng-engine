/* This source file includes some functions in this header file */
#include "e_cng_test.h"

/* Includes required for implementation */
#include <string.h> /* for memcmp */
#include <openssl/evp.h>

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gmac_tag[] = {
    0x8f, 0xe1, 0x8b, 0xe5, 0x41, 0x05, 0xea, 0x30,
    0xa1, 0x80, 0x3f, 0x11, 0x93, 0xfc, 0x0f, 0x68
};

/* Slightly different tag should make verification fail */
static const unsigned char gmac_fail_tag[] = {
    0xf8, 0xe1, 0x8b, 0xe5, 0x41, 0x05, 0xea, 0x30,
    0xa1, 0x80, 0x3f, 0x11, 0x93, 0xfc, 0x0f, 0x68
};


int e_cng_test_aes_gmac_set_tag(void)
{
    int result = 0;

    EVP_CIPHER_CTX *ctx;
    int outlen, foutlen;
    unsigned char outtag[16];

    CNG_TEST_LOG_INFO("Entering AES GMAC tagging test");

    if (NULL == (ctx = EVP_CIPHER_CTX_new())) handleErrors();
    /* Set cipher type and mode */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, gcm_key, gcm_iv)) handleErrors();
    /* Specify entire plaintext as AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_pt, sizeof(gcm_pt));
    /* No encryption of plaintext in this example */
    if (1 != EVP_EncryptFinal_ex(ctx, NULL, &foutlen)) handleErrors();
    /* Get tag  */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outtag)) handleErrors();
#if 0
    /* Output original text */
    CNG_TEST_LOG_INFO("Plaintext:");
    CNG_TEST_DUMP(gcm_pt, sizeof(gcm_pt));
    /* Output expected tag */
    CNG_TEST_LOG_INFO("Expected Tag:");
    CNG_TEST_DUMP(gmac_tag, sizeof(gmac_tag));
    /* Output tag */
    CNG_TEST_LOG_INFO("Tag:");
    CNG_TEST_DUMP(outtag, 16);
#endif
    /* Check results */
    if (memcmp(outtag, gmac_tag, sizeof(gmac_tag))) {
        CNG_TEST_LOG_ERROR("GMAC tag does not match expected tag");
        goto done;
    }

    /* All checks succeeded */
    result = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    CNG_TEST_LOG_INFO("Leaving AES GMAC tagging test, result = %d", result);
    return result;
}

int e_cng_test_aes_gmac_verify_tag(void)
{
    int result = 0;

    EVP_CIPHER_CTX *ctx;
    int outlen, foutlen, tagver;

    CNG_TEST_LOG_INFO("Entering AES GMAC tag verification test");

    if (NULL == (ctx = EVP_CIPHER_CTX_new())) handleErrors();
    /* Select cipher */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, gcm_key, gcm_iv)) handleErrors();
    /* Set expected tag value. */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gmac_tag), (void *)gmac_tag)) handleErrors();
    /* End test Reinier */
    if (1 != EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_pt, sizeof(gcm_pt))) handleErrors();
    /* Finalise, if the result is not positive, something went wrong */
    tagver = EVP_DecryptFinal_ex(ctx, NULL, &foutlen);

    /* Execute checks */
    if (tagver <= 0) {
        CNG_TEST_LOG_ERROR("Tag verification failed");
        goto done;
    }
    result = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    CNG_TEST_LOG_INFO("Leaving AES GMAC tag verification test, result = %d", result);
    return result;
}

int e_cng_test_aes_gmac_verify_fail_tag(void)
{
    int result = 0;

    EVP_CIPHER_CTX *ctx;
    int outlen, foutlen, tagver;

    CNG_TEST_LOG_INFO("Entering AES GMAC wrong tag verification test");

    if (NULL == (ctx = EVP_CIPHER_CTX_new())) handleErrors();
    /* Select cipher */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, gcm_key, gcm_iv)) handleErrors();
    /* Set expected tag value. */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gmac_fail_tag), (void *)gmac_fail_tag)) handleErrors();
    /* Do the 'decrypting' */
    if (1 != EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_pt, sizeof(gcm_pt))) handleErrors();
    /* Finalise, if the result is not positive, something went wrong */
    tagver = EVP_DecryptFinal_ex(ctx, NULL, &foutlen);

    /* Execute checks */
    if (tagver > 0) {
        CNG_TEST_LOG_ERROR("Tag verification incorrectly succeeded");
        goto done;
    }
    result = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    CNG_TEST_LOG_INFO("Leaving AES GMAC wrong tag verification test, result = %d", result);
    return result;
}
