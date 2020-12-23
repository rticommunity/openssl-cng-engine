// modified from openssl's crypto/sha/sha256t.c
/* ====================================================================
* Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
* ====================================================================
*/

#include "test_bcrypt.h"
#include "test_bcrypt_ossl.h"

#include <openssl/sha.h>

// ----------------------------------------------------------------------------
//
// HMAC value-parameterized tests
//
// ----------------------------------------------------------------------------

// Parameters for this type of test
struct ShaParams {
    int nid;
    const char *msg_given;
    const char *dgst_expected;
};

static const ShaParams sha_params[] = {
{
    // nid
    NID_sha1,
    // msg_given
    "616263",
    // dgst_expected
    "a9993e364706816aba3e25717850c26c9cd0d89d"
},
{
    // nid
    NID_sha1,
    // msg_given
    "6162636462636465636465666465666765666768666768696768696A68696A6B",
    // dgst_expected
    "37bc5221ade3bc09cad15e4784f3c7051454b1b3"
},
{
    // nid
    NID_sha256,
    // msg_given
    "616263",
    // dgst_expected
    "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
},
{
    // nid
    NID_sha256,
    // msg_given
    "6162636462636465636465666465666765666768666768696768696A68696A6B"
    "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
    // dgst_expected
    "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
},
{
    // nid
    NID_sha384,
    // msg_given
    "616263",
    // dgst_expected
    "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED"
    "8086072BA1E7CC2358BAECA134C825A7"
},
{
    // nid
    NID_sha384,
    // msg_given
    "61626364656667686263646566676869636465666768696A6465666768696A6B"
    "65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
    "696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
    "6D6E6F70717273746E6F707172737475",
    // dgst_expected
    "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712"
    "FCC7C71A557E2DB966C3E9FA91746039"
},
{
    // nid
    NID_sha512,
    // msg_given
    "616263",
    // dgst_expected
    "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
    "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
},
{
    // nid
    NID_sha512,
    // msg_given
    "61626364656667686263646566676869636465666768696A6465666768696A6B"
    "65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
    "696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
    "6D6E6F70717273746E6F707172737475",
    // dgst_expected
    "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
    "501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"
}
// More to follow...
};


class ShaTest :
    public bcrypt_testing::Test,
    public testing::WithParamInterface<ShaParams>
{
public:
    ShaTest()
    {
        ShaParams params = GetParam();

        // Convert parameters into their number/bytes equivalents
        bcrypt_testing::Bytes msg_given =
            bcrypt_testing::number_from_string(params.msg_given).value();
        bcrypt_testing::Number dgst_expected =
            bcrypt_testing::number_from_string(params.dgst_expected).value();

        // Initialize members from them
        md_ = EVP_get_digestbynid(params.nid);
        msg_given_ = msg_given;
        dgst_expected_ = dgst_expected;
    }

    const EVP_MD *md_;
    bcrypt_testing::Bytes msg_given_;
    bcrypt_testing::Number dgst_expected_;
};

TEST_P(ShaTest, ShaSimple)
{
    OSSL_ASSERT_NE(nullptr, md_);

    std::vector<unsigned char> dgst(dgst_expected_.size());
    unsigned int dgst_len = (unsigned int)dgst.size();
    EXPECT_EQ(1, EVP_Digest(msg_given_.data(), msg_given_.size(),
        &dgst[0], &dgst_len, md_, NULL));
    EXPECT_EQ(dgst, dgst_expected_);
    EXPECT_EQ(dgst_len, dgst_expected_.size());
}

TEST_P(ShaTest, ShaSteps)
{
    OSSL_ASSERT_NE(nullptr, md_);

    bcrypt_testing::unique_EVP_MD_CTX md_ctx(EVP_MD_CTX_new());
    OSSL_ASSERT_TRUE(md_ctx);
    OSSL_ASSERT_EQ(1, EVP_DigestInit(md_ctx.get(), md_));
    OSSL_ASSERT_EQ(1, EVP_DigestUpdate(md_ctx.get(), msg_given_.data(), msg_given_.size()));

    std::vector<unsigned char> dgst(dgst_expected_.size());
    unsigned int dgst_len = (unsigned int)dgst.size();
    OSSL_ASSERT_EQ(1, EVP_DigestFinal(md_ctx.get(), &dgst[0], &dgst_len));
    EXPECT_EQ(dgst, dgst_expected_);
    EXPECT_EQ(dgst_len, dgst_expected_.size());
}

INSTANTIATE_TEST_CASE_P(ShaTests, ShaTest, testing::ValuesIn(sha_params));
