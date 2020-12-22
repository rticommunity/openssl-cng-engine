/* Modified from openssl's crypto/rand/randtest.c */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
* All rights reserved.
*
* This package is an SSL implementation written
* by Eric Young (eay@cryptsoft.com).
* The implementation was written so as to conform with Netscapes SSL.
*
* This library is free for commercial and non-commercial use as long as
* the following conditions are aheared to.  The following conditions
* apply to all code found in this distribution, be it the RC4, RSA,
* lhash, DES, etc., code; not just the SSL code.  The SSL documentation
* included with this distribution is covered by the same copyright terms
* except that the holder is Tim Hudson (tjh@cryptsoft.com).
*
* Copyright remains Eric Young's, and as such any Copyright notices in
* the code are not to be removed.
* If this package is used in a product, Eric Young should be given attribution
* as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or
* in documentation (online or textual) provided with the package.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*    "This product includes cryptographic software written by
*     Eric Young (eay@cryptsoft.com)"
*    The word 'cryptographic' can be left out if the rouines from the library
*    being used are not cryptographic related :-).
* 4. If you include any Windows specific code (or a derivative thereof) from
*    the apps directory (application code) you must include an acknowledgement:
*    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
*
* THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
* The licence and distribution terms for any publically available version or
* derivative of this code cannot be changed.  i.e. this code cannot simply be
* copied and put under another distribution licence
* [including the GNU Public Licence.]
*/

#include "test_bcrypt.h"
#include "test_bcrypt_ossl.h"

#include <openssl/rand.h>

/* some FIPS 140-1 random number test */
/* some simple tests */
#if 0
class RandTest : public bcrypt_testing::Test
{
    // Nothing, this class is just to make sure the bcrypt testing
    //   baseclass gets invoked.
};

TEST_F(RandTest, SimpleRand)
#else
TEST(RandTest, SimpleRand)
#endif
{
    unsigned char buf[2500];
    int i, j, k, s, sign, nsign, err = 0;
    unsigned long n1;
    unsigned long n2[16];
    unsigned long runs[2][34];
    /*double d; */
    long d;

    OSSL_EXPECT_LE(0, i = RAND_bytes(buf, 2500));

    n1 = 0;
    for (i = 0; i<16; i++) n2[i] = 0;
    for (i = 0; i<34; i++) runs[0][i] = runs[1][i] = 0;

    /* test 1 and 2 */
    sign = 0;
    nsign = 0;
    for (i = 0; i<2500; i++)
    {
        j = buf[i];

        n2[j & 0x0f]++;
        n2[(j >> 4) & 0x0f]++;

        for (k = 0; k<8; k++)
        {
            s = (j & 0x01);
            if (s == sign)
                nsign++;
            else
            {
                if (nsign > 34) nsign = 34;
                if (nsign != 0)
                {
                    runs[sign][nsign - 1]++;
                    if (nsign > 6)
                        runs[sign][5]++;
                }
                sign = s;
                nsign = 1;
            }

            if (s) n1++;
            j >>= 1;
        }
    }
    if (nsign > 34) nsign = 34;
    if (nsign != 0) runs[sign][nsign - 1]++;

    /* test 1 */
    EXPECT_TRUE((9654 < n1) && (n1 < 10346));

    /* test 2 */
#ifdef undef
    d = 0;
    for (i = 0; i<16; i++)
        d += n2[i] * n2[i];
    d = d*16.0 / 5000.0 - 5000.0;
    EXPECT_TRUE((1.03 < d) && (d < 57.4));
#endif
    d = 0;
    for (i = 0; i<16; i++)
        d += n2[i] * n2[i];
    d = (d * 8) / 25 - 500000;
    EXPECT_TRUE((103 < d) && (d < 5740));

    /* test 3 */
    for (i = 0; i<2; i++)
    {
        EXPECT_TRUE((2267 < runs[i][0]) && (runs[i][0] < 2733));
        EXPECT_TRUE((1079 < runs[i][1]) && (runs[i][1] < 1421));
        EXPECT_TRUE((502 < runs[i][2]) && (runs[i][2] < 748));
        EXPECT_TRUE((223 < runs[i][3]) && (runs[i][3] < 402));
        EXPECT_TRUE((90 < runs[i][4]) && (runs[i][4] < 223));
        EXPECT_TRUE((90 < runs[i][5]) && (runs[i][5] < 223));
    }

    /* test 4 */
    EXPECT_EQ(0, runs[0][33]);
    EXPECT_EQ(0, runs[1][33]);
}
