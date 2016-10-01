/*\
 * This is the central part of SHA1. The following code handles one block of
 * the input. OP is a target-dependent macro that executes one step of SHA1. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D, E) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of SHA1. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#include "sha1_filter.h"

#include "keyspace.h"

#ifndef SHA1_INIT
#define SHA1_INIT(A, B, C, D, E) do { \
    A = SET1(0x67452301); \
    B = SET1(0xEFCDAB89); \
    C = SET1(0x98BADCFE); \
    D = SET1(0x10325476); \
    E = SET1(0xC3D2E1F0); \
} while (0)
#endif

#ifndef SHA1_F
#define SHA1_F(B,C,D) OR(AND(B, C), ANDNOT(B, D))
#endif

#ifndef SHA1_G
#define SHA1_G(B,C,D) XOR(B, XOR(C, D))
#endif

#ifndef SHA1_H
#define SHA1_H(B,C,D) OR(AND(B, C), OR(AND(B, D), AND(C, D)))
#endif

#ifndef SHA1_OP
#define SHA1_OP(f,A,B,C,D,K,W) do { \
    WORD tmp = ADD(ROL(A,5), ADD(f(B,C,D), ADD(E, ADD(W, SET1(K))))); \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#endif

#ifndef SHA1_BLOCK
#define SHA1_BLOCK(BLOCK, A,B,C,D,E) do { \
    WORD previous_A = A; \
    WORD previous_B = B; \
    WORD previous_C = C; \
    WORD previous_D = D; \
    WORD previous_E = E; \
    \
    /* run SHA-1 steps and update W on the fly */ \
    WORD x = BSWAP(X[0]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,x); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[1]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[2]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[3]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[4]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[5]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[6]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[7]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[8]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[9]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[10]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[11]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[12]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[13]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[14]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[15]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[16] ^ ROL(x,1)); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[17]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[18]); \
    SHA1_OP(SHA1_F,A,B,C,D,0X5A827999,W[19] ^ ROL(x,2)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[20]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[21]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[22] ^ ROL(x,3)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[23]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[24] ^ ROL(x,2)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[25] ^ ROL(x,4)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[26]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[27]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[28] ^ ROL(x,5)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[29]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[30] ^ ROL(x,2) ^ ROL(x,4)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[31] ^ ROL(x,6)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[32] ^ ROL(x,2) ^ ROL(x,3)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[33]); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[34] ^ ROL(x,7)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[35] ^ ROL(x,4)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[36] ^ ROL(x,4) ^ ROL(x,6)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[37] ^ ROL(x,8)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[38] ^ ROL(x,4)); \
    SHA1_OP(SHA1_G,A,B,C,D,0X6ED9EBA1,W[39]); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[40] ^ ROL(x,9) ^ ROL(x,4)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[41]); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[42] ^ ROL(x,8) ^ ROL(x,6)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[43] ^ ROL(x,10)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[44] ^ ROL(x,3) ^ ROL(x,6) ^ ROL(x,7)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[45]); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[46] ^ ROL(x,11) ^ ROL(x,4)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[47] ^ ROL(x,8) ^ ROL(x,4)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[48] ^ ROL(x,8) ^ ROL(x,10) ^ ROL(x,3) ^ ROL(x,4) ^ ROL(x,5)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[49] ^ ROL(x,12)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[50] ^ ROL(x,8)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[51] ^ ROL(x,4) ^ ROL(x,6)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[52] ^ ROL(x,8) ^ ROL(x,4) ^ ROL(x,13)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[53]); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[54] ^ ROL(x,10) ^ ROL(x,12) ^ ROL(x,7)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[55] ^ ROL(x,14)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[56] ^ ROL(x,4) ^ ROL(x,6) ^ ROL(x,7) ^ ROL(x,10) ^ ROL(x,11)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[57] ^ ROL(x,8)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[58] ^ ROL(x,8) ^ ROL(x,4) ^ ROL(x,15)); \
    SHA1_OP(SHA1_H,A,B,C,D,0X8F1BBCDC,W[59] ^ ROL(x,8) ^ ROL(x,12)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[60] ^ ROL(x,4) ^ ROL(x,7) ^ ROL(x,8) ^ ROL(x,12) ^ ROL(x,14)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[61] ^ ROL(x,16)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[62] ^ ROL(x,4) ^ ROL(x,6) ^ ROL(x,8) ^ ROL(x,12)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[63] ^ ROL(x,8)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[64] ^ ROL(x,4) ^ ROL(x,6) ^ ROL(x,7) ^ ROL(x,8) ^ ROL(x,12) ^ ROL(x,17)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[65]); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[66] ^ ROL(x,16) ^ ROL(x,14)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[67] ^ ROL(x,8) ^ ROL(x,18)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[68] ^ ROL(x,11) ^ ROL(x,14) ^ ROL(x,15)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[69]); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[70] ^ ROL(x,12) ^ ROL(x,19)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[71] ^ ROL(x,16) ^ ROL(x,12)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[72] ^ ROL(x,5) ^ ROL(x,11) ^ ROL(x,12) ^ ROL(x,13) ^ ROL(x,16) ^ ROL(x,18)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[73] ^ ROL(x,20)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[74] ^ ROL(x,8) ^ ROL(x,16)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[75] ^ ROL(x,6) ^ ROL(x,12) ^ ROL(x,14)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[76] ^ ROL(x,7) ^ ROL(x,8) ^ ROL(x,12) ^ ROL(x,16) ^ ROL(x,21)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[77]); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[78] ^ ROL(x,7) ^ ROL(x,8) ^ ROL(x,15) ^ ROL(x,18) ^ ROL(x,20)); \
    SHA1_OP(SHA1_G,A,B,C,D,0XCA62C1D6,W[79] ^ ROL(x,8) ^ ROL(x,22)); \
    \
    A = ADD(A, previous_A); \
    B = ADD(B, previous_B); \
    C = ADD(C, previous_C); \
    D = ADD(D, previous_D); \
    E = ADD(E, previous_E); \
} while (0)
#endif

extern int do_generate_passwords;

#define APPEND(PREFIX, SUFFIX) PREFIX##SUFFIX
// append together the *values* of the macros, rather than their names
#define APPEND_VALUE(PREFIX, SUFFIX) APPEND(PREFIX, SUFFIX)

// sha1_filterone_*
__attribute__((target(TARGET_ID)))
#define FUNCTION_NAME APPEND_VALUE(sha1_filterone_, TARGET_SUFFIX)
size_t FUNCTION_NAME(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count) {
#undef FUNCTION_NAME
    size_t stride = sizeof(WORD) / 4;
    size_t n_iterations = (count + stride - 1) / stride;  /* ceil(count / stride) */

    /* prepare block */
    uint8_t block[64*stride];
    const char* ptrs[64*stride];
    sha1_pad(block, length, stride);
    set_keys(block, ptrs, length, stride, start, n_iterations);

    /* compute W assuming X[0] = 0 */
    WORD W[80];
    WORD* X = (WORD*) block;
    W[0] = SET1(0);
    for (int t = 1; t < 16; t += 1) {
        W[t] = BSWAP(X[t]);
    }
    for (int t = 16; t < 80; t += 1) {
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    size_t n_candidates = 0;
    for (size_t i = 0; i < n_iterations; i += 1) {
        WORD A, B, C, D, E;
        SHA1_INIT(A, B, C, D, E);
        SHA1_BLOCK(block, A,B,C,D,E);

        if (ANY_EQ(A, filter)) {
            uint32_t* hashes = (uint32_t*) &A;
            for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
                if (hashes[interleaf] != filter) {
                    continue;
                }
                candidates[n_candidates] = start + interleaf*n_iterations + i;
                n_candidates += 1;
                if (n_candidates >= size) {
                    return n_candidates;
                }
            }
        }

        if (do_generate_passwords) {
            next_keys(block, ptrs, length, stride);
        }
    }

    return n_candidates;
}
