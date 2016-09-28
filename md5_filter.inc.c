/*\
 * This is the central part of MD5. The following code handles one block of the
 * input. OP is a target-dependent macro that executes one step of MD5. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of MD5. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#include "md5_filter.h"

#include "keyspace.h"

static const uint32_t T[] = {
    0,

    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

#ifndef MD5_INIT
#define MD5_INIT(A, B, C, D) do { \
    A = SET1(0x67452301); \
    B = SET1(0xEFCDAB89); \
    C = SET1(0x98BADCFE); \
    D = SET1(0x10325476); \
} while (0)
#endif

#ifndef MD5_F
#define MD5_F(X,Y,Z) OR(AND(X, Y), ANDNOT(X, Z))
#endif

#ifndef MD5_G
#define MD5_G(X,Y,Z) OR(AND(X, Z), ANDNOT(Z, Y))
#endif

#ifndef MD5_H
#define MD5_H(X,Y,Z) XOR(XOR(X, Y),Z)
#endif

#ifndef MD5_OP
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    WORD tmp = ADD(a, ADD(f(b,c,d), ADD(X[k], SET1(T[i])))); \
    a = ADD(b, ROL(tmp, s)); \
} while (0)
#endif

// hackish, but I really like the grid layout
#define MD5_OP_F(A,B,C,D,K,S,I) MD5_OP(MD5_F,A,B,C,D,K,S,I)
#define MD5_OP_G(A,B,C,D,K,S,I) MD5_OP(MD5_G,A,B,C,D,K,S,I)
#define MD5_OP_H(A,B,C,D,K,S,I) MD5_OP(MD5_H,A,B,C,D,K,S,I)

#ifndef MD5_BLOCK
#define MD5_BLOCK(BLOCK, A,B,C,D) do { \
    WORD* X = (WORD*) block; \
    \
    MD5_OP_F(A,B,C,D, 0, 7, 1); MD5_OP_F(D,A,B,C, 1,12, 2); MD5_OP_F(C,D,A,B, 2,17, 3); MD5_OP_F(B,C,D,A, 3,22, 4); \
    MD5_OP_F(A,B,C,D, 4, 7, 5); MD5_OP_F(D,A,B,C, 5,12, 6); MD5_OP_F(C,D,A,B, 6,17, 7); MD5_OP_F(B,C,D,A, 7,22, 8); \
    MD5_OP_F(A,B,C,D, 8, 7, 9); MD5_OP_F(D,A,B,C, 9,12,10); MD5_OP_F(C,D,A,B,10,17,11); MD5_OP_F(B,C,D,A,11,22,12); \
    MD5_OP_F(A,B,C,D,12, 7,13); MD5_OP_F(D,A,B,C,13,12,14); MD5_OP_F(C,D,A,B,14,17,15); MD5_OP_F(B,C,D,A,15,22,16); \
    \
    MD5_OP_G(A,B,C,D, 1, 5,17); MD5_OP_G(D,A,B,C, 6, 9,18); MD5_OP_G(C,D,A,B,11,14,19); MD5_OP_G(B,C,D,A, 0,20,20); \
    MD5_OP_G(A,B,C,D, 5, 5,21); MD5_OP_G(D,A,B,C,10, 9,22); MD5_OP_G(C,D,A,B,15,14,23); MD5_OP_G(B,C,D,A, 4,20,24); \
    MD5_OP_G(A,B,C,D, 9, 5,25); MD5_OP_G(D,A,B,C,14, 9,26); MD5_OP_G(C,D,A,B, 3,14,27); MD5_OP_G(B,C,D,A, 8,20,28); \
    MD5_OP_G(A,B,C,D,13, 5,29); MD5_OP_G(D,A,B,C, 2, 9,30); MD5_OP_G(C,D,A,B, 7,14,31); MD5_OP_G(B,C,D,A,12,20,32); \
    \
    MD5_OP_H(A,B,C,D, 5, 4,33); MD5_OP_H(D,A,B,C, 8,11,34); MD5_OP_H(C,D,A,B,11,16,35); MD5_OP_H(B,C,D,A,14,23,36); \
    MD5_OP_H(A,B,C,D, 1, 4,37); MD5_OP_H(D,A,B,C, 4,11,38); MD5_OP_H(C,D,A,B, 7,16,39); MD5_OP_H(B,C,D,A,10,23,40); \
    MD5_OP_H(A,B,C,D,13, 4,41); MD5_OP_H(D,A,B,C, 0,11,42); MD5_OP_H(C,D,A,B, 3,16,43); MD5_OP_H(B,C,D,A, 6,23,44); \
    MD5_OP_H(A,B,C,D, 9, 4,45); MD5_OP_H(D,A,B,C,12,11,46); \
} while (0)
#endif

extern int do_generate_passwords;

#define APPEND(PREFIX, SUFFIX) PREFIX##SUFFIX
// append together the *values* of the macros, rather than their names
#define APPEND_VALUE(PREFIX, SUFFIX) APPEND(PREFIX, SUFFIX)

// md5_filterone_*
__attribute__((target(TARGET_ID)))
#define FUNCTION_NAME APPEND_VALUE(md5_filterone_, TARGET_SUFFIX)
size_t FUNCTION_NAME(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count) {
#undef FUNCTION_NAME
    size_t stride = sizeof(WORD) / 4;
    size_t n_iterations = (count + stride - 1) / stride;  /* ceil(count / stride) */

    /* prepare block */
    uint8_t block[64*stride];
    const char* ptrs[64*stride];
    md5_pad(block, length, stride);
    set_keys(block, ptrs, length, stride, start, n_iterations);

    size_t n_candidates = 0;
    for (size_t i = 0; i < n_iterations; i += 1) {
        WORD A, B, C, D;
        MD5_INIT(A, B, C, D);
        MD5_BLOCK(block, A,B,C,D);

        if (ANY_EQ(D, filter)) {
            uint32_t* hashes = (uint32_t*) &D;
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
