#include "md5_simd.h"

#include <string.h>

#include "simd.h"
#include "simd_util.h"

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

#define MD5_BLOCK( \
        X, /* WORD*: the block to be processed */ \
        A,B,C,D, /* WORD: the 128 bit state of MD5 */ \
        F,G,H,I, /* the four MD5 auxiliary functions */ \
        OP, /* execute a single step of MD5, update the state */ \
        ADD, /* add WORD to another WORD */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    __typeof__(A) previous_A = A; \
    __typeof__(A) previous_B = B; \
    __typeof__(A) previous_C = C; \
    __typeof__(A) previous_D = D; \
    \
    OP(F,A,B,C,D,X, 0, 7, 1); OP(F,D,A,B,C,X, 1,12, 2); OP(F,C,D,A,B,X, 2,17, 3); OP(F,B,C,D,A,X, 3,22, 4); \
    OP(F,A,B,C,D,X, 4, 7, 5); OP(F,D,A,B,C,X, 5,12, 6); OP(F,C,D,A,B,X, 6,17, 7); OP(F,B,C,D,A,X, 7,22, 8); \
    OP(F,A,B,C,D,X, 8, 7, 9); OP(F,D,A,B,C,X, 9,12,10); OP(F,C,D,A,B,X,10,17,11); OP(F,B,C,D,A,X,11,22,12); \
    OP(F,A,B,C,D,X,12, 7,13); OP(F,D,A,B,C,X,13,12,14); OP(F,C,D,A,B,X,14,17,15); OP(F,B,C,D,A,X,15,22,16); \
    \
    OP(G,A,B,C,D,X, 1, 5,17); OP(G,D,A,B,C,X, 6, 9,18); OP(G,C,D,A,B,X,11,14,19); OP(G,B,C,D,A,X, 0,20,20); \
    OP(G,A,B,C,D,X, 5, 5,21); OP(G,D,A,B,C,X,10, 9,22); OP(G,C,D,A,B,X,15,14,23); OP(G,B,C,D,A,X, 4,20,24); \
    OP(G,A,B,C,D,X, 9, 5,25); OP(G,D,A,B,C,X,14, 9,26); OP(G,C,D,A,B,X, 3,14,27); OP(G,B,C,D,A,X, 8,20,28); \
    OP(G,A,B,C,D,X,13, 5,29); OP(G,D,A,B,C,X, 2, 9,30); OP(G,C,D,A,B,X, 7,14,31); OP(G,B,C,D,A,X,12,20,32); \
    \
    OP(H,A,B,C,D,X, 5, 4,33); OP(H,D,A,B,C,X, 8,11,34); OP(H,C,D,A,B,X,11,16,35); OP(H,B,C,D,A,X,14,23,36); \
    OP(H,A,B,C,D,X, 1, 4,37); OP(H,D,A,B,C,X, 4,11,38); OP(H,C,D,A,B,X, 7,16,39); OP(H,B,C,D,A,X,10,23,40); \
    OP(H,A,B,C,D,X,13, 4,41); OP(H,D,A,B,C,X, 0,11,42); OP(H,C,D,A,B,X, 3,16,43); OP(H,B,C,D,A,X, 6,23,44); \
    OP(H,A,B,C,D,X, 9, 4,45); OP(H,D,A,B,C,X,12,11,46); OP(H,C,D,A,B,X,15,16,47); OP(H,B,C,D,A,X, 2,23,48); \
    \
    /* first look at the "else" block to see the full version */ \
    if (LENGTH <= 4) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since X[12], X[ 3], X[10] and X[ 1] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        OP(I,A,B,C,D,X, 0, 6,49); \
    } else if (LENGTH <= 8) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        OP(I,A,B,C,D,X, 0, 6,49); OP(I,D,A,B,C,X, 7,10,50); OP(I,C,D,A,B,X,14,15,51); OP(I,B,C,D,A,X, 5,21,52); \
        OP(I,A,B,C,D,X,12, 6,53); \
    } else if (LENGTH < 56) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since we only guarantee the computation of A, we can skip the last three steps */ \
        OP(I,A,B,C,D,X, 0, 6,49); OP(I,D,A,B,C,X, 7,10,50); OP(I,C,D,A,B,X,14,15,51); OP(I,B,C,D,A,X, 5,21,52); \
        OP(I,A,B,C,D,X,12, 6,53); OP(I,D,A,B,C,X, 3,10,54); OP(I,C,D,A,B,X,10,15,55); OP(I,B,C,D,A,X, 1,21,56); \
        OP(I,A,B,C,D,X, 8, 6,57); OP(I,D,A,B,C,X,15,10,58); OP(I,C,D,A,B,X, 6,15,59); OP(I,B,C,D,A,X,13,21,60); \
        OP(I,A,B,C,D,X, 4, 6,61); \
    } else { \
        OP(I,A,B,C,D,X, 0, 6,49); OP(I,D,A,B,C,X, 7,10,50); OP(I,C,D,A,B,X,14,15,51); OP(I,B,C,D,A,X, 5,21,52); \
        OP(I,A,B,C,D,X,12, 6,53); OP(I,D,A,B,C,X, 3,10,54); OP(I,C,D,A,B,X,10,15,55); OP(I,B,C,D,A,X, 1,21,56); \
        OP(I,A,B,C,D,X, 8, 6,57); OP(I,D,A,B,C,X,15,10,58); OP(I,C,D,A,B,X, 6,15,59); OP(I,B,C,D,A,X,13,21,60); \
        OP(I,A,B,C,D,X, 4, 6,61); OP(I,D,A,B,C,X,11,10,62); OP(I,C,D,A,B,X, 2,15,63); OP(I,B,C,D,A,X, 9,21,64); \
        \
        A = ADD(A, previous_A); \
        B = ADD(B, previous_B); \
        C = ADD(C, previous_C); \
        D = ADD(D, previous_D); \
    } \
} while (0)

/*\
 * Below are the target-dependent implementations. An implementation needs:
 *
 * * INIT to reset the state
 * * auxiliary functions F,G,H,I from the MD5 specification
 * * OP to execute a single STEP of MD5 (expecting one of F,G,H,I)
 * * ADD which just adds two values (for the end of the update)
\*/

// x86: no CPU extension, no interleaving (e.g. interleaving of 1)
#define X86_INIT(A, B, C, D) do { \
    A = 0x67452301; \
    B = 0xEFCDAB89; \
    C = 0x98BADCFE; \
    D = 0x10325476; \
} while (0)
#define X86_F(X,Y,Z) ((((Y) ^ (Z)) & (X)) ^ (Z))
#define X86_G(X,Y,Z) ((((X) ^ (Y)) & (Z)) ^ (Y))
#define X86_H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define X86_I(X,Y,Z) ((Y) ^ ((X) | ~(Z)))
#define X86_OP(f,a,b,c,d,X,k,s,i) do { \
    uint32_t tmp = a + f(b,c,d) + X[k] + T[i]; \
    a = b + X86_ROT(tmp, s); \
} while (0)
#define X86_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD5_BLOCK(((uint32_t*)BLOCK), \
              A,B,C,D, \
              X86_F, X86_G, X86_H, X86_I, \
              X86_OP, X86_ADD, LENGTH)

// MMX
#define MMX_INIT(A, B, C, D) do { \
    A = _mm_set1_pi32((int) 0x67452301); \
    B = _mm_set1_pi32((int) 0xEFCDAB89); \
    C = _mm_set1_pi32((int) 0x98BADCFE); \
    D = _mm_set1_pi32((int) 0x10325476); \
} while (0)
#define MMX_F(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_andnot_si64(X, Z))
#define MMX_G(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Z), _mm_andnot_si64(Z, Y))
#define MMX_H(X,Y,Z) _mm_xor_si64(_mm_xor_si64(X, Y),Z)
#define MMX_I(X,Y,Z) _mm_xor_si64(Y, _mm_or_si64(X, ~Z))
#define MMX_OP(f,a,b,c,d,X,k,s,i) do { \
    __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(f(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int) T[i])))); \
    a = _mm_add_pi32(b, MMX_ROT(tmp, s)); \
} while (0)
#define MMX_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD5_BLOCK(((__m64*)BLOCK), \
              A,B,C,D, \
              MMX_F, MMX_G, MMX_H, MMX_I, \
              MMX_OP, MMX_ADD, LENGTH)

// SSE2
#define SSE2_INIT(A, B, C, D) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
} while (0)
#define SSE2_F(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_andnot_si128(X, Z))
#define SSE2_G(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Z), _mm_andnot_si128(Z, Y))
#define SSE2_H(X,Y,Z) _mm_xor_si128(_mm_xor_si128(X, Y),Z)
#define SSE2_I(X,Y,Z) _mm_xor_si128(Y, _mm_or_si128(X, ~Z))
#define SSE2_OP(f,a,b,c,d,X,k,s,i) do { \
    __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(f(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int) T[i])))); \
    a = _mm_add_epi32(b, SSE2_ROT(tmp, s)); \
} while (0)
#define SSE2_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD5_BLOCK(((__m128i*)BLOCK), \
              A,B,C,D, \
              SSE2_F, SSE2_G, SSE2_H, SSE2_I, \
              SSE2_OP, SSE2_ADD, LENGTH)

// AVX2
#define AVX2_INIT(A, B, C, D) do { \
    A = _mm256_set1_epi32((int) 0x67452301); \
    B = _mm256_set1_epi32((int) 0xEFCDAB89); \
    C = _mm256_set1_epi32((int) 0x98BADCFE); \
    D = _mm256_set1_epi32((int) 0x10325476); \
} while (0)
#define AVX2_F(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_andnot_si256(X, Z))
#define AVX2_G(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Z), _mm256_andnot_si256(Z, Y))
#define AVX2_H(X,Y,Z) _mm256_xor_si256(_mm256_xor_si256(X, Y),Z)
#define AVX2_I(X,Y,Z) _mm256_xor_si256(Y, _mm256_or_si256(X, ~Z))
#define AVX2_OP(f,a,b,c,d,X,k,s,i) do { \
    __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(f(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int) T[i])))); \
    a = _mm256_add_epi32(b, AVX2_ROT(tmp, s)); \
} while (0)
#define AVX2_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD5_BLOCK(((__m256i*)BLOCK), \
              A,B,C,D, \
              AVX2_F, AVX2_G, AVX2_H, AVX2_I, \
              AVX2_OP, AVX2_ADD, LENGTH)

// AVX-512
#define AVX512_INIT(A, B, C, D) do { \
    A = _mm512_set1_epi32((int) 0x67452301); \
    B = _mm512_set1_epi32((int) 0xEFCDAB89); \
    C = _mm512_set1_epi32((int) 0x98BADCFE); \
    D = _mm512_set1_epi32((int) 0x10325476); \
} while (0)
#define AVX512_F(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_andnot_si512(X, Z))
#define AVX512_G(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Z), _mm512_andnot_si512(Z, Y))
#define AVX512_H(X,Y,Z) _mm512_xor_si512(_mm512_xor_si512(X, Y),Z)
#define AVX512_I(X,Y,Z) _mm512_xor_si512(Y, _mm512_or_si512(X, ~Z))
#define AVX512_OP(f,a,b,c,d,X,k,s,i) do { \
    __m512i tmp = _mm512_add_epi32(a, _mm512_add_epi32(f(b,c,d), _mm512_add_epi32(X[k], _mm512_set1_epi32((int) T[i])))); \
    a = _mm512_add_epi32(b, AVX512_ROT(tmp, s)); \
} while (0)
#define AVX512_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD5_BLOCK(((__m512i*)BLOCK), \
              A,B,C,D, \
              AVX512_F, AVX512_G, AVX512_H, AVX512_I, \
              AVX512_OP, AVX512_ADD, LENGTH);

void md5_pad(uint8_t* block, size_t length, size_t stride) {
    memset(block, 0, 64 * stride);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t offset;

        // data termination
        offset = interleaved_offset(length, stride, interleaf);
        block[offset] = 0x80;

        // length in bits
        offset = interleaved_offset(56, stride, interleaf);
        *(uint32_t*) (block + offset) = (uint32_t) (length * 8);
    }
}

// generate architecture-dependent functions
#define GENERATE(TARGET, LOWERCASE, UPPERCASE) \
    __attribute__((target(TARGET))) \
    void md5_oneblock_##LOWERCASE(uint8_t* digest, const uint8_t* block) { \
        UPPERCASE##_WORD A, B, C, D; \
        UPPERCASE##_INIT(A, B, C, D); \
        UPPERCASE##_BLOCK(block, A,B,C,D, 64); \
        \
        UPPERCASE##_WORD* Y = (UPPERCASE##_WORD*) digest; \
        Y[0] = A; \
        Y[1] = B; \
        Y[2] = C; \
        Y[3] = D; \
    } \
    \
    __attribute__((target(TARGET))) \
    int md5_test_##LOWERCASE(const uint8_t* digest, const uint8_t* block) { \
        UPPERCASE##_WORD A, B, C, D; \
        UPPERCASE##_INIT(A, B, C, D); \
        UPPERCASE##_BLOCK(block, A,B,C,D, 64); \
        \
        return UPPERCASE##_ANY_EQ(A, *(uint32_t*) digest); \
    } \

GENERATE("arch=x86-64", x86, X86)
GENERATE("mmx", mmx, MMX)
GENERATE("sse2", sse2, SSE2)
GENERATE("avx2", avx2, AVX2)
GENERATE("avx512f", avx512, AVX512)
