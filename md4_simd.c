#include "md4_simd.h"

#include <string.h>

#include "simd.h"
#include "simd_util.h"

/*\
 * This is the central part of MD4. The following code handles one block of the
 * input. OP is a target-dependent macro that executes one step of MD4. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of MD4. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#define MD4_BLOCK( \
        X, /* WORD*: the block to be processed */ \
        A,B,C,D, /* WORD: the 128 bit state of MD4 */ \
        OP1, OP2, OP3, /* the three kinds of MD4 steps */ \
        ADD, /* add WORD to another WORD */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    __typeof__(A) previous_A = A; \
    __typeof__(A) previous_B = B; \
    __typeof__(A) previous_C = C; \
    __typeof__(A) previous_D = D; \
    \
    OP1(A,B,C,D,X,  0, 3); OP1(D,A,B,C,X,  1, 7); OP1(C,D,A,B,X,  2,11); OP1(B,C,D,A,X,  3,19); \
    OP1(A,B,C,D,X,  4, 3); OP1(D,A,B,C,X,  5, 7); OP1(C,D,A,B,X,  6,11); OP1(B,C,D,A,X,  7,19); \
    OP1(A,B,C,D,X,  8, 3); OP1(D,A,B,C,X,  9, 7); OP1(C,D,A,B,X, 10,11); OP1(B,C,D,A,X, 11,19); \
    OP1(A,B,C,D,X, 12, 3); OP1(D,A,B,C,X, 13, 7); OP1(C,D,A,B,X, 14,11); OP1(B,C,D,A,X, 15,19); \
    \
    OP2(A,B,C,D,X,  0, 3); OP2(D,A,B,C,X,  4, 5); OP2(C,D,A,B,X,  8, 9); OP2(B,C,D,A,X, 12,13); \
    OP2(A,B,C,D,X,  1, 3); OP2(D,A,B,C,X,  5, 5); OP2(C,D,A,B,X,  9, 9); OP2(B,C,D,A,X, 13,13); \
    OP2(A,B,C,D,X,  2, 3); OP2(D,A,B,C,X,  6, 5); OP2(C,D,A,B,X, 10, 9); OP2(B,C,D,A,X, 14,13); \
    OP2(A,B,C,D,X,  3, 3); OP2(D,A,B,C,X,  7, 5); OP2(C,D,A,B,X, 11, 9); OP2(B,C,D,A,X, 15,13); \
    \
    /* first look at the "else" block to see the full version */ \
    if (LENGTH <= 4) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since X[12], X[ 3], X[10] and X[ 1] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        OP3(A,B,C,D,X,  0, 3); \
    } else if (LENGTH <= 12) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        OP3(A,B,C,D,X,  0, 3); OP3(D,A,B,C,X,  8, 9); OP3(C,D,A,B,X,  4,11); OP3(B,C,D,A,X, 12,15); \
        OP3(A,B,C,D,X,  2, 3); OP3(D,A,B,C,X, 10, 9); OP3(C,D,A,B,X,  6,11); OP3(B,C,D,A,X, 14,15); \
        OP3(A,B,C,D,X,  1, 3); \
    } else if (LENGTH < 56) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since we only guarantee the computation of A, we can skip the last three steps */ \
        OP3(A,B,C,D,X,  0, 3); OP3(D,A,B,C,X,  8, 9); OP3(C,D,A,B,X,  4,11); OP3(B,C,D,A,X, 12,15); \
        OP3(A,B,C,D,X,  2, 3); OP3(D,A,B,C,X, 10, 9); OP3(C,D,A,B,X,  6,11); OP3(B,C,D,A,X, 14,15); \
        OP3(A,B,C,D,X,  1, 3); OP3(D,A,B,C,X,  9, 9); OP3(C,D,A,B,X,  5,11); OP3(B,C,D,A,X, 13,15); \
        OP3(A,B,C,D,X,  3, 3); OP3(D,A,B,C,X, 11, 9); OP3(C,D,A,B,X,  7,11); OP3(B,C,D,A,X, 15,15); \
    } else { \
        OP3(A,B,C,D,X,  0, 3); OP3(D,A,B,C,X,  8, 9); OP3(C,D,A,B,X,  4,11); OP3(B,C,D,A,X, 12,15); \
        OP3(A,B,C,D,X,  2, 3); OP3(D,A,B,C,X, 10, 9); OP3(C,D,A,B,X,  6,11); OP3(B,C,D,A,X, 14,15); \
        OP3(A,B,C,D,X,  1, 3); OP3(D,A,B,C,X,  9, 9); OP3(C,D,A,B,X,  5,11); OP3(B,C,D,A,X, 13,15); \
        OP3(A,B,C,D,X,  3, 3); OP3(D,A,B,C,X, 11, 9); OP3(C,D,A,B,X,  7,11); OP3(B,C,D,A,X, 15,15); \
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
 * * auxiliary functions F,G,H,I from the MD4 specification
 * * OP to execute a single STEP of MD4 (expecting one of F,G,H,I)
 * * ADD which just adds two values (for the end of the update)
\*/

// x86: no CPU extension, no interleaving (e.g. interleaving of 1)
#define X86_INIT(A, B, C, D) do { \
    A = 0x67452301; \
    B = 0xEFCDAB89; \
    C = 0x98BADCFE; \
    D = 0x10325476; \
} while (0)
#define X86_F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define X86_G(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define X86_H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define X86_OP1(a,b,c,d,X,k,s) do { uint32_t tmp = a + X86_F(b,c,d) + X[k] + 0x00000000; a = X86_ROT(tmp, s); } while (0)
#define X86_OP2(a,b,c,d,X,k,s) do { uint32_t tmp = a + X86_G(b,c,d) + X[k] + 0x5A827999; a = X86_ROT(tmp, s); } while (0)
#define X86_OP3(a,b,c,d,X,k,s) do { uint32_t tmp = a + X86_H(b,c,d) + X[k] + 0x6ED9EBA1; a = X86_ROT(tmp, s); } while (0)
#define X86_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD4_BLOCK(((uint32_t*)BLOCK), \
              A,B,C,D, \
              X86_OP1, X86_OP2, X86_OP3, \
              X86_ADD, LENGTH)

// MMX
#define MMX_INIT(A, B, C, D) do { \
    A = _mm_set1_pi32((int) 0x67452301); \
    B = _mm_set1_pi32((int) 0xEFCDAB89); \
    C = _mm_set1_pi32((int) 0x98BADCFE); \
    D = _mm_set1_pi32((int) 0x10325476); \
} while (0)
#define MMX_F(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_andnot_si64(X, Z))
#define MMX_G(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_or_si64(_mm_and_si64(X, Z), _mm_and_si64(Y, Z)))
#define MMX_H(X,Y,Z) _mm_xor_si64(Y, _mm_xor_si64(X, Z))
#define MMX_OP1(a,b,c,d,X,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MMX_F(b,c,d), X[k])); a = MMX_ROT(tmp, s); } while (0)
#define MMX_OP2(a,b,c,d,X,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MMX_G(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int)0x5A827999)))); a = MMX_ROT(tmp, s); } while (0)
#define MMX_OP3(a,b,c,d,X,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MMX_H(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int)0x6ED9EBA1)))); a = MMX_ROT(tmp, s); } while (0)
#define MMX_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD4_BLOCK(((__m64*)BLOCK), \
              A,B,C,D, \
              MMX_OP1, MMX_OP2, MMX_OP3, \
              MMX_ADD, LENGTH)

// SSE2
#define SSE2_INIT(A, B, C, D) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
} while (0)
#define SSE2_F(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_andnot_si128(X, Z))
#define SSE2_G(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_or_si128(_mm_and_si128(X, Z), _mm_and_si128(Y, Z)))
#define SSE2_H(X,Y,Z) _mm_xor_si128(Y, _mm_xor_si128(X, Z))
#define SSE2_OP1(a,b,c,d,X,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(SSE2_F(b,c,d), X[k])); a = SSE2_ROT(tmp, s); } while (0)
#define SSE2_OP2(a,b,c,d,X,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(SSE2_G(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int)0x5A827999)))); a = SSE2_ROT(tmp, s); } while (0)
#define SSE2_OP3(a,b,c,d,X,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(SSE2_H(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int)0x6ED9EBA1)))); a = SSE2_ROT(tmp, s); } while (0)
#define SSE2_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD4_BLOCK(((__m128i*)BLOCK), \
              A,B,C,D, \
              SSE2_OP1, SSE2_OP2, SSE2_OP3, \
              SSE2_ADD, LENGTH)

// AVX2
#define AVX2_INIT(A, B, C, D) do { \
    A = _mm256_set1_epi32((int) 0x67452301); \
    B = _mm256_set1_epi32((int) 0xEFCDAB89); \
    C = _mm256_set1_epi32((int) 0x98BADCFE); \
    D = _mm256_set1_epi32((int) 0x10325476); \
} while (0)
#define AVX2_F(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_andnot_si256(X, Z))
#define AVX2_G(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_or_si256(_mm256_and_si256(X, Z), _mm256_and_si256(Y, Z)))
#define AVX2_H(X,Y,Z) _mm256_xor_si256(Y, _mm256_xor_si256(X, Z))
#define AVX2_OP1(a,b,c,d,X,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(AVX2_F(b,c,d), X[k])); a = AVX2_ROT(tmp, s); } while (0)
#define AVX2_OP2(a,b,c,d,X,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(AVX2_G(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int)0x5A827999)))); a = AVX2_ROT(tmp, s); } while (0)
#define AVX2_OP3(a,b,c,d,X,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(AVX2_H(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int)0x6ED9EBA1)))); a = AVX2_ROT(tmp, s); } while (0)
#define AVX2_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD4_BLOCK(((__m256i*)BLOCK), \
              A,B,C,D, \
              AVX2_OP1, AVX2_OP2, AVX2_OP3, \
              AVX2_ADD, LENGTH)

// AVX-512
#define AVX512_INIT(A, B, C, D) do { \
    A = _mm512_set1_epi32((int) 0x67452301); \
    B = _mm512_set1_epi32((int) 0xEFCDAB89); \
    C = _mm512_set1_epi32((int) 0x98BADCFE); \
    D = _mm512_set1_epi32((int) 0x10325476); \
} while (0)
#define AVX512_F(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_andnot_si512(X, Z))
#define AVX512_G(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_or_si512(_mm512_and_si512(X, Z), _mm512_and_si512(Y, Z)))
#define AVX512_H(X,Y,Z) _mm512_xor_si512(Y, _mm512_xor_si512(X, Z))
#define AVX512_OP1(a,b,c,d,X,k,s) do { __m512i tmp = _mm512_add_epi32(a, _mm512_add_epi32(AVX512_F(b,c,d), X[k])); a = AVX512_ROT(tmp, s); } while (0)
#define AVX512_OP2(a,b,c,d,X,k,s) do { __m512i tmp = _mm512_add_epi32(a, _mm512_add_epi32(AVX512_G(b,c,d), _mm512_add_epi32(X[k], _mm512_set1_epi32((int)0x5A827999)))); a = AVX512_ROT(tmp, s); } while (0)
#define AVX512_OP3(a,b,c,d,X,k,s) do { __m512i tmp = _mm512_add_epi32(a, _mm512_add_epi32(AVX512_H(b,c,d), _mm512_add_epi32(X[k], _mm512_set1_epi32((int)0x6ED9EBA1)))); a = AVX512_ROT(tmp, s); } while (0)
#define AVX512_BLOCK(BLOCK, A,B,C,D, LENGTH) \
    MD4_BLOCK(((__m512i*)BLOCK), \
              A,B,C,D, \
              AVX512_OP1, AVX512_OP2, AVX512_OP3, \
              AVX512_ADD, LENGTH)

void md4_pad(uint8_t* block, size_t length, size_t stride) {
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
    void md4_oneblock_##LOWERCASE(uint8_t* digest, const uint8_t* block) { \
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
    int md4_test_##LOWERCASE(const uint8_t* digest, const uint8_t* block) { \
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
