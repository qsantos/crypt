#include "sha1_simd.h"

#include <string.h>
#include <mmintrin.h>  // MMX
#include <emmintrin.h>  // SSE2
#include <immintrin.h>  // AVX/AVX2/AVX512

#include "simd.h"

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

#define SHA1_BLOCK( \
        X, /* WORD*: the block to be processed */ \
        A,B,C,D,E, /* WORD: the 160 bit state of SHA1 */ \
        F,G,H, /* the three SHA1 auxiliary functions */ \
        OP, /* execute a single step of SHA1, update the state */ \
        ADD, /* add WORD to another WORD */ \
        ROT, /* rotate WORD by s bits */ \
        REV_ENDIAN, /* reverse the endianness of a WORD */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    __typeof__(A) W[80]; \
    \
    for (int t = 0; t < 16; t += 1) { \
        W[t] = REV_ENDIAN(X[t]); \
    } \
    \
    for (int t = 16; t < 80; t += 1) { \
        W[t] = ROT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
    } \
    \
    __typeof__(A) previous_A = A; \
    __typeof__(A) previous_B = B; \
    __typeof__(A) previous_C = C; \
    __typeof__(A) previous_D = D; \
    __typeof__(A) previous_E = E; \
    \
    for (int t =  0; t < 20; t += 1) { OP(F,A,B,C,D,W,t,0x5A827999); } \
    for (int t = 20; t < 40; t += 1) { OP(G,A,B,C,D,W,t,0x6ED9EBA1); } \
    for (int t = 40; t < 60; t += 1) { OP(H,A,B,C,D,W,t,0x8F1BBCDC); } \
    for (int t = 60; t < 80; t += 1) { OP(G,A,B,C,D,W,t,0xCA62C1D6); } \
    \
    A = ADD(A, previous_A); \
    B = ADD(B, previous_B); \
    C = ADD(C, previous_C); \
    D = ADD(D, previous_D); \
    E = ADD(E, previous_E); \
} while (0)

/*\
 * Below are the target-dependent implementations. An implementation needs:
 *
 * * INIT to reset the state
 * * auxiliary functions F,G,H,I from the SHA1 specification
 * * OP to execute a single STEP of SHA1 (expecting one of F,G,H,I)
 * * ADD which just adds two values (for the end of the update)
\*/

// x86: no CPU extension, no interleaving (e.g. interleaving of 1)
#define X86_WORD uint32_t
#define X86_INIT(A, B, C, D, E) do { \
    A = 0x67452301; \
    B = 0xEFCDAB89; \
    C = 0x98BADCFE; \
    D = 0x10325476; \
    E = 0xC3D2E1F0; \
} while (0)
#define X86_F(B,C,D) ((((C) ^ (D)) & (B)) ^ (D))
#define X86_G(B,C,D) ((B) ^ (C) ^ (D))
#define X86_H(B,C,D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define X86_ROT(x,n) (((x) << n) | ((x) >> (32-n)))
#define X86_OP(f,A,B,C,D,W,t,K) do { \
    uint32_t tmp = X86_ROT(A,5) + f(B,C,D) + E + W[t] + K; \
    E = D; D = C; C = X86_ROT(B, 30); B = A; A = tmp; \
} while (0)
#define X86_ADD(a, b) ((a) + (b))
#define X86_BLOCK(BLOCK, A,B,C,D,E, LENGTH) \
    SHA1_BLOCK(((uint32_t*)BLOCK), \
              A,B,C,D,E,\
              X86_F, X86_G, X86_H, \
              X86_OP, X86_ADD, X86_ROT, X86_REV_ENDIAN, LENGTH)
#define X86_ANY_EQ(X, V) ((X) == (V))
#define X86_REV_ENDIAN(X) __builtin_bswap32(X)

// MMX
#define MMX_WORD __m64
#define MMX_INIT(A, B, C, D, E) do { \
    A = _mm_set1_pi32((int) 0x67452301); \
    B = _mm_set1_pi32((int) 0xEFCDAB89); \
    C = _mm_set1_pi32((int) 0x98BADCFE); \
    D = _mm_set1_pi32((int) 0x10325476); \
    E = _mm_set1_pi32((int) 0xC3D2E1F0); \
} while (0)
#define MMX_F(B,C,D) _mm_or_si64(_mm_and_si64(B, C), _mm_andnot_si64(B, D))
#define MMX_G(B,C,D) _mm_xor_si64(B, _mm_xor_si64(C, D))
#define MMX_H(B,C,D) _mm_or_si64(_mm_and_si64(B, C), _mm_or_si64(_mm_and_si64(B, D), _mm_and_si64(C, D)))
#define MMX_ROT(x,n) _mm_or_si64(_mm_slli_pi32(x, n), _mm_srli_pi32(x, 32-n))
#define MMX_OP(f,A,B,C,D,W,t,K) do { \
    __m64 tmp = _mm_add_pi32(MMX_ROT(A,5), _mm_add_pi32(f(B,C,D), _mm_add_pi32(E, _mm_add_pi32(W[t], _mm_set1_pi32((int) K))))); \
    E = D; D = C; C = MMX_ROT(B, 30); B = A; A = tmp; \
} while (0)
#define MMX_ADD(a, b) (_mm_add_pi32((a), (b)))
#define MMX_BLOCK(BLOCK, A,B,C,D,E, LENGTH) \
    SHA1_BLOCK(((__m64*)BLOCK), \
              A,B,C,D,E,\
              MMX_F, MMX_G, MMX_H, \
              MMX_OP, MMX_ADD, MMX_ROT, MMX_REV_ENDIAN, LENGTH)
#define MMX_ANY_EQ(X, V) _mm_movemask_pi8(_mm_cmpeq_pi32(X, _mm_set1_pi32((int) V)));
__attribute__((target("mmx")))
static __m64 _mm_swap_pi32(__m64 x) {
    uint64_t y = (uint64_t) _m_to_int64(x);
    uint64_t r = __builtin_bswap32((uint32_t) (y >> 32));
    r <<= 32;
    r |= __builtin_bswap32((uint32_t) y);
    x = _mm_cvtsi64_m64((long long int) r);
    return x;
}
#define MMX_REV_ENDIAN(X) _mm_swap_pi32(X)

// SSE2
#define SSE2_WORD __m128i
#define SSE2_INIT(A, B, C, D, E) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
    E = _mm_set1_epi32((int) 0xC3D2E1F0); \
} while (0)
#define SSE2_F(B,C,D) _mm_or_si128(_mm_and_si128(B, C), _mm_andnot_si128(B, D))
#define SSE2_G(B,C,D) _mm_xor_si128(B, _mm_xor_si128(C, D))
#define SSE2_H(B,C,D) _mm_or_si128(_mm_and_si128(B, C), _mm_or_si128(_mm_and_si128(B, D), _mm_and_si128(C, D)))
#define SSE2_ROT(x,n) _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32-n))
#define SSE2_OP(f,A,B,C,D,W,t,K) do { \
    __m128i tmp = _mm_add_epi32(SSE2_ROT(A,5), _mm_add_epi32(f(B,C,D), _mm_add_epi32(E, _mm_add_epi32(W[t], _mm_set1_epi32((int) K))))); \
    E = D; D = C; C = SSE2_ROT(B, 30); B = A; A = tmp; \
} while (0)
#define SSE2_ADD(a, b) (_mm_add_epi32((a), (b)))
#define SSE2_BLOCK(BLOCK, A,B,C,D,E, LENGTH) \
    SHA1_BLOCK(((__m128i*)BLOCK), \
              A,B,C,D,E,\
              SSE2_F, SSE2_G, SSE2_H, \
              SSE2_OP, SSE2_ADD, SSE2_ROT, SSE2_REV_ENDIAN, LENGTH)
#define SSE2_ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, _mm_set1_epi32((int) V)));
// TODO: cheating with _mm_movemask_epi8 (SSSE3 instruction)
//#define SSE2_REV_ENDIAN(X) _mm_shuffle_epi8(X, _mm_set_epi32(0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203))
__attribute__((target("sse2")))
static __m128i _mm_swap_epi32(__m128i x) {
    uint32_t* y = (uint32_t*) &x;
    y[0] = __builtin_bswap32(y[0]);
    y[1] = __builtin_bswap32(y[1]);
    y[2] = __builtin_bswap32(y[2]);
    y[3] = __builtin_bswap32(y[3]);
    return x;
}
#define SSE2_REV_ENDIAN(X) _mm_swap_epi32(X)

// AVX2
#define AVX2_WORD __m256i
#define AVX2_INIT(A, B, C, D, E) do { \
    A = _mm256_set1_epi32((int) 0x67452301); \
    B = _mm256_set1_epi32((int) 0xEFCDAB89); \
    C = _mm256_set1_epi32((int) 0x98BADCFE); \
    D = _mm256_set1_epi32((int) 0x10325476); \
    E = _mm256_set1_epi32((int) 0xC3D2E1F0); \
} while (0)
#define AVX2_F(B,C,D) _mm256_or_si256(_mm256_and_si256(B, C), _mm256_andnot_si256(B, D))
#define AVX2_G(B,C,D) _mm256_xor_si256(B, _mm256_xor_si256(C, D))
#define AVX2_H(B,C,D) _mm256_or_si256(_mm256_and_si256(B, C), _mm256_or_si256(_mm256_and_si256(B, D), _mm256_and_si256(C, D)))
#define AVX2_ROT(x,n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32-n))
#define AVX2_OP(f,A,B,C,D,W,t,K) do { \
    __m256i tmp = _mm256_add_epi32(AVX2_ROT(A,5), _mm256_add_epi32(f(B,C,D), _mm256_add_epi32(E, _mm256_add_epi32(W[t], _mm256_set1_epi32((int) K))))); \
    E = D; D = C; C = AVX2_ROT(B, 30); B = A; A = tmp; \
} while (0)
#define AVX2_ADD(a, b) (_mm256_add_epi32((a), (b)))
#define AVX2_BLOCK(BLOCK, A,B,C,D,E, LENGTH) \
    SHA1_BLOCK(((__m256i*)BLOCK), \
              A,B,C,D,E,\
              AVX2_F, AVX2_G, AVX2_H, \
              AVX2_OP, AVX2_ADD, AVX2_ROT, AVX2_REV_ENDIAN, LENGTH)
#define AVX2_ANY_EQ(X, V) _mm256_movemask_epi8(_mm256_cmpeq_epi32(X, _mm256_set1_epi32((int) V)));
__attribute__((target("avx2")))
static __m256i _mm256_swap_epi32(__m256i x) {
    uint32_t* y = (uint32_t*) &x;
    y[0] = __builtin_bswap32(y[0]);
    y[1] = __builtin_bswap32(y[1]);
    y[2] = __builtin_bswap32(y[2]);
    y[3] = __builtin_bswap32(y[3]);
    y[4] = __builtin_bswap32(y[4]);
    y[5] = __builtin_bswap32(y[5]);
    y[6] = __builtin_bswap32(y[6]);
    y[7] = __builtin_bswap32(y[7]);
    return x;
}
#define AVX2_REV_ENDIAN(X) _mm256_swap_epi32(X)

// AVX-512
#define AVX512_WORD __m512i
#define AVX512_INIT(A, B, C, D, E) do { \
    A = _mm512_set1_epi32((int) 0x67452301); \
    B = _mm512_set1_epi32((int) 0xEFCDAB89); \
    C = _mm512_set1_epi32((int) 0x98BADCFE); \
    D = _mm512_set1_epi32((int) 0x10325476); \
    E = _mm512_set1_epi32((int) 0xC3D2E1F0); \
} while (0)
#define AVX512_F(B,C,D) _mm512_or_si512(_mm512_and_si512(B, C), _mm512_andnot_si512(B, D))
#define AVX512_G(B,C,D) _mm512_xor_si512(B, _mm512_xor_si512(C, D))
#define AVX512_H(B,C,D) _mm512_or_si512(_mm512_and_si512(B, C), _mm512_or_si512(_mm512_and_si512(B, D), _mm512_and_si512(C, D)))
#define AVX512_ROT(x,n) _mm512_or_si512(_mm512_slli_epi32(x, n), _mm512_srli_epi32(x, 32-n))
#define AVX512_OP(f,A,B,C,D,W,t,K) do { \
    __m512i tmp = _mm512_add_epi32(AVX512_ROT(A,5), _mm512_add_epi32(f(B,C,D), _mm512_add_epi32(E, _mm512_add_epi32(W[t], _mm512_set1_epi32((int) K))))); \
    E = D; D = C; C = AVX512_ROT(B, 30); B = A; A = tmp; \
} while (0)
#define AVX512_ADD(a, b) (_mm512_add_epi32((a), (b)))
#define AVX512_BLOCK(BLOCK, A,B,C,D,E, LENGTH) \
    SHA1_BLOCK(((__m512i*)BLOCK), \
              A,B,C,D,E,\
              AVX512_F, AVX512_G, AVX512_H, \
              AVX512_OP, AVX512_ADD, AVX512_ROT, AVX512_REV_ENDIAN, LENGTH)
#define AVX512_ANY_EQ(X, V) _mm512_cmpeq_epi32_mask(X, _mm512_set1_epi32((int) V));
__attribute__((target("avx512f")))
static __m512i _mm512_swap_epi32(__m512i x) {
    uint32_t* y = (uint32_t*) &x;
    y[ 0] = __builtin_bswap32(y[ 0]);
    y[ 1] = __builtin_bswap32(y[ 1]);
    y[ 2] = __builtin_bswap32(y[ 2]);
    y[ 3] = __builtin_bswap32(y[ 3]);
    y[ 4] = __builtin_bswap32(y[ 4]);
    y[ 5] = __builtin_bswap32(y[ 5]);
    y[ 6] = __builtin_bswap32(y[ 6]);
    y[ 7] = __builtin_bswap32(y[ 7]);
    y[ 8] = __builtin_bswap32(y[ 8]);
    y[ 9] = __builtin_bswap32(y[ 9]);
    y[10] = __builtin_bswap32(y[10]);
    y[11] = __builtin_bswap32(y[11]);
    y[12] = __builtin_bswap32(y[12]);
    y[13] = __builtin_bswap32(y[13]);
    y[14] = __builtin_bswap32(y[14]);
    y[15] = __builtin_bswap32(y[15]);
    return x;
}
#define AVX512_REV_ENDIAN(X) _mm512_swap_epi32(X)

void sha1_pad(uint8_t* block, size_t length, size_t stride) {
    memset(block, 0, 64 * stride);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t offset;

        // data termination
        offset = interleaved_offset(length, stride, interleaf);
        block[offset] = 0x80;

        // length in bits
        size_t bits = length * 8;
        for (size_t i = 8; i --> 0; ) {
            offset = interleaved_offset(56 + i, stride, interleaf);
            block[offset] = (uint8_t) bits;
            bits >>= 8;
        }
    }
}

#define GENERATE(TARGET, LOWERCASE, UPPERCASE) \
    __attribute__((target(TARGET))) \
    void sha1_oneblock_##LOWERCASE(uint8_t* digest, const uint8_t* block) { \
        UPPERCASE##_WORD A, B, C, D, E; \
        UPPERCASE##_INIT(A, B, C, D, E); \
        UPPERCASE##_BLOCK(block, A,B,C,D,E, 64); \
        \
        UPPERCASE##_WORD* Y = (UPPERCASE##_WORD*) digest; \
        Y[0] = UPPERCASE##_REV_ENDIAN(A); \
        Y[1] = UPPERCASE##_REV_ENDIAN(B); \
        Y[2] = UPPERCASE##_REV_ENDIAN(C); \
        Y[3] = UPPERCASE##_REV_ENDIAN(D); \
        Y[4] = UPPERCASE##_REV_ENDIAN(E); \
    } \
    \
    __attribute__((target(TARGET))) \
    int sha1_test_##LOWERCASE(const uint8_t* digest, const uint8_t* block) { \
        UPPERCASE##_WORD A, B, C, D, E; \
        UPPERCASE##_INIT(A, B, C, D, E); \
        UPPERCASE##_BLOCK(block, A,B,C,D,E, 64); \
        \
        return UPPERCASE##_ANY_EQ(A, *(uint32_t*) digest); \
    } \

GENERATE("arch=x86-64", x86, X86)
GENERATE("mmx", mmx, MMX)
GENERATE("sse2", sse2, SSE2)
GENERATE("avx2", avx2, AVX2)
GENERATE("avx512f", avx512, AVX512)
