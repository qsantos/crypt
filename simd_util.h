#ifndef SIMD_UTIL_H
#define SIMD_UTIL_H

#include <mmintrin.h>  // MMX
#include <emmintrin.h>  // SSE2
#include <immintrin.h>  // AVX/AVX2/AVX512

// rotate packed 32-bit integers
__attribute__((target("mmx")))
static inline __m64 _mm_rol_pi32(__m64 a, int s) {
    return _mm_or_si64(_mm_slli_pi32(a, s), _mm_srli_pi32(a, 32-s));
}

__attribute__((target("sse2")))
static inline __m128i _mm_rol_epi32(__m128i a, int s) {
    return _mm_or_si128(_mm_slli_epi32(a, s), _mm_srli_epi32(a, 32-s));
}

__attribute__((target("avx2")))
static inline __m256i _mm256_rol_epi32(__m256i a, int s) {
    if (s == 16) {
        long long high = 0x0d0c0f0e09080b0a;
        long long low = 0x0504070601000302;
        __m256i mask = _mm256_set_epi64x(high, low, high, low);
        return _mm256_shuffle_epi8(a, mask);
    }

    return _mm256_or_si256(_mm256_slli_epi32(a, s), _mm256_srli_epi32(a, 32-s));
}

// swap endianness of 32-bit integers
__attribute__((target("mmx")))
static inline __m64 _mm_swap_pi32(__m64 x) {
    uint64_t y = (uint64_t) _m_to_int64(x);
    uint64_t r = __builtin_bswap32((uint32_t) (y >> 32));
    r <<= 32;
    r |= __builtin_bswap32((uint32_t) y);
    x = _mm_cvtsi64_m64((long long int) r);
    return x;
}

__attribute__((target("sse2")))
static inline __m128i _mm_swap_epi32(__m128i x) {
    uint32_t* y = (uint32_t*) &x;
    y[0] = __builtin_bswap32(y[0]);
    y[1] = __builtin_bswap32(y[1]);
    y[2] = __builtin_bswap32(y[2]);
    y[3] = __builtin_bswap32(y[3]);
    return x;
}

__attribute__((target("avx2")))
static inline __m256i _mm256_swap_epi32(__m256i a) {
    long long high = 0x0405060700010203;
    long long low = 0x0c0d0e0f08090a0b;
    __m256i mask = _mm256_set_epi64x(high, low, high, low);
    return _mm256_shuffle_epi8(a, mask);
}

__attribute__((target("avx512bw")))
static inline __m512i _mm512_swap_epi32(__m512i a) {
    long long high = 0x0405060700010203;
    long long low = 0x0c0d0e0f08090a0b;
    __m512i mask = _mm512_set_epi64(high, low, high, low, high, low, high, low);
    return _mm512_shuffle_epi8(a, mask);
}

#define X86_WORD uint32_t
#define MMX_WORD __m64
#define SSE2_WORD __m128i
#define AVX2_WORD __m256i
#define AVX512_WORD __m512i

#define X86_ROT(x,n) (((x) << n) | ((x) >> (32-n)))
#define MMX_ROT(x,n) _mm_rol_pi32(x, n)
#define SSE2_ROT(x,n) _mm_rol_epi32(x, n)
#define AVX2_ROT(x,n) _mm256_rol_epi32(x, n)
#define AVX512_ROT(x,n) _mm512_rol_epi32(x, n)

#define X86_ADD(a, b) ((a) + (b))
#define MMX_ADD(a, b) (_mm_add_pi32((a), (b)))
#define SSE2_ADD(a, b) (_mm_add_epi32((a), (b)))
#define AVX2_ADD(a, b) (_mm256_add_epi32((a), (b)))
#define AVX512_ADD(a, b) (_mm512_add_epi32((a), (b)))

#define X86_ANY_EQ(X, V) ((X) == (V))
// TODO: cheating with _mm_movemask_epi8 (SSE instruction)
#define MMX_ANY_EQ(X, V) _mm_movemask_pi8(_mm_cmpeq_pi32(X, _mm_set1_pi32((int) V)));
#define SSE2_ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, _mm_set1_epi32((int) V)));
#define AVX2_ANY_EQ(X, V) _mm256_movemask_epi8(_mm256_cmpeq_epi32(X, _mm256_set1_epi32((int) V)));
#define AVX512_ANY_EQ(X, V) _mm512_cmpeq_epi32_mask(X, _mm512_set1_epi32((int) V));

#define X86_REV_ENDIAN(X) __builtin_bswap32(X)
#define MMX_REV_ENDIAN(X) _mm_swap_pi32(X)
#define SSE2_REV_ENDIAN(X) _mm_swap_epi32(X)
#define AVX2_REV_ENDIAN(X) _mm256_swap_epi32(X)
#define AVX512_REV_ENDIAN(X) _mm512_swap_epi32(X)

#endif
