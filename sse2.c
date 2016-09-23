#include <stdint.h>
#include <emmintrin.h>  // SSE2 (for _mm_movemask_epi8)

// rotate packed 32-bit integers
__attribute__((target("sse2")))
static inline __m128i my_mm_rol_epi32(__m128i a, int s) {
    return _mm_or_si128(_mm_slli_epi32(a, s), _mm_srli_epi32(a, 32-s));
}

// swap endianness of packed 32-bit integers
__attribute__((target("sse2")))
static inline __m128i my_mm_bswap_epi32(__m128i x) {
    uint32_t* y = (uint32_t*) &x;
    y[0] = __builtin_bswap32(y[0]);
    y[1] = __builtin_bswap32(y[1]);
    y[2] = __builtin_bswap32(y[2]);
    y[3] = __builtin_bswap32(y[3]);
    return x;
}

#define WORD __m128i
#define ROT(x,n) my_mm_rol_epi32(x, n)
#define ADD(a, b) (_mm_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, _mm_set1_epi32((int) V)));
#define BSWAP(X) my_mm_bswap_epi32(X)

#define MD5_INIT(A, B, C, D) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
} while (0)
#define MD5_F(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_andnot_si128(X, Z))
#define MD5_G(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Z), _mm_andnot_si128(Z, Y))
#define MD5_H(X,Y,Z) _mm_xor_si128(_mm_xor_si128(X, Y),Z)
#define MD5_I(X,Y,Z) _mm_xor_si128(Y, _mm_or_si128(X, ~Z))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(f(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int) T[i])))); \
    a = _mm_add_epi32(b, ROT(tmp, s)); \
} while (0)

#include "md5_block.h"
MD5_GENERATE("sse2", sse2)
