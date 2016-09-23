#include <stdint.h>
#include <immintrin.h>  // AVX/AVX2/AVX512

// swap endianness of packed 32-bit integers
__attribute__((target("avx512bw")))
static inline __m512i _mm512_bswap_epi32(__m512i a) {
    long long high = 0x0405060700010203;
    long long low = 0x0c0d0e0f08090a0b;
    __m512i mask = _mm512_set_epi64(high, low, high, low, high, low, high, low);
    return _mm512_shuffle_epi8(a, mask);
}

#define WORD __m512i
#define ROT(x,n) _mm512_rol_epi32(x, n)
#define ADD(a, b) (_mm512_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm512_cmpeq_epi32_mask(X, _mm512_set1_epi32((int) V));
#define BSWAP(X) _mm512_bswap_epi32(X)

#define MD5_INIT(A, B, C, D) do { \
    A = _mm512_set1_epi32((int) 0x67452301); \
    B = _mm512_set1_epi32((int) 0xEFCDAB89); \
    C = _mm512_set1_epi32((int) 0x98BADCFE); \
    D = _mm512_set1_epi32((int) 0x10325476); \
} while (0)
#define MD5_F(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_andnot_si512(X, Z))
#define MD5_G(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Z), _mm512_andnot_si512(Z, Y))
#define MD5_H(X,Y,Z) _mm512_xor_si512(_mm512_xor_si512(X, Y),Z)
#define MD5_I(X,Y,Z) _mm512_xor_si512(Y, _mm512_or_si512(X, ~Z))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    __m512i tmp = _mm512_add_epi32(a, _mm512_add_epi32(f(b,c,d), _mm512_add_epi32(X[k], _mm512_set1_epi32((int) T[i])))); \
    a = _mm512_add_epi32(b, ROT(tmp, s)); \
} while (0)

#include "md5_block.h"
MD5_GENERATE("avx512f", avx512)
