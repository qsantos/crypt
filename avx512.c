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
#define OR(a, b) _mm512_or_si512(a, b)
#define XOR(a, b) _mm512_xor_si512(a, b)
#define AND(a, b) _mm512_and_si512(a, b)
#define ANDNOT(a, b) _mm512_andnot_si512(a, b)
#define ROL(x,n) _mm512_rol_epi32(x, n)
#define ADD(a, b) (_mm512_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm512_cmpeq_epi32_mask(X, SET1(V));
#define BSWAP(X) _mm512_bswap_epi32(X)
#define SET1(a) (_mm512_set1_epi32((int) (a)))

#include "md4_block.h"
MD4_GENERATE("avx512f", avx512)

#include "md5_block.h"
MD5_GENERATE("avx512f", avx512)

#include "sha1_block.h"
SHA1_GENERATE("avx512f", avx512)
