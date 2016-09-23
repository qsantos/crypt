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
#define OR(a, b) _mm_or_si128(a, b)
#define XOR(a, b) _mm_xor_si128(a, b)
#define AND(a, b) _mm_and_si128(a, b)
#define ANDNOT(a, b) _mm_andnot_si128(a, b)
#define ROL(x,n) my_mm_rol_epi32(x, n)
#define ADD(a, b) (_mm_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, SET1(V)));
#define BSWAP(X) my_mm_bswap_epi32(X)
#define SET1(a) (_mm_set1_epi32((int) (a)))

#include "md4_block.h"
MD4_GENERATE("sse2", sse2)

#include "md5_block.h"
MD5_GENERATE("sse2", sse2)

#include "sha1_block.h"
SHA1_GENERATE("sse2", sse2)
