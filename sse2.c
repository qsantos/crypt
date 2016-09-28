#include <stdint.h>
#include <emmintrin.h>  // SSE2 (for _mm_movemask_epi8)

#define TARGET_NAME "SSE2"
#define TARGET_SUFFIX sse2
#define TARGET_ID "sse2"

// rotate packed 32-bit integers to the left
__attribute__((target("sse2")))
static inline __m128i my_mm_rol_epi32(__m128i a, int s) {
    return _mm_or_si128(_mm_slli_epi32(a, s), _mm_srli_epi32(a, 32-s));
}

// rotate packed 32-bit integers to the right
__attribute__((target("sse2")))
static inline __m128i my_mm_ror_epi32(__m128i a, int s) {
    return _mm_or_si128(_mm_srli_epi32(a, s), _mm_slli_epi32(a, 32-s));
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
#define SHL(a, s) _mm_slli_epi32(a, s)
#define SHR(a, s) _mm_srli_epi32(a, s)
#define ROL(a, s) my_mm_rol_epi32(a, s)
#define ROR(a, s) my_mm_ror_epi32(a, s)
#define ADD(a, b) (_mm_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, SET1(V)))
#define BSWAP(X) my_mm_bswap_epi32(X)
#define SET1(a) (_mm_set1_epi32((int) (a)))

#include "md4_filter.inc.c"
#include "md5_filter.inc.c"
#include "sha1_filter.inc.c"
#include "sha256_filter.inc.c"
