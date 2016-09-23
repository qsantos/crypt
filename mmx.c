#include <stdint.h>
#include <mmintrin.h>  // MMX
#include <emmintrin.h>  // SSE2 (for _mm_movemask_epi8)

// rotate packed 32-bit integers
__attribute__((target("mmx")))
static inline __m64 my_mm_rol_pi32(__m64 a, int s) {
    return _mm_or_si64(_mm_slli_pi32(a, s), _mm_srli_pi32(a, 32-s));
}

// swap endianness of packed 32-bit integers
__attribute__((target("mmx")))
static inline __m64 my_mm_bswap_pi32(__m64 x) {
    uint64_t y = (uint64_t) _m_to_int64(x);
    uint64_t r = __builtin_bswap32((uint32_t) (y >> 32));
    r <<= 32;
    r |= __builtin_bswap32((uint32_t) y);
    x = _mm_cvtsi64_m64((long long int) r);
    return x;
}

#define WORD __m64
#define OR(a, b) _mm_or_si64(a, b)
#define XOR(a, b) _mm_xor_si64(a, b)
#define AND(a, b) _mm_and_si64(a, b)
#define ANDNOT(a, b) _mm_andnot_si64(a, b)
#define ROL(x,n) my_mm_rol_pi32(x, n)
#define ADD(a, b) (_mm_add_pi32((a), (b)))
// TODO: cheating with _mm_movemask_epi8 (SSE instruction)
#define ANY_EQ(X, V) _mm_movemask_pi8(_mm_cmpeq_pi32(X, SET1(V)));
#define BSWAP(X) my_mm_bswap_pi32(X)
#define SET1(a) (_mm_set1_pi32((int) (a)))

#include "md4_block.h"
MD4_GENERATE("mmx", mmx)

#include "md5_block.h"
MD5_GENERATE("mmx", mmx)

#include "sha1_block.h"
SHA1_GENERATE("mmx", mmx)
