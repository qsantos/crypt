#include <stdint.h>
#include <immintrin.h>  // AVX/AVX2/AVX512

#define TARGET_NAME "AVX2"
#define TARGET_SUFFIX avx2
#define TARGET_ID "avx2"

// rotate packed 32-bit integers to the left
__attribute__((target("avx2")))
static inline __m256i my_mm256_rol_epi32(__m256i a, int s) {
    if (s == 16) {
        long long high = 0x0d0c0f0e09080b0a;
        long long low = 0x0504070601000302;
        __m256i mask = _mm256_set_epi64x(high, low, high, low);
        return _mm256_shuffle_epi8(a, mask);
    }

    return _mm256_or_si256(_mm256_slli_epi32(a, s), _mm256_srli_epi32(a, 32-s));
}

// rotate packed 32-bit integers to the right
__attribute__((target("avx2")))
static inline __m256i my_mm256_ror_epi32(__m256i a, int s) {
    if (s == 16) {
        long long high = 0x0d0c0f0e09080b0a;
        long long low = 0x0504070601000302;
        __m256i mask = _mm256_set_epi64x(high, low, high, low);
        return _mm256_shuffle_epi8(a, mask);
    }

    return _mm256_or_si256(_mm256_srli_epi32(a, s), _mm256_slli_epi32(a, 32-s));
}

// swap endianness of packed 32-bit integers
__attribute__((target("avx2")))
static inline __m256i my_mm256_bswap_epi32(__m256i a) {
    long long high = 0x0405060700010203;
    long long low = 0x0c0d0e0f08090a0b;
    __m256i mask = _mm256_set_epi64x(high, low, high, low);
    return _mm256_shuffle_epi8(a, mask);
}

#define WORD __m256i
#define OR(a, b) _mm256_or_si256(a, b)
#define XOR(a, b) _mm256_xor_si256(a, b)
#define AND(a, b) _mm256_and_si256(a, b)
#define ANDNOT(a, b) _mm256_andnot_si256(a, b)
#define SHL(a, s) _mm256_slli_epi32(a, s)
#define SHR(a, s) _mm256_srli_epi32(a, s)
#define ROL(a, s) my_mm256_rol_epi32(a, s)
#define ROR(a, s) my_mm256_ror_epi32(a, s)
#define ADD(a, b) (_mm256_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm256_movemask_epi8(_mm256_cmpeq_epi32(X, SET1(V)))
#define BSWAP(X) my_mm256_bswap_epi32(X)
#define SET1(a) (_mm256_set1_epi32((int) (a)))

#include "md4_block.h"
MD4_GENERATE("avx2", avx2)

#include "md5_block.h"
MD5_GENERATE("avx2", avx2)

#include "sha1_block.h"
SHA1_GENERATE("avx2", avx2)

#include "sha256_block.h"
SHA256_GENERATE("avx2", avx2)
