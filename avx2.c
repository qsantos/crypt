#include <stdint.h>
#include <immintrin.h>  // AVX/AVX2/AVX512

// rotate packed 32-bit integers
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

// swap endianness of packed 32-bit integers
__attribute__((target("avx2")))
static inline __m256i my_mm256_bswap_epi32(__m256i a) {
    long long high = 0x0405060700010203;
    long long low = 0x0c0d0e0f08090a0b;
    __m256i mask = _mm256_set_epi64x(high, low, high, low);
    return _mm256_shuffle_epi8(a, mask);
}

#define WORD __m256i
#define ROT(x,n) my_mm256_rol_epi32(x, n)
#define ADD(a, b) (_mm256_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm256_movemask_epi8(_mm256_cmpeq_epi32(X, _mm256_set1_epi32((int) V)));
#define BSWAP(X) my_mm256_bswap_epi32(X)

// MD4
#define MD4_INIT(A, B, C, D) do { \
    A = _mm256_set1_epi32((int) 0x67452301); \
    B = _mm256_set1_epi32((int) 0xEFCDAB89); \
    C = _mm256_set1_epi32((int) 0x98BADCFE); \
    D = _mm256_set1_epi32((int) 0x10325476); \
} while (0)
#define MD4_F(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_andnot_si256(X, Z))
#define MD4_G(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_or_si256(_mm256_and_si256(X, Z), _mm256_and_si256(Y, Z)))
#define MD4_H(X,Y,Z) _mm256_xor_si256(Y, _mm256_xor_si256(X, Z))
#define MD4_OP1(a,b,c,d,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(MD4_F(b,c,d), X[k])); a = ROT(tmp, s); } while (0)
#define MD4_OP2(a,b,c,d,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(MD4_G(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int)0x5A827999)))); a = ROT(tmp, s); } while (0)
#define MD4_OP3(a,b,c,d,k,s) do { __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(MD4_H(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int)0x6ED9EBA1)))); a = ROT(tmp, s); } while (0)
#include "md4_block.h"
MD4_GENERATE("avx2", avx2)

// MD5
#define MD5_INIT(A, B, C, D) do { \
    A = _mm256_set1_epi32((int) 0x67452301); \
    B = _mm256_set1_epi32((int) 0xEFCDAB89); \
    C = _mm256_set1_epi32((int) 0x98BADCFE); \
    D = _mm256_set1_epi32((int) 0x10325476); \
} while (0)
#define MD5_F(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_andnot_si256(X, Z))
#define MD5_G(X,Y,Z) _mm256_or_si256(_mm256_and_si256(X, Z), _mm256_andnot_si256(Z, Y))
#define MD5_H(X,Y,Z) _mm256_xor_si256(_mm256_xor_si256(X, Y),Z)
#define MD5_I(X,Y,Z) _mm256_xor_si256(Y, _mm256_or_si256(X, ~Z))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    __m256i tmp = _mm256_add_epi32(a, _mm256_add_epi32(f(b,c,d), _mm256_add_epi32(X[k], _mm256_set1_epi32((int) T[i])))); \
    a = _mm256_add_epi32(b, ROT(tmp, s)); \
} while (0)

#include "md5_block.h"
MD5_GENERATE("avx2", avx2)
