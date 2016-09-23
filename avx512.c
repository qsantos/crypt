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
#define ROL(x,n) _mm512_rol_epi32(x, n)
#define ADD(a, b) (_mm512_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm512_cmpeq_epi32_mask(X, SET1(V));
#define BSWAP(X) _mm512_bswap_epi32(X)
#define SET1(a) (_mm512_set1_epi32((int) (a)))

// MD4
#define MD4_F(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_andnot_si512(X, Z))
#define MD4_G(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_or_si512(_mm512_and_si512(X, Z), _mm512_and_si512(Y, Z)))
#define MD4_H(X,Y,Z) _mm512_xor_si512(Y, _mm512_xor_si512(X, Z))
#define MD4_OP1(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_F(b,c,d), X[k])); a = ROL(tmp, s); } while (0)
#define MD4_OP2(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_G(b,c,d), ADD(X[k], SET1(0x5A827999)))); a = ROL(tmp, s); } while (0)
#define MD4_OP3(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_H(b,c,d), ADD(X[k], SET1(0x6ED9EBA1)))); a = ROL(tmp, s); } while (0)
#include "md4_block.h"
MD4_GENERATE("avx512f", avx512)

// MD4
#define MD5_F(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Y), _mm512_andnot_si512(X, Z))
#define MD5_G(X,Y,Z) _mm512_or_si512(_mm512_and_si512(X, Z), _mm512_andnot_si512(Z, Y))
#define MD5_H(X,Y,Z) _mm512_xor_si512(_mm512_xor_si512(X, Y),Z)
#define MD5_I(X,Y,Z) _mm512_xor_si512(Y, _mm512_or_si512(X, ~Z))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    WORD tmp = _mm512_add_epi32(a, _mm512_add_epi32(f(b,c,d), _mm512_add_epi32(X[k], SET1(T[i])))); \
    a = _mm512_add_epi32(b, ROL(tmp, s)); \
} while (0)
#include "md5_block.h"
MD5_GENERATE("avx512f", avx512)

// SHA-1
#define SHA1_F(B,C,D) _mm512_or_si512(_mm512_and_si512(B, C), _mm512_andnot_si512(B, D))
#define SHA1_G(B,C,D) _mm512_xor_si512(B, _mm512_xor_si512(C, D))
#define SHA1_H(B,C,D) _mm512_or_si512(_mm512_and_si512(B, C), _mm512_or_si512(_mm512_and_si512(B, D), _mm512_and_si512(C, D)))
#define SHA1_OP(f,A,B,C,D,t,K) do { \
    WORD tmp = ADD(ROL(A,5), ADD(f(B,C,D), ADD(E, ADD(W[t], SET1(K))))); \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#include "sha1_block.h"
SHA1_GENERATE("avx512f", avx512)
