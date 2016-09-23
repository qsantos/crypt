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
#define ROL(x,n) my_mm_rol_epi32(x, n)
#define ADD(a, b) (_mm_add_epi32((a), (b)))
#define ANY_EQ(X, V) _mm_movemask_epi8(_mm_cmpeq_epi32(X, _mm_set1_epi32((int) V)));
#define BSWAP(X) my_mm_bswap_epi32(X)

// MD4
#define MD4_INIT(A, B, C, D) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
} while (0)
#define MD4_F(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_andnot_si128(X, Z))
#define MD4_G(X,Y,Z) _mm_or_si128(_mm_and_si128(X, Y), _mm_or_si128(_mm_and_si128(X, Z), _mm_and_si128(Y, Z)))
#define MD4_H(X,Y,Z) _mm_xor_si128(Y, _mm_xor_si128(X, Z))
#define MD4_OP1(a,b,c,d,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(MD4_F(b,c,d), X[k])); a = ROL(tmp, s); } while (0)
#define MD4_OP2(a,b,c,d,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(MD4_G(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int)0x5A827999)))); a = ROL(tmp, s); } while (0)
#define MD4_OP3(a,b,c,d,k,s) do { __m128i tmp = _mm_add_epi32(a, _mm_add_epi32(MD4_H(b,c,d), _mm_add_epi32(X[k], _mm_set1_epi32((int)0x6ED9EBA1)))); a = ROL(tmp, s); } while (0)
#include "md4_block.h"
MD4_GENERATE("sse2", sse2)

// MD5
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
    a = _mm_add_epi32(b, ROL(tmp, s)); \
} while (0)
#include "md5_block.h"
MD5_GENERATE("sse2", sse2)

// SHA-1
#define SHA1_INIT(A, B, C, D, E) do { \
    A = _mm_set1_epi32((int) 0x67452301); \
    B = _mm_set1_epi32((int) 0xEFCDAB89); \
    C = _mm_set1_epi32((int) 0x98BADCFE); \
    D = _mm_set1_epi32((int) 0x10325476); \
    E = _mm_set1_epi32((int) 0xC3D2E1F0); \
} while (0)
#define SHA1_F(B,C,D) _mm_or_si128(_mm_and_si128(B, C), _mm_andnot_si128(B, D))
#define SHA1_G(B,C,D) _mm_xor_si128(B, _mm_xor_si128(C, D))
#define SHA1_H(B,C,D) _mm_or_si128(_mm_and_si128(B, C), _mm_or_si128(_mm_and_si128(B, D), _mm_and_si128(C, D)))
#define SHA1_OP(f,A,B,C,D,t,K) do { \
    __m128i tmp = _mm_add_epi32(ROL(A,5), _mm_add_epi32(f(B,C,D), _mm_add_epi32(E, _mm_add_epi32(W[t], _mm_set1_epi32((int) K))))); \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#include "sha1_block.h"
SHA1_GENERATE("sse2", sse2)
