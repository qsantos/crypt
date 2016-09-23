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
#define ROL(x,n) my_mm_rol_pi32(x, n)
#define ADD(a, b) (_mm_add_pi32((a), (b)))
// TODO: cheating with _mm_movemask_epi8 (SSE instruction)
#define ANY_EQ(X, V) _mm_movemask_pi8(_mm_cmpeq_pi32(X, _mm_set1_pi32((int) V)));
#define BSWAP(X) my_mm_bswap_pi32(X)
#define SET1(a) (_mm_set1_pi32((int) (a)))

// MD4
#define MD4_F(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_andnot_si64(X, Z))
#define MD4_G(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_or_si64(_mm_and_si64(X, Z), _mm_and_si64(Y, Z)))
#define MD4_H(X,Y,Z) _mm_xor_si64(Y, _mm_xor_si64(X, Z))
#define MD4_OP1(a,b,c,d,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MD4_F(b,c,d), X[k])); a = ROL(tmp, s); } while (0)
#define MD4_OP2(a,b,c,d,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MD4_G(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int)0x5A827999)))); a = ROL(tmp, s); } while (0)
#define MD4_OP3(a,b,c,d,k,s) do { __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(MD4_H(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int)0x6ED9EBA1)))); a = ROL(tmp, s); } while (0)
#include "md4_block.h"
MD4_GENERATE("mmx", mmx)

// MD5
#define MD5_F(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Y), _mm_andnot_si64(X, Z))
#define MD5_G(X,Y,Z) _mm_or_si64(_mm_and_si64(X, Z), _mm_andnot_si64(Z, Y))
#define MD5_H(X,Y,Z) _mm_xor_si64(_mm_xor_si64(X, Y),Z)
#define MD5_I(X,Y,Z) _mm_xor_si64(Y, _mm_or_si64(X, ~Z))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    __m64 tmp = _mm_add_pi32(a, _mm_add_pi32(f(b,c,d), _mm_add_pi32(X[k], _mm_set1_pi32((int) T[i])))); \
    a = _mm_add_pi32(b, ROL(tmp, s)); \
} while (0)
#include "md5_block.h"
MD5_GENERATE("mmx", mmx)

// SHA-1
#define SHA1_F(B,C,D) _mm_or_si64(_mm_and_si64(B, C), _mm_andnot_si64(B, D))
#define SHA1_G(B,C,D) _mm_xor_si64(B, _mm_xor_si64(C, D))
#define SHA1_H(B,C,D) _mm_or_si64(_mm_and_si64(B, C), _mm_or_si64(_mm_and_si64(B, D), _mm_and_si64(C, D)))
#define SHA1_OP(f,A,B,C,D,t,K) do { \
    __m64 tmp = _mm_add_pi32(ROL(A,5), _mm_add_pi32(f(B,C,D), _mm_add_pi32(E, _mm_add_pi32(W[t], _mm_set1_pi32((int) K))))); \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#include "sha1_block.h"
SHA1_GENERATE("mmx", mmx)
