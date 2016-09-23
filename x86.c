#include <stdint.h>

#define WORD uint32_t
#define ROT(x,n) (((x) << n) | ((x) >> (32-n)))
#define ADD(a, b) ((a) + (b))
#define ANY_EQ(X, V) ((X) == (V))
#define BSWAP(X) __builtin_bswap32(X)

#define MD5_INIT(A, B, C, D) do { \
    A = 0x67452301; \
    B = 0xEFCDAB89; \
    C = 0x98BADCFE; \
    D = 0x10325476; \
} while (0)
#define MD5_F(X,Y,Z) ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MD5_G(X,Y,Z) ((((X) ^ (Y)) & (Z)) ^ (Y))
#define MD5_H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define MD5_I(X,Y,Z) ((Y) ^ ((X) | ~(Z)))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    uint32_t tmp = a + f(b,c,d) + X[k] + T[i]; \
    a = b + ROT(tmp, s); \
} while (0)

#include "md5_block.h"
MD5_GENERATE("arch=x86-64", x86)
