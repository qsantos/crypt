#include <stdint.h>

#define WORD uint32_t
#define ROL(x,n) (((x) << n) | ((x) >> (32-n)))
#define ADD(a, b) ((a) + (b))
#define ANY_EQ(X, V) ((X) == (V))
#define BSWAP(X) __builtin_bswap32(X)
#define SET1(a) (a)

// MD4
#define MD4_F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define MD4_G(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define MD4_H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define MD4_OP1(a,b,c,d,k,s) do { uint32_t tmp = a + MD4_F(b,c,d) + X[k] + 0x00000000; a = ROL(tmp, s); } while (0)
#define MD4_OP2(a,b,c,d,k,s) do { uint32_t tmp = a + MD4_G(b,c,d) + X[k] + 0x5A827999; a = ROL(tmp, s); } while (0)
#define MD4_OP3(a,b,c,d,k,s) do { uint32_t tmp = a + MD4_H(b,c,d) + X[k] + 0x6ED9EBA1; a = ROL(tmp, s); } while (0)
#include "md4_block.h"
MD4_GENERATE("arch=x86-64", x86)

// MD5
#define MD5_F(X,Y,Z) ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MD5_G(X,Y,Z) ((((X) ^ (Y)) & (Z)) ^ (Y))
#define MD5_H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define MD5_I(X,Y,Z) ((Y) ^ ((X) | ~(Z)))
#define MD5_OP(f,a,b,c,d,k,s,i) do { \
    uint32_t tmp = a + f(b,c,d) + X[k] + T[i]; \
    a = b + ROL(tmp, s); \
} while (0)
#include "md5_block.h"
MD5_GENERATE("arch=x86-64", x86)

// SHA-1
#define SHA1_F(B,C,D) ((((C) ^ (D)) & (B)) ^ (D))
#define SHA1_G(B,C,D) ((B) ^ (C) ^ (D))
#define SHA1_H(B,C,D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define SHA1_OP(f,A,B,C,D,t,K) do { \
    uint32_t tmp = ROL(A,5) + f(B,C,D) + E + W[t] + K; \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#include "sha1_block.h"
SHA1_GENERATE("arch=x86-64", x86)
