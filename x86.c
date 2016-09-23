#include <stdint.h>

#define WORD uint32_t
#define OR(a, b) ((a) | (b))
#define XOR(a, b) ((a) ^ (b))
#define AND(a, b) ((a) & (b))
#define ANDNOT(a, b) (~(a) & (b))
#define ROL(x,n) (((x) << n) | ((x) >> (32-n)))
#define ADD(a, b) ((a) + (b))
#define ANY_EQ(X, V) ((X) == (V))
#define BSWAP(X) __builtin_bswap32(X)
#define SET1(a) (a)

#include "md4_block.h"
MD4_GENERATE("arch=x86-64", x86)

#include "md5_block.h"
MD5_GENERATE("arch=x86-64", x86)

#include "sha1_block.h"
SHA1_GENERATE("arch=x86-64", x86)
