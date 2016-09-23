#include <stdint.h>

#define WORD uint32_t
#define OR(a, b) ((a) | (b))
#define XOR(a, b) ((a) ^ (b))
#define AND(a, b) ((a) & (b))
#define ANDNOT(a, b) (~(a) & (b))
#define SHL(a, s) ((a) << (s))
#define SHR(a, s) ((a) >> (s))
#define ROL(a, s) (((a) << (s)) | ((a) >> (32-(s))))
#define ROR(a, s) (((a) >> (s)) | ((a) << (32-(s))))
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

#include "sha256_block.h"
SHA256_GENERATE("arch=x86-64", x86)
