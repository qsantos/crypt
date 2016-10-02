#include <stdint.h>

#define TARGET_NAME "x86"
#define TARGET_SUFFIX x86
#define TARGET_ID "arch=x86-64"

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

#include "md2_filter.inc.c"
#include "md4_filter.inc.c"
#include "md5_filter.inc.c"
#include "sha1_filter.inc.c"
#include "sha256_filter.inc.c"
