#include "md5_filter.h"

#include <string.h>

#include "interleave.h"
#include "keyspace.h"

void md5_pad(uint8_t* block, size_t length, size_t stride) {
    memset(block, 0, 64 * stride);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t offset;

        // data termination
        offset = interleaved_offset(length, stride, interleaf);
        block[offset] = 0x80;

        // length in bits
        offset = interleaved_offset(56, stride, interleaf);
        *(uint32_t*) (block + offset) = (uint32_t) (length * 8);
    }
}

static const uint32_t T[] = {
    0,

    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};


#define I(X,Y,Z) ((Y) ^ ((X) | ~(Z)))
#define ROT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define REV(f,a,b,c,d,k,s,i) a = ROT(a - b, 32-s) - f(b,c,d) - X[k] - T[i];

uint32_t md5_getfilterone(uint8_t digest[16], size_t length, size_t index, size_t* lifetime) {
    if (lifetime != NULL) {
        size_t n_prefixes = 1;
        for (size_t i = 0; i < 4; i += 1) {
            n_prefixes *= charset_length;
        }
        *lifetime = n_prefixes - (index % n_prefixes);
    }

    uint8_t block[64];
    const char* ptrs[64];
    md5_pad(block, length, 1);
    set_keys(block, ptrs, length, 1, index, 0);

    uint32_t* words = (uint32_t*) digest;
    uint32_t A = words[0];
    uint32_t B = words[1];
    uint32_t C = words[2];
    uint32_t D = words[3];

    A -= 0x67452301;
    B -= 0xEFCDAB89;
    C -= 0x98BADCFE;
    D -= 0x10325476;

    uint32_t* X = (uint32_t*) block;
    REV(I,B,C,D,A,  9,21,64); REV(I,C,D,A,B,  2,15,63); REV(I,D,A,B,C, 11,10,62); REV(I,A,B,C,D,  4, 6,61);
    REV(I,B,C,D,A, 13,21,60); REV(I,C,D,A,B,  6,15,59); REV(I,D,A,B,C, 15,10,58); REV(I,A,B,C,D,  8, 6,57);
    REV(I,B,C,D,A,  1,21,56); REV(I,C,D,A,B, 10,15,55); REV(I,D,A,B,C,  3,10,54); REV(I,A,B,C,D, 12, 6,53);
    REV(I,B,C,D,A,  5,21,52); REV(I,C,D,A,B, 14,15,51); REV(I,D,A,B,C,  7,10,50);

    return D;
}
