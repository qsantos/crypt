#include "md4_filter.h"

#include <string.h>

#include "interleave.h"
#include "keyspace.h"

void md4_pad(uint8_t* block, size_t length, size_t stride) {
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

#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define ROT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define REV3(a,b,c,d,k,s) a = ROT(a, 32-s) - H(b,c,d) - X[k] - 0x6ED9EBA1;

uint32_t md4_getfilterone(uint8_t digest[16], size_t length, size_t index, size_t* lifetime) {
    if (lifetime != NULL) {
        size_t n_prefixes = 1;
        for (size_t i = 0; i < 4; i += 1) {
            n_prefixes *= charset_length;
        }
        *lifetime = n_prefixes - (index % n_prefixes);
    }

    uint8_t block[64];
    const char* ptrs[64];
    md4_pad(block, length, 1);
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
    REV3(B,C,D,A, 15,15); REV3(C,D,A,B,  7,11); REV3(D,A,B,C, 11, 9); REV3(A,B,C,D,  3, 3);
    REV3(B,C,D,A, 13,15); REV3(C,D,A,B,  5,11); REV3(D,A,B,C,  9, 9); REV3(A,B,C,D,  1, 3);
    REV3(B,C,D,A, 14,15); REV3(C,D,A,B,  6,11); REV3(D,A,B,C, 10, 9); REV3(A,B,C,D,  2, 3);
    REV3(B,C,D,A, 12,15); REV3(C,D,A,B,  4,11); REV3(D,A,B,C,  8, 9);

    return D;
}
