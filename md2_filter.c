#include "md4_filter.h"

#include <string.h>

#include "interleave.h"
#include "keyspace.h"

#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define ROT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define REV3(a,b,c,d,k,s) a = ROT(a, 32-s) - H(b,c,d) - X[k] - 0x6ED9EBA1;

void md2_pad(uint8_t* block, size_t length, size_t stride) {
    uint8_t pad = (uint8_t) (16 - length);
    memset(block + length*stride, pad, (16-length)*stride);
}

uint32_t md2_getfilterone(uint8_t digest[16], size_t length, size_t index, size_t* lifetime) {
    (void) length;
    (void) index;

    if (lifetime != NULL) {
        *lifetime = (size_t) -1;
    }

    return digest[0];
}
