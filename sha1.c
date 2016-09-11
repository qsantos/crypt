/*\
 *  Insecure implementation of some cryptographic primitives
 *  Copyright (C) 2012  Quentin SANTOS
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
\*/

// Reference:
// RFC 3174
#include "sha1.h"

#include <string.h>

static const uint8_t* padding = (uint8_t*) (
    "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
);

static const SHA1_CTX initctx = { 0, 0, {0}, {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}, {0}};

void SHA1Init(SHA1_CTX* sha1) {
    memcpy(sha1, &initctx, sizeof(SHA1_CTX));
}

#define F(B,C,D) (((B) & (C)) | (~(B) & (D)))
#define G(B,C,D) ((B) ^ (C) ^ (D))
#define H(B,C,D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define ROT(x,n) (((x) << n) | ((x) >> (32-n)))
#define OP(f,K) { \
    uint32_t TEMP = ROT(A,5) + f(B,C,D) + E + W[t] + K; \
    E = D; D = C; C = ROT(B, 30); B = A; A = TEMP; \
    TEMP = 0; \
}
void SHA1Block(SHA1_CTX* sha1, const uint8_t block[64]) {
    uint32_t W[80];
    for (int t = 0; t < 16; t += 1) {
        W[t] = (uint32_t) ( (block[t*4] << 24) | (block[t*4+1] << 16) | (block[t*4+2] << 8) | (block[t*4+3] << 0) );
    }

    for (int t = 16; t < 80; t += 1) {
        W[t] = ROT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    uint32_t A = sha1->H[0];
    uint32_t B = sha1->H[1];
    uint32_t C = sha1->H[2];
    uint32_t D = sha1->H[3];
    uint32_t E = sha1->H[4];

    for (int t =  0; t < 20; t += 1) {
        OP(F, 0x5A827999);
    }
    for (int t = 20; t < 40; t += 1) {
        OP(G, 0x6ED9EBA1);
    }
    for (int t = 40; t < 60; t += 1) {
        OP(H, 0x8F1BBCDC);
    }
    for (int t = 60; t < 80; t += 1) {
        OP(G, 0xCA62C1D6);
    }

    sha1->H[0] += A;
    sha1->H[1] += B;
    sha1->H[2] += C;
    sha1->H[3] += D;
    sha1->H[4] += E;

    // TODO : true cleaning
}

void SHA1Update(SHA1_CTX* sha1, const uint8_t* data, size_t len) {
    size_t i = 0;
    size_t availBuf = 64 - sha1->bufLen;
    if (len >= availBuf) {
        memcpy(sha1->buffer + sha1->bufLen, data, availBuf);
        SHA1Block(sha1, sha1->buffer);
        i = availBuf;
        sha1->bufLen = 0;

        while (i + 63 < len) {
            SHA1Block(sha1, data + i);
            i+= 64;
        }
    }
    memcpy(sha1->buffer + sha1->bufLen, data + i, len - i);
    sha1->bufLen += len - i;
    sha1->len += len;

    // TODO : true cleaning
}

static void u32to8(uint32_t v, uint8_t* dst) {
    dst[0] = (uint8_t) (v >> 24);
    dst[1] = (uint8_t) (v >> 16);
    dst[2] = (uint8_t) (v >>  8);
    dst[3] = (uint8_t) (v >>  0);

    // TODO : true cleaning
}

void SHA1Final(SHA1_CTX* sha1, uint8_t dst[20]) {
    uint64_t len = sha1->len << 3;
    size_t pad = (sha1->bufLen < 56 ? 56 : 120) - sha1->bufLen;
    SHA1Update(sha1, padding, pad);

    uint8_t len8[8];
    len8[7] = (uint8_t) (len >>  0);
    len8[6] = (uint8_t) (len >>  8);
    len8[5] = (uint8_t) (len >> 16);
    len8[4] = (uint8_t) (len >> 24);
    len8[3] = (uint8_t) (len >> 32);
    len8[2] = (uint8_t) (len >> 40);
    len8[1] = (uint8_t) (len >> 48);
    len8[0] = (uint8_t) (len >> 56);
    SHA1Update(sha1, len8, 8);

    u32to8(sha1->H[0], dst +  0);
    u32to8(sha1->H[1], dst +  4);
    u32to8(sha1->H[2], dst +  8);
    u32to8(sha1->H[3], dst + 12);
    u32to8(sha1->H[4], dst + 16);

    // TODO : true cleaning
}

void SHA1(uint8_t dst[20], const uint8_t* src, size_t slen) {
    SHA1_CTX sha1;
    SHA1Init(&sha1);
    SHA1Update(&sha1, src, slen);
    SHA1Final(&sha1, dst);
}
