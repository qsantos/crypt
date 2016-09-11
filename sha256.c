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
// Federal Information Processing Standards Publication
// (FIPS PUB) 180-2, Secure hash Standard, 1 August 2002.
#include "sha256.h"

#include <string.h>

static const uint8_t* padding = (uint8_t*) (
    "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
);

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const SHA256Context initctx256 = {
    0, 0, {0},
    {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
};

void sha256_init(SHA256Context* ctx) {
    memcpy(ctx, &initctx256, sizeof(SHA256Context));
}

#define  Ch(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define Maj(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define ROTL(x,n) (((x) << n) | ((x) >> (32-n)))
#define ROTR(x,n) (((x) >> n) | ((x) << (32-n)))
#define  SHR(x,n) ((x) >> n)
#define   Sum0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define   Sum1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define Sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR (x, 3))
#define Sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR (x,10))
void sha256_block(SHA256Context* ctx, const uint8_t block[64]) {
    uint32_t W[64];
    for (int t = 0; t < 16; t += 1) {
        W[t] = (uint32_t) ( (block[t*4] << 24) | (block[t*4+1] << 16) | (block[t*4+2] << 8) | (block[t*4+3] << 0) );
    }

    for (int t = 16; t < 64; t += 1) {
        W[t] = Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16];
    }

    uint32_t a = ctx->H[0];
    uint32_t b = ctx->H[1];
    uint32_t c = ctx->H[2];
    uint32_t d = ctx->H[3];
    uint32_t e = ctx->H[4];
    uint32_t f = ctx->H[5];
    uint32_t g = ctx->H[6];
    uint32_t h = ctx->H[7];

    uint32_t T1;
    uint32_t T2;
    for (int t = 0; t < 64; t += 1) {
        T1 = Sum1(e) + Ch (e,f,g) + K[t] + W[t] + h;
        T2 = Sum0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    T1 = 0;
    T2 = 0;

    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;

    // TODO : true cleaning
}

void sha256_udpate(SHA256Context* ctx, const uint8_t* data, size_t length) {
    size_t i = 0;
    size_t free_bytes_in_buffer = 64 - ctx->bytes_in_buffer;
    if (length >= free_bytes_in_buffer) {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, data, free_bytes_in_buffer);
        sha256_block(ctx, ctx->buffer);
        i = free_bytes_in_buffer;
        ctx->bytes_in_buffer = 0;

        while (i + 63 < length) {
            sha256_block(ctx, data + i);
            i+= 64;
        }
    }
    memcpy(ctx->buffer + ctx->bytes_in_buffer, data + i, length - i);
    ctx->bytes_in_buffer += length - i;
    ctx->total_length += length;

    // TODO : true cleaning
}

static void u32to8(uint32_t v, uint8_t* dst) {
    dst[0] = (uint8_t) (v >> 24);
    dst[1] = (uint8_t) (v >> 16);
    dst[2] = (uint8_t) (v >>  8);
    dst[3] = (uint8_t) (v >>  0);

    // TODO : true cleaning
}

void sha256_final(SHA256Context* ctx, uint8_t dst[32]) {
    uint64_t length = ctx->total_length << 3;
    size_t pad = (ctx->bytes_in_buffer < 56 ? 56 : 120) - ctx->bytes_in_buffer;
    sha256_udpate(ctx, padding, pad);

    uint8_t len8[8];
    len8[7] = (uint8_t) (length >>  0);
    len8[6] = (uint8_t) (length >>  8);
    len8[5] = (uint8_t) (length >> 16);
    len8[4] = (uint8_t) (length >> 24);
    len8[3] = (uint8_t) (length >> 32);
    len8[2] = (uint8_t) (length >> 40);
    len8[1] = (uint8_t) (length >> 48);
    len8[0] = (uint8_t) (length >> 56);
    sha256_udpate(ctx, len8, 8);

    u32to8(ctx->H[0], dst +  0);
    u32to8(ctx->H[1], dst +  4);
    u32to8(ctx->H[2], dst +  8);
    u32to8(ctx->H[3], dst + 12);
    u32to8(ctx->H[4], dst + 16);
    u32to8(ctx->H[5], dst + 20);
    u32to8(ctx->H[6], dst + 24);
    u32to8(ctx->H[7], dst + 28);

    // TODO : true cleaning
}

void sha256(uint8_t dst[32], const uint8_t* src, size_t length) {
    SHA256Context ctx;
    sha256_init(&ctx);
    sha256_udpate(&ctx, src, length);
    sha256_final(&ctx, dst);
}


static const SHA224Context initctx224 = {
    0, 0, {0},
    {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4},
};

void sha224_init(SHA224Context* ctx) {
    memcpy(ctx, &initctx224, sizeof(SHA224Context));
}

void sha224_block(SHA224Context* ctx, const uint8_t block[64]) {
    sha256_block(ctx, block);
}

void sha224_update(SHA224Context* ctx, const uint8_t* data, size_t length) {
    sha256_udpate(ctx, data, length);
}

void sha224_final(SHA224Context* ctx, uint8_t dst[28]) {
    uint64_t length = ctx->total_length << 3;
    size_t pad = (ctx->bytes_in_buffer < 56 ? 56 : 120) - ctx->bytes_in_buffer;
    sha224_update(ctx, padding, pad);

    uint8_t len8[8];
    len8[7] = (uint8_t) (length >>  0);
    len8[6] = (uint8_t) (length >>  8);
    len8[5] = (uint8_t) (length >> 16);
    len8[4] = (uint8_t) (length >> 24);
    len8[3] = (uint8_t) (length >> 32);
    len8[2] = (uint8_t) (length >> 40);
    len8[1] = (uint8_t) (length >> 48);
    len8[0] = (uint8_t) (length >> 56);
    sha224_update(ctx, len8, 8);

    u32to8(ctx->H[0], dst +  0);
    u32to8(ctx->H[1], dst +  4);
    u32to8(ctx->H[2], dst +  8);
    u32to8(ctx->H[3], dst + 12);
    u32to8(ctx->H[4], dst + 16);
    u32to8(ctx->H[5], dst + 20);
    u32to8(ctx->H[6], dst + 24);
    //u32to8(ctx->H[7], dst + 28);

    // TODO : true cleaning
}

void sha224(uint8_t dst[28], const uint8_t* src, size_t length) {
    SHA224Context ctx;
    sha224_init(&ctx);
    sha224_update(&ctx, src, length);
    sha224_final(&ctx, dst);
}
