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
#include "sha512.h"

#include <string.h>

static const uint8_t* padding = (uint8_t*) (
    "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
);

static const uint64_t K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

static const SHA512Context initctx512 = {
    0, 0, {0},
    { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 },
};

void sha512_init(SHA512Context* ctx) {
    memcpy(ctx, &initctx512, sizeof(SHA512Context));
}

static uint64_t Ch (uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (~x & z);          }
static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (x & z) | (y & z); }
#define ROTR(x,n) (((x) >> n) | ((x) << (64-n)))
#define  SHR(x,n) ((x) >> n)
static uint64_t Sum0  (uint64_t x) { return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39); }
static uint64_t Sum1  (uint64_t x) { return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41); }
static uint64_t Sigma0(uint64_t x) { return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR (x, 7); }
static uint64_t Sigma1(uint64_t x) { return ROTR(x,19) ^ ROTR(x,61) ^ SHR (x, 6); }
#define B64(i) ((uint64_t)(block[t*8+i]))
void sha512_block(SHA512Context* ctx, const uint8_t block[128]) {
    uint64_t W[80];
    for (int t = 0; t < 16; t += 1) {
        W[t] = (B64(0) << 56) | (B64(1) << 48) | (B64(2) << 40) | (B64(3) << 32)
             | (B64(4) << 24) | (B64(5) << 16) | (B64(6) <<  8) | (B64(7) <<  0);
    }

    for (int t = 16; t < 80; t += 1) {
        W[t] = Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16];
    }

    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];

    uint64_t T1;
    uint64_t T2;
    for (int t = 0; t < 80; t += 1) {
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

void sha512_update(SHA512Context* ctx, const uint8_t* data, size_t length) {
    size_t i = 0;
    size_t free_bytes_in_buffer = 128 - ctx->bytes_in_buffer;
    if (length >= free_bytes_in_buffer) {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, data, free_bytes_in_buffer);
        sha512_block(ctx, ctx->buffer);
        i = free_bytes_in_buffer;
        ctx->bytes_in_buffer = 0;

        while (i + 127 < length) {
            sha512_block(ctx, data + i);
            i+= 128;
        }
    }
    memcpy(ctx->buffer + ctx->bytes_in_buffer, data + i, length - i);
    ctx->bytes_in_buffer += length - i;
    ctx->total_length += length;


    // TODO : true cleaning
}

static void u64to8(uint64_t v, uint8_t* dst) {
    dst[0] = (uint8_t) (v >> 56);
    dst[1] = (uint8_t) (v >> 48);
    dst[2] = (uint8_t) (v >> 40);
    dst[3] = (uint8_t) (v >> 32);
    dst[4] = (uint8_t) (v >> 24);
    dst[5] = (uint8_t) (v >> 16);
    dst[6] = (uint8_t) (v >>  8);
    dst[7] = (uint8_t) (v >>  0);

    v = 0;
}

void sha512_final(SHA512Context* ctx, uint8_t dst[32]) {
    uint64_t len0 = ctx->total_length << 3;
    uint64_t len1 = 0; // TODO
    size_t pad = (ctx->bytes_in_buffer < 112 ? 112 : 240) - ctx->bytes_in_buffer;
    sha512_update(ctx, padding, pad);

    uint8_t len8[16];
    len8[15] = (uint8_t) (len0 >>  0);
    len8[14] = (uint8_t) (len0 >>  8);
    len8[13] = (uint8_t) (len0 >> 16);
    len8[12] = (uint8_t) (len0 >> 24);
    len8[11] = (uint8_t) (len0 >> 32);
    len8[10] = (uint8_t) (len0 >> 40);
    len8[ 9] = (uint8_t) (len0 >> 48);
    len8[ 8] = (uint8_t) (len0 >> 56);
    len8[ 7] = (uint8_t) (len1 >>  0);
    len8[ 6] = (uint8_t) (len1 >>  8);
    len8[ 5] = (uint8_t) (len1 >> 16);
    len8[ 4] = (uint8_t) (len1 >> 24);
    len8[ 3] = (uint8_t) (len1 >> 32);
    len8[ 2] = (uint8_t) (len1 >> 40);
    len8[ 1] = (uint8_t) (len1 >> 48);
    len8[ 0] = (uint8_t) (len1 >> 56);
    sha512_update(ctx, len8, 16);

    u64to8(ctx->H[0], dst +  0);
    u64to8(ctx->H[1], dst +  8);
    u64to8(ctx->H[2], dst + 16);
    u64to8(ctx->H[3], dst + 24);
    u64to8(ctx->H[4], dst + 32);
    u64to8(ctx->H[5], dst + 40);
    u64to8(ctx->H[6], dst + 48);
    u64to8(ctx->H[7], dst + 56);

    // TODO : true cleaning
}

void sha512(uint8_t dst[64], const uint8_t* src, size_t length) {
    SHA512Context ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, src, length);
    sha512_final(&ctx, dst);
}



static const SHA384Context initctx384 = {
    0, 0, {0},
    { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4},
};

void sha384_init(SHA384Context* ctx) {
    memcpy(ctx, &initctx384, sizeof(SHA384Context));
}

void sha384_block(SHA384Context* ctx, const uint8_t block[128]) {
    sha512_block(ctx, block);
}

void sha384_update(SHA384Context* ctx, const uint8_t* data, size_t length) {
    sha512_update(ctx, data, length);
}

void sha384_final(SHA384Context* ctx, uint8_t dst[32]) {
    uint64_t len0 = ctx->total_length << 3;
    uint64_t len1 = 0; // TODO
    size_t pad = (ctx->bytes_in_buffer < 112 ? 112 : 240) - ctx->bytes_in_buffer;
    sha384_update(ctx, padding, pad);

    uint8_t len8[16];
    len8[15] = (uint8_t) (len0 >>  0);
    len8[14] = (uint8_t) (len0 >>  8);
    len8[13] = (uint8_t) (len0 >> 16);
    len8[12] = (uint8_t) (len0 >> 24);
    len8[11] = (uint8_t) (len0 >> 32);
    len8[10] = (uint8_t) (len0 >> 40);
    len8[ 9] = (uint8_t) (len0 >> 48);
    len8[ 8] = (uint8_t) (len0 >> 56);
    len8[ 7] = (uint8_t) (len1 >>  0);
    len8[ 6] = (uint8_t) (len1 >>  8);
    len8[ 5] = (uint8_t) (len1 >> 16);
    len8[ 4] = (uint8_t) (len1 >> 24);
    len8[ 3] = (uint8_t) (len1 >> 32);
    len8[ 2] = (uint8_t) (len1 >> 40);
    len8[ 1] = (uint8_t) (len1 >> 48);
    len8[ 0] = (uint8_t) (len1 >> 56);
    sha384_update(ctx, len8, 16);

    u64to8(ctx->H[0], dst +  0);
    u64to8(ctx->H[1], dst +  8);
    u64to8(ctx->H[2], dst + 16);
    u64to8(ctx->H[3], dst + 24);
    u64to8(ctx->H[4], dst + 32);
    u64to8(ctx->H[5], dst + 40);
    //u64to8(ctx->H[6], dst + 48);
    //u64to8(ctx->H[7], dst + 56);

    // TODO : true cleaning
}

void sha384(uint8_t dst[32], const uint8_t* src, size_t length) {
    SHA384Context ctx;
    sha384_init(&ctx);
    sha384_update(&ctx, src, length);
    sha384_final(&ctx, dst);
}
