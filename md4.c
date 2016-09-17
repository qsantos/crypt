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
// RFC 1320
#include "md4.h"

#include <string.h>

static const uint8_t* padding = (uint8_t*) (
    "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
);

static const MD4Context initctx = { 0, 0, {0}, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

void md4_init(MD4Context* ctx) {
    memcpy(ctx, &initctx, sizeof(MD4Context));
}

#define F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define G(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define ROT(x,n) ((x) << n) | ((x) >> (32-n))
#define OP1(a,b,c,d,k,s) ctx->a = ROT(ctx->a + F(ctx->b,ctx->c,ctx->d) + X[k] + 0x00000000, s);
#define OP2(a,b,c,d,k,s) ctx->a = ROT(ctx->a + G(ctx->b,ctx->c,ctx->d) + X[k] + 0x5A827999, s);
#define OP3(a,b,c,d,k,s) ctx->a = ROT(ctx->a + H(ctx->b,ctx->c,ctx->d) + X[k] + 0x6ED9EBA1, s);
void md4_block(MD4Context* ctx, const uint8_t block[64]) {
    const uint32_t* X = (const uint32_t*) block;

    uint32_t AA = ctx->A;
    uint32_t BB = ctx->B;
    uint32_t CC = ctx->C;
    uint32_t DD = ctx->D;

    OP1(A,B,C,D,  0, 3)  OP1(D,A,B,C,  1, 7)  OP1(C,D,A,B,  2,11)  OP1(B,C,D,A,  3,19)
    OP1(A,B,C,D,  4, 3)  OP1(D,A,B,C,  5, 7)  OP1(C,D,A,B,  6,11)  OP1(B,C,D,A,  7,19)
    OP1(A,B,C,D,  8, 3)  OP1(D,A,B,C,  9, 7)  OP1(C,D,A,B, 10,11)  OP1(B,C,D,A, 11,19)
    OP1(A,B,C,D, 12, 3)  OP1(D,A,B,C, 13, 7)  OP1(C,D,A,B, 14,11)  OP1(B,C,D,A, 15,19)

    OP2(A,B,C,D,  0, 3)  OP2(D,A,B,C,  4, 5)  OP2(C,D,A,B,  8, 9)  OP2(B,C,D,A, 12,13)
    OP2(A,B,C,D,  1, 3)  OP2(D,A,B,C,  5, 5)  OP2(C,D,A,B,  9, 9)  OP2(B,C,D,A, 13,13)
    OP2(A,B,C,D,  2, 3)  OP2(D,A,B,C,  6, 5)  OP2(C,D,A,B, 10, 9)  OP2(B,C,D,A, 14,13)
    OP2(A,B,C,D,  3, 3)  OP2(D,A,B,C,  7, 5)  OP2(C,D,A,B, 11, 9)  OP2(B,C,D,A, 15,13)

    OP3(A,B,C,D,  0, 3)  OP3(D,A,B,C,  8, 9)  OP3(C,D,A,B,  4,11)  OP3(B,C,D,A, 12,15)
    OP3(A,B,C,D,  2, 3)  OP3(D,A,B,C, 10, 9)  OP3(C,D,A,B,  6,11)  OP3(B,C,D,A, 14,15)
    OP3(A,B,C,D,  1, 3)  OP3(D,A,B,C,  9, 9)  OP3(C,D,A,B,  5,11)  OP3(B,C,D,A, 13,15)
    OP3(A,B,C,D,  3, 3)  OP3(D,A,B,C, 11, 9)  OP3(C,D,A,B,  7,11)  OP3(B,C,D,A, 15,15)

    ctx->A += AA;
    ctx->B += BB;
    ctx->C += CC;
    ctx->D += DD;

    // TODO : true cleaning
}

void md4_update(MD4Context* ctx, const uint8_t* data, size_t length) {
    size_t i = 0;
    size_t free_bytes_in_buffer = 64 - ctx->bytes_in_buffer;
    if (length >= free_bytes_in_buffer) {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, data, free_bytes_in_buffer);
        md4_block(ctx, ctx->buffer);
        i = free_bytes_in_buffer;
        ctx->bytes_in_buffer = 0;

        while (i + 63 < length) {
            md4_block(ctx, data + i);
            i+= 64;
        }
    }
    memcpy(ctx->buffer + ctx->bytes_in_buffer, data + i, length - i);
    ctx->bytes_in_buffer += length - i;
    ctx->total_length += length;

    // TODO : true cleaning
}

void md4_final(MD4Context* ctx, uint8_t dst[16]) {
    uint64_t length = ctx->total_length << 3;
    size_t pad = (ctx->bytes_in_buffer < 56 ? 56 : 120) - ctx->bytes_in_buffer;
    md4_update(ctx, padding, pad);
    md4_update(ctx, (uint8_t*) &length, 8);

    memcpy(dst +  0, &ctx->A, 4);
    memcpy(dst +  4, &ctx->B, 4);
    memcpy(dst +  8, &ctx->C, 4);
    memcpy(dst + 12, &ctx->D, 4);

    // TODO : true cleaning
}

void md4(uint8_t dst[16], const uint8_t* src, size_t length) {
    MD4Context ctx;
    md4_init(&ctx);
    md4_update(&ctx, src, length);
    md4_final(&ctx, dst);
}
