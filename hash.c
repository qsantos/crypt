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

#include "hash.h"

#include <string.h>

uint8_t hash_blocksize(uint8_t mode) {
    switch (mode & 0x07) {
        case HASH_MD2: return 16;
        case HASH_MD4: return 64;
        case HASH_MD5: return 64;
        case HASH_SHA1: return 64;
        case HASH_SHA256: return 64;
        case HASH_SHA224: return 64;
        case HASH_SHA512: return 128;
        case HASH_SHA384: return 128;
        default: return 0;
    }
}

uint8_t digest_length(uint8_t mode) {
    switch (mode & 0x07) {
    case HASH_MD2: return 16;
    case HASH_MD4: return 16;
    case HASH_MD5: return 16;
    case HASH_SHA1: return 20;
    case HASH_SHA256: return 32;
    case HASH_SHA224: return 28;
    case HASH_SHA512: return 64;
    case HASH_SHA384: return 48;
    default: return 1;
    }
}

int8_t hash_function_code(char* function) {
    if      (!strcmp(function, "md2")) { return HASH_MD2; }
    else if (!strcmp(function, "md4")) { return HASH_MD4; }
    else if (!strcmp(function, "md5")) { return HASH_MD5; }
    else if (!strcmp(function, "sha1")) { return HASH_SHA1; }
    else if (!strcmp(function, "sha256")) { return HASH_SHA256; }
    else if (!strcmp(function, "sha224")) { return HASH_SHA224; }
    else if (!strcmp(function, "sha512")) { return HASH_SHA512; }
    else if (!strcmp(function, "sha384")) { return HASH_SHA384; }
    else {
        return -1;
    }
}

void hash_init(uint8_t mode, HashContext* ctx) {
    switch (mode) {
    case HASH_MD2:    md2_init   ((MD2Context*)    ctx); break;
    case HASH_MD4:    md4_init   ((MD4Context*)    ctx); break;
    case HASH_MD5:    md5_init   ((MD5Context*)    ctx); break;
    case HASH_SHA1:   sha1_init  ((SHA1Context*)   ctx); break;
    case HASH_SHA256: sha256_init((SHA256Context*) ctx); break;
    case HASH_SHA224: sha224_init((SHA224Context*) ctx); break;
    case HASH_SHA512: sha512_init((SHA512Context*) ctx); break;
    case HASH_SHA384: sha384_init((SHA384Context*) ctx); break;
    default: break;
    }
}

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[64];
} AnyContext;

static void hash_block(uint8_t mode, AnyContext* ctx, const uint8_t* data) {
    switch (mode) {
    case HASH_MD2:    md2_block   ((MD2Context*)    ctx, data); break;
    case HASH_MD4:    md4_block   ((MD4Context*)    ctx, data); break;
    case HASH_MD5:    md5_block   ((MD5Context*)    ctx, data); break;
    case HASH_SHA1:   sha1_block  ((SHA1Context*)   ctx, data); break;
    case HASH_SHA256: sha256_block((SHA256Context*) ctx, data); break;
    case HASH_SHA224: sha224_block((SHA224Context*) ctx, data); break;
    case HASH_SHA512: sha512_block((SHA512Context*) ctx, data); break;
    case HASH_SHA384: sha384_block((SHA384Context*) ctx, data); break;
    default: break;
    }
}

void hash_update(uint8_t mode, HashContext* _ctx, const uint8_t* data, uint64_t length) {
    AnyContext* ctx = (AnyContext*) _ctx;
    uint8_t blockSize = hash_blocksize(mode);
    if (blockSize == 0) {
        return;
    }

    size_t i = 0;
    size_t free_bytes_in_buffer = blockSize - ctx->bytes_in_buffer;
    if (length >= free_bytes_in_buffer) {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, data, free_bytes_in_buffer);
        hash_block(mode, ctx, ctx->buffer);
        i = free_bytes_in_buffer;
        ctx->bytes_in_buffer = 0;

        size_t last = length - blockSize;
        while (i <= last) {
            hash_block(mode, ctx, data + i);
            i+= blockSize;
        }
    }
    memcpy(ctx->buffer + ctx->bytes_in_buffer, data + i, length - i);
    ctx->bytes_in_buffer += length - i;
    ctx->total_length += length;
}

void hash_final(uint8_t mode, HashContext* ctx, uint8_t* dst) {
    switch (mode) {
    case HASH_MD2:    md2_final   ((MD2Context*)    ctx, dst); break;
    case HASH_MD4:    md4_final   ((MD4Context*)    ctx, dst); break;
    case HASH_MD5:    md5_final   ((MD5Context*)    ctx, dst); break;
    case HASH_SHA1:   sha1_final  ((SHA1Context*)   ctx, dst); break;
    case HASH_SHA256: sha256_final((SHA256Context*) ctx, dst); break;
    case HASH_SHA224: sha224_final((SHA224Context*) ctx, dst); break;
    case HASH_SHA512: sha512_final((SHA512Context*) ctx, dst); break;
    case HASH_SHA384: sha384_final((SHA384Context*) ctx, dst); break;
    default: break;
    }
}

void hash(uint8_t mode, uint8_t* digest, const uint8_t* data, uint64_t length) {
    HashContext ctx;
    hash_init  (mode, &ctx);
    hash_update(mode, &ctx, data, length);
    hash_final (mode, &ctx, digest);
}
