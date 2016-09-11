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

#include "cipher.h"

#include <string.h>

#include "des.h"
#include "rijndael.h"

#define ENC(a)   ((mode & 0x03) == CIPHER_##a)
#define GET_ENC void (*blockCrypt)(const uint8_t* key, const uint8_t* in, uint8_t* out, bool inverse) =\
    ENC(RIJNDAEL256) ? rijndael_256 :\
    ENC(RIJNDAEL192) ? rijndael_192 :\
    ENC(RIJNDAEL128) ? rijndael_128 :\
                       des

uint8_t key_length(uint8_t mode) {
    switch (mode & 0x03) {
    case CIPHER_DES:
        return 7;
    case CIPHER_RIJNDAEL128:
        return 16;
    case CIPHER_RIJNDAEL192:
        return 24;
    case CIPHER_RIJNDAEL256:
        return 32;
    default:
        return 0;
    }
}

uint8_t cipher_blocksize(uint8_t mode) {
    switch (mode & 0x03) {
    case CIPHER_DES:
        return 8;
    case CIPHER_RIJNDAEL128:
    case CIPHER_RIJNDAEL192:
    case CIPHER_RIJNDAEL256:
        return 16;
    default:
        return 0;
    }
}

int8_t cipher_function_code(char* function) {
    if (!strcmp(function, "des")) {
        return CIPHER_DES;
    } else if (!strcmp(function, "aes128")) {
        return CIPHER_AES128;
    } else if (!strcmp(function, "aes192")) {
        return CIPHER_AES192;
    } else if (!strcmp(function, "aes256")) {
        return CIPHER_AES256;
    } else {
        return -1;
    }
}

void cipher_init(CipherContext* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV) {
    memset(ctx, 0, sizeof(CipherContext));
    memcpy(ctx->key, key, key_length(mode));
    ctx->mode = mode;
    ctx->blocksize = cipher_blocksize(mode);
    if (IV) {
        memcpy(ctx->feedback, IV, ctx->blocksize);
    }
}

void cipher_block(CipherContext* ctx, uint8_t* out, const uint8_t* in, bool inverse) {
    uint8_t mode = ctx->mode;
    GET_ENC;

    uint8_t O[16];
    switch (mode & 0x70) {
    case CIPHER_MODE_ECB:
        blockCrypt(ctx->key, in, out, inverse);
        break;
    case CIPHER_MODE_CBC:
        if (inverse) {
            blockCrypt(ctx->key, in, out, inverse);
            for (size_t i = 0; i < ctx->blocksize; i += 1) {
                out[i] ^= ctx->feedback[i];
            }
            memcpy(ctx->feedback, in, ctx->blocksize);
        } else {
            for (size_t i = 0; i < ctx->blocksize; i += 1) {
                ctx->feedback[i] ^= in[i];
            }
            blockCrypt(ctx->key, ctx->feedback, out, inverse);
            memcpy(ctx->feedback, out, ctx->blocksize);
        }
        break;
    case CIPHER_MODE_PCBC:
        if (inverse) {
            blockCrypt(ctx->key, in, out, inverse);
            for (size_t i = 0; i < ctx->blocksize; i += 1) {
                out[i] ^= ctx->feedback[i];
            }
        } else {
            for (size_t i = 0; i < ctx->blocksize; i += 1) {
                ctx->feedback[i] ^= in[i];
            }
            blockCrypt(ctx->key, ctx->feedback, out, inverse);
        }
        memcpy(ctx->feedback, out, ctx->blocksize);
        for (size_t i = 0; i < ctx->blocksize; i += 1) {
            ctx->feedback[i] ^= in[i];
        }
        break;
    case CIPHER_MODE_CFB:
        blockCrypt(ctx->key, ctx->feedback, O, true);
        for (size_t i = 0; i < ctx->blocksize; i += 1) {
            out[i] = in[i] ^ O[i];
        }
        memcpy(ctx->feedback, inverse ? out : in, ctx->blocksize);
        break;
    case CIPHER_MODE_OFB:
        blockCrypt(ctx->key, ctx->feedback, O, true);
        for (size_t i = 0; i < ctx->blocksize; i += 1) {
            out[i] = in[i] ^ O[i];
        }
        memcpy(ctx->feedback, O, ctx->blocksize);
        break;
    case CIPHER_MODE_CTR:
        blockCrypt(ctx->key, ctx->feedback, out, true);
        for (size_t i = 0; i < ctx->blocksize; i += 1) {
            out[i] ^= in[i];
        }
        bool carry = true;
        for (size_t i = ctx->blocksize; i --> 0; ) {
            if (carry) {
                ctx->feedback[i] = (uint8_t) (ctx->feedback[i] + 1);
                carry = ctx->feedback[i] != 0;
            }
        }
        break;
    default:
        break;
    }
}

size_t cipher_update(CipherContext* ctx, uint8_t* out, const uint8_t* in, size_t length, bool inverse) {
    size_t free_bytes_in_buffer = ctx->blocksize - ctx->bytes_in_buffer;
    size_t remain = length;
    if (remain >= free_bytes_in_buffer) {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, in, free_bytes_in_buffer);
        cipher_block(ctx, out, ctx->buffer, inverse);
        remain -= free_bytes_in_buffer;
        in += free_bytes_in_buffer;
        out += ctx->blocksize;

        while (remain >= ctx->blocksize) {
            cipher_block(ctx, out, in, inverse);
            remain -= ctx->blocksize;
            in += ctx->blocksize;
            out += ctx->blocksize;
        }

        size_t r = length + ctx->bytes_in_buffer - remain;
        memcpy(ctx->buffer, in, remain);
        ctx->bytes_in_buffer = remain;
        return r;
    } else {
        memcpy(ctx->buffer + ctx->bytes_in_buffer, in, length);
        ctx->bytes_in_buffer += length;
        return 0;
    }
}

size_t cipher_final(CipherContext* ctx, uint8_t* out, bool inverse) {
    if (!ctx->bytes_in_buffer) {
        return 0;
    }

    memset(ctx->buffer + ctx->bytes_in_buffer, 0, ctx->blocksize - ctx->bytes_in_buffer);
    cipher_block(ctx, out, ctx->buffer, inverse);
    return ctx->blocksize;
}

size_t cipher(uint8_t* out, const uint8_t* in, uint32_t length, uint8_t mode, const uint8_t* key, const uint8_t* IV, bool inverse) {
    CipherContext ctx;
    cipher_init(&ctx, mode, key, IV);
    size_t ret = cipher_update(&ctx, out, in, length, inverse);
    ret += cipher_final(&ctx, out, inverse);
    return ret;
}

void encrypt_init(EncryptContext* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV) {
    cipher_init(ctx, mode, key, IV);
}

void encrypt_block(EncryptContext* ctx, uint8_t* out, const uint8_t* in) {
    cipher_block(ctx, out, in, false);
}

size_t encrypt_udpate(EncryptContext* ctx, uint8_t* out, const uint8_t* in, uint32_t length) {
    return cipher_update(ctx, out, in, length, false);
}

size_t encrypt_final(EncryptContext* ctx, uint8_t* out) {
    return cipher_final(ctx, out, false);
}

size_t encrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV) {
    return cipher(o, i, l, m, k, IV, true);
}

void decrypt_init(DecryptContext* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV) {
    cipher_init(ctx, mode, key, IV);
}

void decrypt_block(DecryptContext* ctx, uint8_t* out, const uint8_t* in) {
    cipher_block(ctx, out, in, true);
}

size_t decrypt_update(DecryptContext* ctx, uint8_t* out, const uint8_t* in, uint32_t length) {
    return cipher_update(ctx, out, in, length, true);
}

size_t decrypt_final(DecryptContext* ctx, uint8_t* out) {
    return cipher_final(ctx, out, true);
}

size_t decrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV) {
    return cipher(o, i, l, m, k, IV, true);
}
