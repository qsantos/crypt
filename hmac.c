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
// RFC 2104
#include "hmac.h"

#include <string.h>

#include "hash.h"

#define B 64

void hmac(uint8_t mode, uint8_t* data, uint64_t data_length, uint8_t* key, size_t key_length, uint8_t* digest) {
    HashContext ctx;
    uint8_t ipad[B];
    uint8_t opad[B];
    memset(ipad, 0, B);
    memset(opad, 0, B);

    if (key_length > B) {
        hash_init(mode, &ctx);
        hash_update(mode, &ctx, key, key_length);
        hash_final(mode, &ctx, ipad);
        memcpy(opad, ipad, 16);
    } else {
        memcpy(ipad, key, key_length);
        memcpy(opad, key, key_length);
    }

    for (int i = 0; i < B; i += 1) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    hash_init(mode, &ctx);
    hash_update(mode, &ctx, ipad, B);
    hash_update(mode, &ctx, data, data_length);
    hash_final(mode, &ctx, digest);

    hash_init(mode, &ctx);
    hash_update(mode, &ctx, opad, B);
    hash_update(mode, &ctx, digest, 16);
    hash_final(mode, &ctx, digest);
}
