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

#ifndef AES_H
#define AES_H

#include "rijndael.h"

inline void AES(const uint8_t* key, const uint8_t* in, uint8_t* out, bool inverse, uint8_t Nk, uint8_t Nr)
{
	Rijndael(key, in, out, inverse, Nk, Nr);
}

void AES128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael128(key, in, out, inverse);
}
void AES192(const uint8_t key[24], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael192(key, in, out, inverse);
}

void AES256(const uint8_t key[32], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael256(key, in, out, inverse);
}

#endif
