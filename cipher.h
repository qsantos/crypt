/*\
 *  This is an awesome programm simulating awesome battles of awesome robot tanks
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

#ifndef CIPHER_H
#define CIPHER_H

#include <stdbool.h>
#include <stdint.h>

// algorithms
#define CIPHER_DES          0x00
#define CIPHER_RIJNDAEL128  0x01
#define CIPHER_RIJNDAEL192  0x02
#define CIPHER_RIJNDAEL256  0x03

// algorithm aliases
#define CIPHER_AES128 CIPHER_RIJNDAEL128
#define CIPHER_AES192 CIPHER_RIJNDAEL192
#define CIPHER_AES256 CIPHER_RIJNDAEL256

// modes
#define CIPHER_MODE_ECB         0x00
#define CIPHER_MODE_CBC         0x10
#define CIPHER_MODE_PCBC        0x20
#define CIPHER_MODE_CFB         0x30
#define CIPHER_MODE_CFB1        0x40 // TODO
#define CIPHER_MODE_CFB8        0x50 // TODO
#define CIPHER_MODE_OFB         0x60
#define CIPHER_MODE_CTR         0x70

// chaining methods
#define CIPHER_CHAIN_E          0x00
#define CIPHER_CHAIN_EDE        0x80 // TODO

// mode aliases
#define CIPHER_MODE_TECB  (CIPHER_CHAIN_EDE | CIPHER_MODE_ECB )
#define CIPHER_MODE_TCBC  (CIPHER_CHAIN_EDE | CIPHER_MODE_CBC )
#define CIPHER_MODE_TPCBC (CIPHER_CHAIN_EDE | CIPHER_MODE_PCBC)
#define CIPHER_MODE_TCFB  (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB )
#define CIPHER_MODE_TCFB1 (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB1)
#define CIPHER_MODE_TCFB8 (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB8)
#define CIPHER_MODE_TOFB  (CIPHER_CHAIN_EDE | CIPHER_MODE_OFB )
#define CIPHER_MODE_TCTR  (CIPHER_CHAIN_EDE | CIPHER_MODE_CTR )

uint8_t KeyLength      (uint8_t mode);
uint8_t CipherBlockSize(uint8_t mode);
int8_t  CipherFunCode  (char*   fun);



typedef struct
{
	uint8_t bufLen;
	uint8_t buffer  [16];
	uint8_t feedback[16];
	uint8_t key     [32];
	uint8_t mode;
	uint8_t blocksize;
} Cipher_CTX;

void     CipherInit  (Cipher_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV);
void     CipherBlock (Cipher_CTX* ctx, uint8_t* out, const uint8_t* in, bool inverse);
uint32_t CipherUpdate(Cipher_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len, bool inverse);
uint32_t CipherFinal (Cipher_CTX* ctx, uint8_t* out, bool inverse);

uint32_t Cipher(uint8_t* out, const uint8_t* in, uint32_t len,
                uint8_t mode, const uint8_t* key, const uint8_t* IV, bool inverse);



typedef Cipher_CTX Encrypt_CTX;

void     EncryptInit  (Encrypt_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV);
void     EncryptBlock (Encrypt_CTX* ctx, uint8_t* out, const uint8_t* in);
uint32_t EncryptUpdate(Encrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len);
uint32_t EncryptFinal (Encrypt_CTX* ctx, uint8_t* out);

uint32_t Encrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV);



typedef Cipher_CTX Decrypt_CTX;

void     DecryptInit  (Decrypt_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV);
void     DecryptBlock (Decrypt_CTX* ctx, uint8_t* out, const uint8_t* in);
uint32_t DecryptUpdate(Decrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len);
uint32_t DecryptFinal (Decrypt_CTX* ctx, uint8_t* out);

uint32_t Decrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV);

#endif
