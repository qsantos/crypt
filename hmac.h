#ifndef HMAC_H
#define HMAC_h

#include <stdint.h>

void HMAC(uint8_t mode, uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t* digest);

void HMAC_MD2   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_MD4   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_MD5   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_SHA1  (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[20]);
void HMAC_SHA256(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[32]);
void HMAC_SHA224(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[28]);
void HMAC_SHA512(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[64]);
void HMAC_SHA384(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[48]);

#endif
