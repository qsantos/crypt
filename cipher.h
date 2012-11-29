#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>

#define CIPHER_MODE_ECB         0x00
#define CIPHER_MODE_CBC         0x01
#define CIPHER_MODE_PCBC        0x02
#define CIPHER_MODE_CFB         0x03
#define CIPHER_MODE_CFB1        0x04 // TODO
#define CIPHER_MODE_CFB8        0x05 // TODO
#define CIPHER_MODE_OFB         0x06
#define CIPHER_MODE_CTR         0x07

#define CIPHER_CHAIN_E          0x00
#define CIPHER_CHAIN_EDE        0x08

#define CIPHER_ENC_DES          0x00
#define CIPHER_ENC_RIJNDAEL128  0x10
#define CIPHER_ENC_RIJNDAEL192  0x20
#define CIPHER_ENC_RIJNDAEL256  0x30

#define CIPHER_ENC_AES128 CIPHER_ENC_RIJNDAEL128
#define CIPHER_ENC_AES192 CIPHER_ENC_RIJNDAEL192
#define CIPHER_ENC_AES256 CIPHER_ENC_RIJNDAEL256

#define CIPHER_MODE_TECB  (CIPHER_CHAIN_EDE | CIPHER_MODE_ECB )
#define CIPHER_MODE_TCBC  (CIPHER_CHAIN_EDE | CIPHER_MODE_CBC )
#define CIPHER_MODE_TPCBC (CIPHER_CHAIN_EDE | CIPHER_MODE_PCBC)
#define CIPHER_MODE_TCFB  (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB )
#define CIPHER_MODE_TCFB1 (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB1)
#define CIPHER_MODE_TCFB8 (CIPHER_CHAIN_EDE | CIPHER_MODE_CFB8)
#define CIPHER_MODE_TOFB  (CIPHER_CHAIN_EDE | CIPHER_MODE_OFB )
#define CIPHER_MODE_TCTR  (CIPHER_CHAIN_EDE | CIPHER_MODE_CTR )

uint8_t KeyLength    (uint8_t mode);
int8_t  CipherFunCode(char*   fun);

void Crypt  (uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV);
void Decrypt(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV);

#endif
