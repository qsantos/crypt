#ifndef HMAC_H
#define HMAC_h

#include <stdint.h>

void HMAC(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);

#endif
