#ifndef MD2_H
#define MD2_H

// MD2 provides a 16 byte hash
#include <stdint.h>

typedef struct
{
	uint8_t bufLen;
	uint8_t buffer[16];
	uint8_t C[16];
	uint8_t X[16];
} MD2_CTX;

void MD2Init  (MD2_CTX* md2);
void MD2Update(MD2_CTX* md2, const uint8_t* data, uint64_t len);
void MD2Final (MD2_CTX* md2, uint8_t dst[16]); // sets hash in dst and frees md2

void MD2(uint8_t dst[16], const uint8_t* src, uint64_t slen);

#endif
