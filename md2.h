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
} MD2ctx;

MD2ctx* MD2_new();
void MD2_push(MD2ctx* md2, uint64_t len, const uint8_t* data);
void MD2_hash(MD2ctx* md2, uint8_t dst[16]); // sets hash in dst and frees md2
void MD2(uint64_t len, const uint8_t* src, uint8_t dst[16]);

#endif
