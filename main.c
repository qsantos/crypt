#include <stdio.h>
#include <string.h>

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "cipher.h"

void checkDigestStr(void(digest)(uint64_t, const uint8_t*, uint8_t*), char* str, char* hash, uint8_t hashLen)
{
	uint8_t result[64];
	digest(strlen(str), (uint8_t*) str, result);
	for (uint8_t i = 0; i < 16; i++)
	{
		char digit[3];
		snprintf(digit, 3, "%.2x", result[i]);
		if (digit[0] != hash[2*i] || digit[1] != hash[2*i+1])
		{
			printf("'%s' got wrong hash\n", str);
			break;
		}
	}
}

void checkDigestFile(void(digest)(uint64_t, const uint8_t*, uint8_t*), uint8_t hashLen, const char* file)
{
	FILE* f = fopen(file, "r");
	if (f)
	{
		printf("Checking '%s'\n", file);
	}
	else
	{
		fprintf(stderr, "Could not open '%s'\n", file);
		return;
	}
	char* line = NULL;
	size_t n_line = 0;
	while (1)
	{
		getline(&line, &n_line, f);
		if (feof(f))
			break;
		char* hash = strtok(line, " ");
		char* str  = strtok(NULL, "\n");
		if (hash && str)
		{
			checkDigestStr(digest, str, hash, hashLen);
		}
	}
	fclose(f);
}

#define DIGEST_FILE(F, DIGEST, OUTPUT)             \
{                                                  \
	uint8_t buffer[1024];                      \
	DIGEST##ctx* ctx = DIGEST##_new();         \
	while (!feof(F))                           \
	{                                          \
		int n = fread(buffer, 1, 1024, F); \
		DIGEST##_push(ctx, n, buffer);     \
	}                                          \
	DIGEST##_hash(ctx, OUTPUT);                \
}

int main()
{
	// validity checks
/*
	checkDigestFile(MD2,    16, "tests/md2");
	checkDigestFile(MD4,    16, "tests/md4");
	checkDigestFile(MD5,    16, "tests/md5");
	checkDigestFile(SHA1,   20, "tests/sha1");
	checkDigestFile(SHA256, 32, "tests/sha256");
	checkDigestFile(SHA224, 28, "tests/sha224");
	checkDigestFile(SHA512, 64, "tests/sha512");
	checkDigestFile(SHA384, 48, "tests/sha384");
	return 0;
*/

	// stdin digest
/*
	uint8_t result[20];
	DIGEST_FILE(stdin, SHA1, result);
	for (uint8_t i = 0; i < 20; i++)
		printf("%.2x", result[i]);
	putchar('\n');
	return 0;
*/

	// DES
#define MSG_LEN 8
#define CIP_LEN MSG_LEN + 7-((MSG_LEN-1) % 8)
	uint8_t mode = CIPHER_ENC_AES256 | CIPHER_MODE_ECB;
/*
	const uint8_t* R = (const uint8_t*) "\x81\x02\x03\x04\xAB\xCD\xEF\x12";
	const uint8_t* K = (const uint8_t*) "\x01\x02\x03\x04\x45\x23\x12\x78";
	const uint8_t* I = (const uint8_t*) "\x34\x42\x42\x42\x17\x17\x42\x42";
*/
	//for (uint8_t i = 0; i < MSG_LEN; i++)
	//	printf("%.2X", R[i]);
	//putchar('\n');

	uint8_t O1[CIP_LEN];
	const uint8_t* R = (const uint8_t*) "\x81\x02\x03\x04\xAB\xCD\xEF\x12";
	const uint8_t* I = (const uint8_t*) "\x34\x42\x42\x42\x17\x17\x42\x42";
/*
	const uint8_t K[16] =
	{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
*/
/*
	const uint8_t K[24] =
	{
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
		0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
	};
*/
	const uint8_t K[32] =
	{
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
	};
	Crypt(O1, R, MSG_LEN, mode, K, I);
	//for (uint8_t i = 0 < CIP_LEN; i++)
	//	printf("%.2X", O1[i]);
	//putchar('\n');

/*
	uint8_t O2[MSG_LEN];
	Decrypt(O2, O1, CIP_LEN, mode, K, I);
	//for (uint8_t i = 0; i < MSG_LEN; i++)
	//	printf("%.2X", O2[i]);
	//putchar('\n');
*/

	return 0;
}
