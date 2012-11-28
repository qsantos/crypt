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
	uint8_t mode = CIPHER_ENC_AES128 | CIPHER_MODE_ECB;

	const uint8_t K[16] =
	{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	const uint8_t R[16] =
	{
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
	};

	uint8_t O1[16];
	Crypt(O1, R, 16, mode, K, NULL);
	for (uint8_t i = 0; i < 16; i++)
		printf("%.2x", O1[i]);
	putchar('\n');

/*
	uint8_t O2[MSG_LEN];
	Decrypt(O2, O1, CIP_LEN, mode, K, I);
	//for (uint8_t i = 0; i < MSG_LEN; i++)
	//	printf("%.2X", O2[i]);
	//putchar('\n');
*/

	return 0;
}
