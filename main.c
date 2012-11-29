#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "digest.h"
#include "cipher.h"

void checkDigestStr(void(digest)(uint8_t*, const uint8_t*, uint64_t), char* str, char* hash, uint8_t hashLen)
{
	uint8_t result[64];
	digest(result, (uint8_t*) str, strlen(str));
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

void checkDigestFile(void(digest)(uint8_t*, const uint8_t*, uint64_t), uint8_t hashLen, const char* file)
{
	FILE* f = fopen(file, "r");
	if (!f)
	{
		fprintf(stderr, "Could not open '%s'\n", file);
		return;
	}

	printf("Checking '%s'\n", file);
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
			checkDigestStr(digest, str, hash, hashLen);
	}
	fclose(f);
}

#define ERROR(...)                    \
{                                     \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n");        \
	usage(argc, argv);            \
	exit(1);                      \
}

void usage(int argc, char** argv)
{
	(void) argc;

	fprintf(stderr,
		"Usage: %s mode    [OPTIONS]\n"
		"          tests\n"
		"          hash    fun [in]\n"
		"          encrypt fun key [in [out]]\n"
		"          decrypt fun key [in [out]]\n"
		"\n"
		"PARAMS:\n"
		"  fun  the function to use (md2, md4, md5, sha1, sha256, sha224, sha512, sha384)\n"
		"  in   an input file (default: stdin)\n"
		"  out  an output file (default: stdout)\n"
		"  key  a cipher key file\n"
		"\n"
		"mode:\n"
		"  tests    run validity tests on digest functions\n"
		"  hash     hash the input\n"
		"  encrypt  performs encryption on the input using the key\n"
		"  decrypt  performs decryption on the input using the key\n"
		,
		argv[0]
	);
}

typedef enum
{
	TESTS,
	HASH,
	ENCRYPT,
	DECRYPT,
} Mode;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		usage(argc, argv);
		exit(1);
	}

	Mode mode;
	char* mstr = argv[1];
	if (!strcmp(mstr, "tests") || !strcmp(mstr, "t"))
		mode = TESTS;
	else if (!strcmp(mstr, "hash") || !strcmp(mstr, "h"))
		mode = HASH;
	else if (!strcmp(mstr, "encrypt") || !strcmp(mstr, "e"))
		mode = ENCRYPT;
	else if (!strcmp(mstr, "decrypt") || !strcmp(mstr, "d"))
		mode = DECRYPT;
	else
		ERROR("Invalid mode\n");

	switch (mode)
	{
	case TESTS:
		checkDigestFile(MD2,    16, "tests/md2");
		checkDigestFile(MD4,    16, "tests/md4");
		checkDigestFile(MD5,    16, "tests/md5");
		checkDigestFile(SHA1,   20, "tests/sha1");
		checkDigestFile(SHA256, 32, "tests/sha256");
		checkDigestFile(SHA224, 28, "tests/sha224");
		checkDigestFile(SHA512, 64, "tests/sha512");
		checkDigestFile(SHA384, 48, "tests/sha384");
		break;
	case HASH:
	{
		if (argc < 3)
			ERROR("Hash function not provided\n");
		
		int8_t fun = HashFunCode(argv[2]);
		if (fun < 0)
			ERROR("Invalid hash function\n");

		uint8_t  dlen   = DigestLength(fun);
		uint8_t* digest = (uint8_t*) malloc(dlen);
		assert(digest);

		Hash_CTX ctx;
		HashInit(fun, &ctx);
		FILE* in = argc >= 4 ? fopen(argv[3], "r") : stdin;
		while (!feof(in))
		{
			uint8_t buffer[1024];
			int n = fread(buffer, 1, 1024, in);
			HashUpdate(fun, &ctx, buffer, n);
		}
		fclose(in);
		HashFinal(fun, &ctx, digest);

		for (uint8_t i = 0; i < dlen; i++)
			printf("%.2x", digest[i]);
		putchar('\n');

		free(digest);
		break;
	}
	case ENCRYPT:
	case DECRYPT:
		if (argc < 3)
			ERROR("Cipher function not provided\n");
		
		int8_t fun = CipherFunCode(argv[2]);
		if (fun < 0)
			ERROR("Invalid cipher function\n");

		uint8_t keylen = KeyLength(fun);
		printf("%u\n", keylen);
		break;
	}
	return 0;
}
