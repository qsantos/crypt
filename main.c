/*\
 *  This is an awesome programm simulating awesome battles of awesome robot tanks
 *  Copyright (C) 2012-2013 Quentin SANTOS
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "hash.h"
#include "cipher.h"

static void checkDigestFile(uint8_t mode, const char* file)
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
		{
			uint8_t result[64];
			Hash(mode, result, (uint8_t*) str, strlen(str));
			uint32_t hashLen = DigestLength(mode);
			for (uint8_t i = 0; i < hashLen; i++)
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

static void usage(int argc, char** argv)
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
		checkDigestFile(HASH_MD2,    "tests/md2");
		checkDigestFile(HASH_MD4,    "tests/md4");
		checkDigestFile(HASH_MD5,    "tests/md5");
		checkDigestFile(HASH_SHA1,   "tests/sha1");
		checkDigestFile(HASH_SHA256, "tests/sha256");
		checkDigestFile(HASH_SHA224, "tests/sha224");
		checkDigestFile(HASH_SHA512, "tests/sha512");
		checkDigestFile(HASH_SHA384, "tests/sha384");
		break;
	case HASH:
	{
		if (argc < 3) ERROR("Hash function not provided\n");
		char* filename = argc >= 4 ? argv[3] : NULL;
		
		int8_t fun = HashFunCode(argv[2]);
		if (fun < 0) ERROR("Invalid hash function\n");

		uint8_t  dlen   = DigestLength(fun);
		uint8_t* digest = (uint8_t*) malloc(dlen);
		assert(digest);

		Hash_CTX ctx;
		HashInit(fun, &ctx);
		FILE* in = filename ? fopen(filename, "r") : stdin;
		if (!in) ERROR("Could not open input file\n");

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
		printf("  %s\n", filename ? filename : "-");

		free(digest);
		break;
	}
	case ENCRYPT:
	case DECRYPT:
		if (argc < 3) ERROR("Cipher function not provided\n");
		if (argc < 4) ERROR("Key file must be provided\n");
		char* filein  = argc >= 5 ? argv[4] : NULL;
		char* fileout = argc >= 6 ? argv[5] : NULL;

		// get cipher code
		int8_t fun = CipherFunCode(argv[2]);
		if (fun < 0) ERROR("Invalid cipher function\n");

		// load key
		uint8_t keylength = KeyLength(fun);
		uint8_t* key = malloc(keylength);
		assert(key);
		FILE* k = fopen(argv[3], "r");
		if (!k) ERROR("Could not load key from file\n");
		int r = fread(key, 1, keylength, k);
		fclose(k);
		if (r != keylength) ERROR("Not enough bytes in key file\n");
		printf("Key loaded (%i) bits\n", 8*keylength);

		// initialize input and output
		FILE* in = filein ? fopen(filein, "r") : stdin;
		if (!in) ERROR("Could not open input file\n");
		FILE* out = fileout ? fopen(fileout, "w") : stdout;
		if (!out) ERROR("Could not open output file\n");
		uint8_t blocksize = CipherBlockSize(fun);
		uint32_t bufsz = 16*blocksize;
		uint8_t* bufin  = malloc(bufsz); assert(in);
		uint8_t* bufout = malloc(bufsz); assert(out);

		// proceed to encryption/decryption
		bool decrypt = mode == DECRYPT;
		if (decrypt)
			printf("Deciphering in progress...\n");
		else
			printf("Enciphering in progress...\n");
		Cipher_CTX ctx;
		CipherInit(&ctx, fun, key, NULL);
		free(key);
		while (!feof(in))
		{
			r = fread(bufin, 1, bufsz, in);
			r = CipherUpdate(&ctx, bufout, bufin, r, decrypt);
			fwrite(bufout, 1, r, out);
		}
		r = CipherFinal(&ctx, bufout, decrypt);
		fwrite(bufout, 1, r, out);

		free(bufout);
		free(bufin);
		fclose(out);
		fclose(in);
		break;
	}
	return 0;
}
