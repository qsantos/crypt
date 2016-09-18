/*\
 *  Insecure implementation of some cryptographic primitives
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

#define _XOPEN_SOURCE 700 // for getline()
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "hash.h"
#include "cipher.h"

static void check_digest_against_file(uint8_t mode, const char* file) {
    FILE* f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "Could not open '%s'\n", file);
        return;
    }

    printf("Checking '%s'\n", file);
    char* line = NULL;
    size_t n_line = 0;
    while (1) {
        getline(&line, &n_line, f);
        if (feof(f)) {
            break;
        }
        char* digest = strtok(line, " ");
        char* str  = strtok(NULL, "\n");
        if (digest && str) {
            uint8_t result[64];
            hash(mode, result, (uint8_t*) str, strlen(str));
            int length = digest_length(mode);
            for (int i = 0; i < length; i += 1) {
                char digit[3];
                snprintf(digit, 3, "%.2x", result[i]);
                if (digit[0] != digest[2*i] || digit[1] != digest[2*i+1]) {
                    printf("'%s' got wrong hash\n", str);
                    break;
                }
            }
        }
    }
    fclose(f);
}

#define ERROR(...) { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    usage(argc, argv); \
    exit(1); \
}

static void usage(int argc, char** argv) {
    (void) argc;

    fprintf(stderr,
        "Usage: %s mode    [OPTIONS]\n"
        "          tests\n"
        "          hash    function [in]\n"
        "          encrypt function key [in [out]]\n"
        "          decrypt function key [in [out]]\n"
        "\n"
        "PARAMS:\n"
        "  function  the function to use (ctx, ctx, ctx, ctx, ctx, ctx, ctx, ctx)\n"
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

typedef enum {
    TESTS,
    HASH,
    ENCRYPT,
    DECRYPT,
} Mode;

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argc, argv);
        exit(1);
    }

    Mode mode;
    char* mstr = argv[1];
    if (!strcmp(mstr, "tests") || !strcmp(mstr, "t")) {
        mode = TESTS;
    } else if (!strcmp(mstr, "hash") || !strcmp(mstr, "h")) {
        mode = HASH;
    } else if (!strcmp(mstr, "encrypt") || !strcmp(mstr, "e")) {
        mode = ENCRYPT;
    } else if (!strcmp(mstr, "decrypt") || !strcmp(mstr, "d")) {
        mode = DECRYPT;
    } else {
        ERROR("Invalid mode\n");
    }

    switch (mode) {
    case TESTS:
        check_digest_against_file(HASH_MD2, "tests/md2");
        check_digest_against_file(HASH_MD4, "tests/md4");
        check_digest_against_file(HASH_MD5, "tests/md5");
        check_digest_against_file(HASH_SHA1, "tests/sha1");
        check_digest_against_file(HASH_SHA256, "tests/sha256");
        check_digest_against_file(HASH_SHA224, "tests/sha224");
        check_digest_against_file(HASH_SHA512, "tests/sha512");
        check_digest_against_file(HASH_SHA384, "tests/sha384");
        break;
    case HASH: {
        if (argc < 3) {
            ERROR("hash function not provided\n");
        }
        char* filename = argc >= 4 ? argv[3] : NULL;

        int8_t _function = hash_function_code(argv[2]);
        if (_function < 0) {
            ERROR("Invalid hash function\n");
        }
        uint8_t function = (uint8_t) _function;

        uint8_t dlen = digest_length(function);
        uint8_t* digest = (uint8_t*) malloc(dlen);
        assert(digest);

        HashContext ctx;
        hash_init(function, &ctx);
        FILE* in = filename ? fopen(filename, "r") : stdin;
        if (!in) {
            ERROR("Could not open input file\n");
        }

        while (!feof(in)) {
            uint8_t buffer[1024];
            size_t n = fread(buffer, 1, 1024, in);
            hash_update(function, &ctx, buffer, n);
        }
        fclose(in);
        hash_final(function, &ctx, digest);

        for (int i = 0; i < dlen; i += 1) {
            printf("%.2x", digest[i]);
        }

        printf("  %s\n", filename ? filename : "-");

        free(digest);
        break;
    }
    case ENCRYPT:
    case DECRYPT:
        if (argc < 3) {
            ERROR("cipher function not provided\n");
        }
        if (argc < 4) {
            ERROR("Key file must be provided\n");
        }

        char* filein  = argc >= 5 ? argv[4] : NULL;
        char* fileout = argc >= 6 ? argv[5] : NULL;

        // get cipher code
        int8_t _function = cipher_function_code(argv[2]);
        if (_function < 0) {
            ERROR("Invalid cipher function\n");
        }
        uint8_t function = (uint8_t) _function;

        // load key
        uint8_t keylength = key_length(function);
        uint8_t* key = malloc(keylength);
        assert(key);
        FILE* k = fopen(argv[3], "r");
        if (!k) {
            ERROR("Could not load key from file\n");
        }
        size_t r = fread(key, 1, keylength, k);
        fclose(k);
        if (r != keylength) {
            ERROR("Not enough bytes in key file\n");
        }
        printf("Key loaded (%i) bits\n", 8*keylength);

        // initialize input and output
        FILE* in = filein ? fopen(filein, "r") : stdin;
        if (!in) {
            ERROR("Could not open input file\n");
        }
        FILE* out = fileout ? fopen(fileout, "w") : stdout;
        if (!out) {
            ERROR("Could not open output file\n");
        }
        uint8_t blocksize = cipher_blocksize(function);
        uint32_t bufsz = 16U * blocksize;
        uint8_t* bufin = malloc(bufsz); assert(in);
        uint8_t* bufout = malloc(bufsz); assert(out);

        // proceed to encryption/decryption
        bool decrypt = mode == DECRYPT;
        if (decrypt) {
            printf("Deciphering in progress...\n");
        } else {
            printf("Enciphering in progress...\n");
        }
        CipherContext ctx;
        cipher_init(&ctx, function, key, NULL);
        free(key);
        while (!feof(in)) {
            r = fread(bufin, 1, bufsz, in);
            r = cipher_update(&ctx, bufout, bufin, r, decrypt);
            fwrite(bufout, 1, r, out);
        }
        r = cipher_final(&ctx, bufout, decrypt);
        fwrite(bufout, 1, r, out);

        free(bufout);
        free(bufin);
        fclose(out);
        fclose(in);
        break;
    }
    return 0;
}
