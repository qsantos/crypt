#include <stdio.h>
#include <string.h>

#include "md5.h"

static const char* charset = "0123456789abcdefghijklmnopqrstuvwxyz";
static size_t charset_length = sizeof(charset) - 1;

static size_t get_key(char* dst, size_t length, size_t index) {
    for (size_t i = length; i --> 0; ) {
        dst[i] = charset[index % charset_length];
        index /= charset_length;
    }
    return index;
}

int main(int argc, char** argv) {
    uint8_t block[64];
    char buffer[1024];
    size_t buffer_i = 0;
    size_t index = 0;

    while (1) {
        // get next key
        size_t length;
        if (argc == 1) {
            fgets((char*) block, sizeof(block), stdin);
            if (feof(stdin)) {
                break;
            }
            char* eol = strchr((char*) block, '\n');
            length = (size_t) (eol - (char*) block);
            index += 1;
        } else {
            length = 4;
            if (get_key((char*) block, length, index) != 0) {
                break;
            }
            index += 1;
        }

        uint8_t digest[16];
        md5(digest, (uint8_t*) block, length);
        *(uint32_t*)(buffer + buffer_i + 16) = (uint32_t) index;
        buffer_i += 20;

        // output hash and key
        if (buffer_i > 900) {
            fwrite(buffer, buffer_i, 1, stdout);
            buffer_i = 0;
        }
    }

    return 0;
}
