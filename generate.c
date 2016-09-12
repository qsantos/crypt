#include <stdio.h>
#include <string.h>

#include "md5.h"

static const char* charset = "0123456789abcdefghijklmnopqrstuvwxyz";
static size_t charset_length = 36;

static size_t get_key(char* dst, size_t length, size_t index) {
    for (size_t i = length; i --> 0; ) {
        dst[i] = charset[index % charset_length];
        index /= charset_length;
    }
    return index;
}

int main(int argc, char** argv) {
    uint32_t count = 0;
    char buffer[1024];
    size_t index = 0;
    while (1) {
        // get next key
        size_t length;
        if (argc == 1) {
            fgets((char*) buffer, sizeof(buffer), stdin);
            if (feof(stdin)) {
                break;
            }
            char* eol = strchr(buffer, '\n');
            length = (size_t) (eol - buffer);
        } else {
            length = 4;
            if (get_key((char*) buffer, length, index) != 0) {
                break;
            }
            index += 1;
        }

        // hash key
        uint8_t digest[16];
        md5(digest, (uint8_t*) buffer, length);

        // output hash and key
        fwrite(digest, 16, 1, stdout);
        fwrite(&count, 4, 1, stdout);

        count += 1;
    }

    return 0;
}
