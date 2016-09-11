#include <stdio.h>
#include <string.h>

#include "md5.h"

int main() {
    uint32_t count = 0;
    char buffer[1024];
    while (1) {
        // get next key
        fgets(buffer, sizeof(buffer), stdin);
        if (feof(stdin)) {
            break;
        }
        size_t length = (size_t) (strchr(buffer, '\n') - buffer);

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
