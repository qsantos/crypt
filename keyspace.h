#ifndef KEYSPACE_H
#define KEYSPACE_H

#include "interleave.h"

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
static size_t charset_length = sizeof(charset) - 1;

static inline int key_index(const char* key, size_t* ret) {
    size_t index = 0;
    for (const char* c = key; *c; c += 1) {
        index *= charset_length;
        char* pos = strchr(charset, *c);
        if (pos == NULL) {
            return -1;
        }
        index += (size_t) (pos - charset);
    }
    *ret = index;
    return 0;
}

static inline size_t get_key(char* dst, size_t length, size_t index) {
    for (size_t i = length; i --> 0; ) {
        dst[i] = charset[index % charset_length];
        index /= charset_length;
    }
    return index;
}

static inline void set_key_im(uint8_t* block, const char* key, size_t stride) {
    size_t length = strlen(key);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        interleave(block, (uint8_t*) key, length, stride, interleaf);
    }
}

static inline void set_keys(uint8_t* block, const char** ptrs, size_t length, size_t stride, size_t index, size_t index_stride) {
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t current_index = index + interleaf * index_stride;
        for (size_t i = length; i --> 0; ) {
            size_t offset = interleaved_offset(i, stride, interleaf);
            ptrs[offset] = &charset[current_index % charset_length];
            block[offset] = (uint8_t) *ptrs[offset];

            current_index /= charset_length;
        }
    }
}

static inline void next_keys(uint8_t* block, const char** ptrs, size_t length, size_t stride) {
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        for (size_t i = length; i --> 0; ) {
            size_t offset = interleaved_offset(i, stride, interleaf);
            ptrs[offset] += 1;
            // likely() does make a significant difference
            if (likely(*ptrs[offset] != '\0')) {
                block[offset] = (uint8_t) *ptrs[offset];
                break;
            } else {
                ptrs[offset] = charset;
                block[offset] = (uint8_t) *ptrs[offset];
            }
        }
    }
}

#endif
