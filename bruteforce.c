#ifdef _OPENMP  // TODO
#include <omp.h>
#endif

#include <stdio.h>
#include <string.h>

#include "util.h"
#include "keyspace.h"
#include "md5_simd.h"

int main() {
    uint8_t target[16];
    bytes_fromhex(target, "e80b5017098950fc58aad83c8c14978e");  // abcdef

    size_t length = 6;

    size_t count = 1;
    for (size_t i = 0; i < length; i += 1) {
        count *= charset_length;
    }

    size_t stride = 8;

    #pragma omp parallel
    {
        size_t thread_id = (size_t) omp_get_thread_num();
        size_t n_threads = (size_t) omp_get_num_threads();
        size_t count_per_thread = count / n_threads;
        size_t start = count_per_thread * thread_id;
        fprintf(stderr, "Started thread no %zu / %zu <- keyspace[%zu:%zu]\n",
               thread_id, n_threads, start, start + count);

        uint8_t block[1024] __attribute__((aligned(32)));
        uint8_t interleaved[128];
        const char* ptrs[1024];
        size_t index_stride = (count_per_thread + stride - 1) / stride;
        md5_pad(block, length, stride);
        set_keys(block, ptrs, length, stride, start, index_stride);

        size_t n_iterations = (count_per_thread + stride - 1) / stride;
        for (size_t i = 0; i < n_iterations; i += 1) {
            // check whether any of the interleaved candidates match
            if (md5_test_avx2(target, block)) {
                // if so, re-compute the full hash (happens rarely enough)
                // and redo a full comparison
                md5_oneblock_avx2(interleaved, block);
                for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
                    uint8_t digest[16];
                    uninterleave(digest, interleaved, 16, stride, interleaf);
                    if (bstrncmp(digest, target, 16) != 0) {
                        // not an actuall match
                        continue;
                    }

                    // the hash completely matches the target
                    char buffer[length+1];
                    size_t index = start + interleaf*index_stride + i;
                    get_key(buffer, length, index);
                    buffer[length] = '\0';
                    printf("%s\n", buffer);
                }
            }

            // proceed to next candidate
            next_keys(block, ptrs, length, stride);
        }
    }

    return 0;
}
