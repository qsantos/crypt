/*\
 * This is the central part of SHA1. The following code handles one block of
 * the input. OP is a target-dependent macro that executes one step of SHA1. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D, E) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of SHA1. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#include "sha1_filter.h"

#include "keyspace.h"

#ifndef SHA1_INIT
#define SHA1_INIT(A, B, C, D, E) do { \
    A = SET1(0x67452301); \
    B = SET1(0xEFCDAB89); \
    C = SET1(0x98BADCFE); \
    D = SET1(0x10325476); \
    E = SET1(0xC3D2E1F0); \
} while (0)
#endif

#ifndef SHA1_F
#define SHA1_F(B,C,D) OR(AND(B, C), ANDNOT(B, D))
#endif

#ifndef SHA1_G
#define SHA1_G(B,C,D) XOR(B, XOR(C, D))
#endif

#ifndef SHA1_H
#define SHA1_H(B,C,D) OR(AND(B, C), OR(AND(B, D), AND(C, D)))
#endif

#ifndef SHA1_OP
#define SHA1_OP(f,A,B,C,D,t,K) do { \
    WORD tmp = ADD(ROL(A,5), ADD(f(B,C,D), ADD(E, ADD(W[t], SET1(K))))); \
    E = D; D = C; C = ROL(B, 30); B = A; A = tmp; \
} while (0)
#endif

#ifndef SHA1_BLOCK
#define SHA1_BLOCK( \
        BLOCK, /* the block to be processed */ \
        A,B,C,D,E, /* WORD: the 160 bit state of SHA1 */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    WORD* X = (WORD*) BLOCK; \
    WORD W[80]; \
    \
    WORD previous_A = A; \
    WORD previous_B = B; \
    WORD previous_C = C; \
    WORD previous_D = D; \
    WORD previous_E = E; \
    \
    for (int t =  0; t < 16; t += 1) { \
        W[t] = BSWAP(X[t]); \
        SHA1_OP(SHA1_F,A,B,C,D,t,0x5A827999); \
    } \
    for (int t = 16; t < 20; t += 1) { \
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
        SHA1_OP(SHA1_F,A,B,C,D,t,0x5A827999); \
    } \
    for (int t = 20; t < 40; t += 1) { \
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
        SHA1_OP(SHA1_G,A,B,C,D,t,0x6ED9EBA1); \
    } \
    for (int t = 40; t < 60; t += 1) { \
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
        SHA1_OP(SHA1_H,A,B,C,D,t,0x8F1BBCDC); \
    } \
    for (int t = 60; t < 80; t += 1) { \
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
        SHA1_OP(SHA1_G,A,B,C,D,t,0xCA62C1D6); \
    } \
    \
    A = ADD(A, previous_A); \
    B = ADD(B, previous_B); \
    C = ADD(C, previous_C); \
    D = ADD(D, previous_D); \
    E = ADD(E, previous_E); \
} while (0)
#endif

extern int do_generate_passwords;

#define APPEND(PREFIX, SUFFIX) PREFIX##SUFFIX
// append together the *values* of the macros, rather than their names
#define APPEND_VALUE(PREFIX, SUFFIX) APPEND(PREFIX, SUFFIX)

// sha1_filterone_*
__attribute__((target(TARGET_ID)))
#define FUNCTION_NAME APPEND_VALUE(sha1_filterone_, TARGET_SUFFIX)
size_t FUNCTION_NAME(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count) {
#undef FUNCTION_NAME
    size_t stride = sizeof(WORD) / 4;
    size_t n_iterations = (count + stride - 1) / stride;  /* ceil(count / stride) */

    /* prepare block */
    uint8_t block[64*stride];
    const char* ptrs[64*stride];
    sha1_pad(block, length, stride);
    set_keys(block, ptrs, length, stride, start, n_iterations);

    size_t n_candidates = 0;
    for (size_t i = 0; i < n_iterations; i += 1) {
        WORD A, B, C, D, E;
        SHA1_INIT(A, B, C, D, E);
        SHA1_BLOCK(block, A,B,C,D,E, 64);

        if (ANY_EQ(A, filter)) {
            uint32_t* hashes = (uint32_t*) &A;
            for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
                if (hashes[interleaf] != filter) {
                    continue;
                }
                candidates[n_candidates] = start + interleaf*n_iterations + i;
                n_candidates += 1;
                if (n_candidates >= size) {
                    return n_candidates;
                }
            }
        }

        if (do_generate_passwords) {
            next_keys(block, ptrs, length, stride);
        }
    }

    return n_candidates;
}
