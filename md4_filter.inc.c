/*\
 * This is the central part of MD4. The following code handles one block of the
 * input. OP is a target-dependent macro that executes one step of MD4. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of MD4. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#include "md4_filter.h"

#include "keyspace.h"

#ifndef MD4_INIT
#define MD4_INIT(A, B, C, D) do { \
    A = SET1(0x67452301); \
    B = SET1(0xEFCDAB89); \
    C = SET1(0x98BADCFE); \
    D = SET1(0x10325476); \
} while (0)
#endif

#ifndef MD4_F
#define MD4_F(X,Y,Z) OR(AND(X, Y), ANDNOT(X, Z))
#endif

#ifndef MD4_G
#define MD4_G(X,Y,Z) OR(AND(X, Y), OR(AND(X, Z), AND(Y, Z)))
#endif

#ifndef MD4_H
#define MD4_H(X,Y,Z) XOR(Y, XOR(X, Z))
#endif

#ifndef MD4_OP1
#define MD4_OP1(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_F(b,c,d), X[k])); a = ROL(tmp, s); } while (0)
#endif

#ifndef MD4_OP2
#define MD4_OP2(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_G(b,c,d), ADD(X[k], SET1(0x5A827999)))); a = ROL(tmp, s); } while (0)
#endif

#ifndef MD4_OP3
#define MD4_OP3(a,b,c,d,k,s) do { WORD tmp = ADD(a, ADD(MD4_H(b,c,d), ADD(X[k], SET1(0x6ED9EBA1)))); a = ROL(tmp, s); } while (0)
#endif

#ifndef MD4_BLOCK
#define MD4_BLOCK( \
        BLOCK, /* WORD*: the block to be processed */ \
        A,B,C,D, /* WORD: the 128 bit state of MD4 */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    WORD* X = (WORD*) BLOCK; \
    \
    MD4_OP1(A,B,C,D,  0, 3); MD4_OP1(D,A,B,C,  1, 7); MD4_OP1(C,D,A,B,  2,11); MD4_OP1(B,C,D,A,  3,19); \
    MD4_OP1(A,B,C,D,  4, 3); MD4_OP1(D,A,B,C,  5, 7); MD4_OP1(C,D,A,B,  6,11); MD4_OP1(B,C,D,A,  7,19); \
    MD4_OP1(A,B,C,D,  8, 3); MD4_OP1(D,A,B,C,  9, 7); MD4_OP1(C,D,A,B, 10,11); MD4_OP1(B,C,D,A, 11,19); \
    MD4_OP1(A,B,C,D, 12, 3); MD4_OP1(D,A,B,C, 13, 7); MD4_OP1(C,D,A,B, 14,11); MD4_OP1(B,C,D,A, 15,19); \
    \
    MD4_OP2(A,B,C,D,  0, 3); MD4_OP2(D,A,B,C,  4, 5); MD4_OP2(C,D,A,B,  8, 9); MD4_OP2(B,C,D,A, 12,13); \
    MD4_OP2(A,B,C,D,  1, 3); MD4_OP2(D,A,B,C,  5, 5); MD4_OP2(C,D,A,B,  9, 9); MD4_OP2(B,C,D,A, 13,13); \
    MD4_OP2(A,B,C,D,  2, 3); MD4_OP2(D,A,B,C,  6, 5); MD4_OP2(C,D,A,B, 10, 9); MD4_OP2(B,C,D,A, 14,13); \
    MD4_OP2(A,B,C,D,  3, 3); MD4_OP2(D,A,B,C,  7, 5); \
} while (0)
#endif

extern int do_generate_passwords;

#define APPEND(PREFIX, SUFFIX) PREFIX##SUFFIX
// append together the *values* of the macros, rather than their names
#define APPEND_VALUE(PREFIX, SUFFIX) APPEND(PREFIX, SUFFIX)

// md4_filterone_*
__attribute__((target(TARGET_ID)))
#define FUNCTION_NAME APPEND_VALUE(md4_filterone_, TARGET_SUFFIX)
size_t FUNCTION_NAME(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count) {
#undef FUNCTION_NAME
    size_t stride = sizeof(WORD) / 4;
    size_t n_iterations = (count + stride - 1) / stride;  /* ceil(count / stride) */

    /* prepare block */
    uint8_t block[64*stride];
    const char* ptrs[64*stride];
    md4_pad(block, length, stride);
    set_keys(block, ptrs, length, stride, start, n_iterations);

    size_t n_candidates = 0;
    for (size_t i = 0; i < n_iterations; i += 1) {
        WORD A, B, C, D;
        MD4_INIT(A, B, C, D);
        MD4_BLOCK(block, A,B,C,D, 64);

        if (ANY_EQ(D, filter)) {
            uint32_t* hashes = (uint32_t*) &D;
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
