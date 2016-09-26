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

#define SHA1_GENERATE(TARGET, PREFIX) \
    __attribute__((target(TARGET))) \
    void sha1_oneblock_##PREFIX(uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E; \
        SHA1_INIT(A, B, C, D, E); \
        SHA1_BLOCK(block, A,B,C,D,E, 64); \
        \
        WORD* Y = (WORD*) digest; \
        Y[0] = BSWAP(A); \
        Y[1] = BSWAP(B); \
        Y[2] = BSWAP(C); \
        Y[3] = BSWAP(D); \
        Y[4] = BSWAP(E); \
    } \
    \
    __attribute__((target(TARGET))) \
    int sha1_test_##PREFIX(const uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E; \
        SHA1_INIT(A, B, C, D, E); \
        SHA1_BLOCK(block, A,B,C,D,E, 64); \
        \
        return ANY_EQ(A, *(uint32_t*) digest); \
    } \

