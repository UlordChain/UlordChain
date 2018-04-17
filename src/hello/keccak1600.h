#ifndef KECCAK1600_H
#define KECCAK1600_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	extern size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r);
	extern void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);

#ifdef __cplusplus
}
#endif

#define KECCAK1600_WIDTH 1600

typedef struct {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t num;                 /* used bytes in below buffer */
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    unsigned char pad;
} KECCAK1600_CTX;

inline int sha3_init(KECCAK1600_CTX *ctx, size_t block_size, size_t md_size)
{
    size_t bsz = block_size;

    if (bsz <= sizeof(ctx->buf)) {
        memset(ctx->A, 0, sizeof(ctx->A));

        ctx->num = 0;
        ctx->block_size = bsz;
        ctx->md_size = md_size;
        ctx->pad = '\x06';

        return 1;
    }

    return 0;
}

inline int sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len)
{
    const unsigned char *inp = _inp;
    size_t bsz = ctx->block_size;
    size_t num, rem;

    if ((num = ctx->num) != 0) {      /* process intermediate buffer? */
        rem = bsz - num;

        if (len < rem) {
            memcpy(ctx->buf + num, inp, len);
            ctx->num += len;
            return 1;
        }
        /*
         * We have enough data to fill or overflow the intermediate
         * buffer. So we append |rem| bytes and process the block,
         * leaving the rest for later processing...
         */
        memcpy(ctx->buf + num, inp, rem);
        inp += rem, len -= rem;
        (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        ctx->num = 0;
        /* ctx->buf is processed, ctx->num is guaranteed to be zero */
    }

    if (len >= bsz)
        rem = SHA3_absorb(ctx->A, inp, len, bsz);
    else
        rem = len;

    if (rem) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->num = rem;
    }

    return 1;
}

inline int sha3_final(KECCAK1600_CTX *ctx, unsigned char *md)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->num;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + num, 0, bsz - num);
    ctx->buf[num] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, md, ctx->md_size, bsz);

    return 1;
}

#endif