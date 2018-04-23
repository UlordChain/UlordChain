#include "c_sha3_256.h"

#include <stdint.h>
#include <string.h>

#include "keccak1600.h"
#include "common.h"

// SHA3-256
void crypto_sha3_256(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	unsigned char result[OUTPUT_LEN];
	
	KECCAK1600_CTX ctx;
	sha3_init(&ctx, ((1600-512)/8), 256/8);
	sha3_update(&ctx, input, inputLen);
	sha3_final(&ctx, result);
	
	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}

int sha3_init(KECCAK1600_CTX *ctx, size_t block_size, size_t md_size)
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

int sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len)

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


int sha3_final(KECCAK1600_CTX *ctx, unsigned char *md)
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
