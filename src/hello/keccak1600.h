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

int sha3_init(KECCAK1600_CTX *ctx, size_t block_size, size_t md_size);

int sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len);

int sha3_final(KECCAK1600_CTX *ctx, unsigned char *md);
#endif
