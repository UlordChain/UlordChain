#include "c_skein512_256.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "jtr_sph_skein.h"

#define SKEIN512_256_BINARY_SIZE	32

void crypto_skein512_256(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[SKEIN512_256_BINARY_SIZE];

	sph_skein256_context ctx;
	sph_skein256_init(&ctx);
	sph_skein256(&ctx, input, inputLen);
	sph_skein256_close(&ctx, result);
	
	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
