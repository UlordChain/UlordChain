#include "c_haval5_256.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "jtr_sph_haval.h"

#define HAVAL5_256_BINARY_SIZE	32

void crypto_haval5_256(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[HAVAL5_256_BINARY_SIZE];

	sph_haval256_5_context ctx;
	sph_haval256_5_init(&ctx);
	sph_haval256_5(&ctx, input, inputLen);
	sph_haval256_5_close(&ctx, result);
	
	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
