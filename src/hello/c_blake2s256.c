#include "c_blake2s256.h"

#include <stdint.h>
#include <string.h>
#include "blake2s.h"

#include "common.h"

void crypto_blake2s256(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[BLAKE2S_OUTBYTES];
	
	BLAKE2S_CTX ctx;
	BLAKE2s_Init(&ctx);
	BLAKE2s_Update(&ctx, input, inputLen);
	BLAKE2s_Final(result, &ctx);

	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
