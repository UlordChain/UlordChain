#include "sha3_256.h"

#include <stdint.h>
#include <string.h>

#include "keccak1600.h"
#include "common.h"

// SHA3-256
void sha3_256(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	unsigned char result[OUTPUT_LEN];
	
	KECCAK1600_CTX ctx;
	sha3_init(&ctx, ((1600-512)/8), 256/8);
	sha3_update(&ctx, input, inputLen);
	sha3_final(&ctx, result);
	
	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
