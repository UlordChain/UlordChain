#include "c_whirlpool.h"

#include <string.h>
#include <stdint.h>
#include <openssl/whrlpool.h>

#include "common.h"

/*
     * FUNCTION: one-way function Whirlpool
     *      1. input : input message, msglength
     *		2. output: Whirlpool message
*/
void crypto_whirlpool(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[WHIRLPOOL_DIGEST_LENGTH];

	WHIRLPOOL_CTX ctx;
	WHIRLPOOL_Init(&ctx);
	WHIRLPOOL_Update(&ctx, input, inputLen);
	WHIRLPOOL_Final(result, &ctx);

	reduce_bit(result, WHIRLPOOL_DIGEST_LENGTH, output, 256);
}