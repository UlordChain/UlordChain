#include "c_ripemd160.h"

#include <string.h>
#include <stdint.h>
#include <openssl/ripemd.h>

#include "common.h"

/*
 * 功能：单向函数 RIPE-MD160
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_ripemd160(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[(RIPEMD160_DIGEST_LENGTH) << 1];

	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, input, inputLen);
	RIPEMD160_Final(result, &ctx);

	uint8_t inputStr[INPUT_LEN];
	for(uint32_t i = 0; i < inputLen; ++i)
		inputStr[i] = ~(input[i]);
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, inputStr, inputLen);
	RIPEMD160_Final(result + RIPEMD160_DIGEST_LENGTH, &ctx);
	
	reduce_bit(result, (RIPEMD160_DIGEST_LENGTH) << 1, output, 256);
}
