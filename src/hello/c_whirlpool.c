#include "c_whirlpool.h"

#include <string.h>
#include <stdint.h>
#include <openssl/whrlpool.h>

#include "common.h"

/*
 * 功能：单向函数 Whirlpool
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_whirlpool(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[WHIRLPOOL_DIGEST_LENGTH];

	WHIRLPOOL_CTX ctx;
	WHIRLPOOL_Init(&ctx);
	WHIRLPOOL_Update(&ctx, input, inputLen);
	WHIRLPOOL_Final(result, &ctx);

	reduce_bit(result, WHIRLPOOL_DIGEST_LENGTH, output, 256);
}