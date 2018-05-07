#include "c_gost.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "jtr_gost.h"

#define GOST_BINARY_SIZE	32

/*
 * 功能：单向函数 GOST R 34.11-94
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_gost(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t result[GOST_BINARY_SIZE];

	gost_ctx ctx;
	john_gost_init(&ctx);
	john_gost_update(&ctx, input, inputLen);
	john_gost_final(&ctx, result);
	
	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}