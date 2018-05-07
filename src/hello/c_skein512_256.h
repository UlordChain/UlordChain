#ifndef C_SKEIN512_256_H
#define C_SKEIN512_256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * 功能：单向函数 Skein-512(256bits)
	 * 输入：1. input ：输入消息
	 *		 2. output：输出结果
	*/
	void crypto_skein512_256(uint8_t *input, uint32_t inputLen, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif
