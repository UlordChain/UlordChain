#ifndef C_GOST_H
#define C_GOST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * 功能：单向函数 GOST R 34.11-94
	 * 输入：1. input ：输入消息
	 *		 2. output：输出结果
	*/
	void gost_init_table(void);
	void crypto_gost(uint8_t *input, uint32_t inputLen, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif
