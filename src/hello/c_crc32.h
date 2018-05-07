#ifndef C_CRC32_H
#define C_CRC32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * 功能：单向函数 CRC32
	 * 输入：1. input ：输入消息
	 *		 2. output：输出结果
	*/
	void CRC32_Table_Init();
	void crypto_crc32(uint8_t *input, uint32_t inputLen, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif
