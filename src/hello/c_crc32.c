#include "c_crc32.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "common.h"
#include "jtr_crc32.h"

/*
 * 功能：单向函数 crc32
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_crc32(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	/** 
	 *	$hash[0:31] = sha256($input)
	 * 	$output[0:31] = crc32($hash[0:31]), crc by word
	**/
	uint8_t sha256Digest[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, inputLen);
	SHA256_Final(sha256Digest, &ctx);

	CRC32_t crc;
	for (uint32_t i = 0; i < SHA256_DIGEST_LENGTH; i += 4) {
		CRC32_Init(&crc);
		CRC32_Update(&crc, &sha256Digest[i], 4);
		CRC32_Final(&output[i], crc);
	}
}