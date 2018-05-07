#include "c_des.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

#include "common.h"

#define DES_BLOCK_SIZE 8

/*
 * 功能：单向函数 des
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_des(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	/** 
	 *	$hash[0:31] = sha256($input)
	 *	$hash2[0:15] = md5($hash[0:31])
	 *  $key = DES_set_key_unchecked($hash2[0:15])
	 * 	$output[ 0: 7] = DES_encrypt($key, $hash[ 0: 7])
	 * 	$output[ 8:15] = DES_encrypt($key, $hash[ 8:15])
	 * 	$output[16:23] = DES_encrypt($key, $hash[16:23])
	 * 	$output[24:31] = DES_encrypt($key, $hash[24:31])
	**/
	uint8_t sha256Digest[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, inputLen);
	SHA256_Final(sha256Digest, &ctx);

	uint8_t md5Digest[MD5_DIGEST_LENGTH];
	
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, sha256Digest, SHA256_DIGEST_LENGTH);
	MD5_Final(md5Digest, &md5_ctx);
	
	uint8_t result[OUTPUT_LEN];
	
	DES_key_schedule akey;
	DES_set_key_unchecked((const_DES_cblock *)md5Digest, &akey);
	DES_ecb_encrypt((const_DES_cblock *)sha256Digest, (const_DES_cblock *)result, &akey, DES_ENCRYPT);
	DES_ecb_encrypt((const_DES_cblock *)(sha256Digest+DES_BLOCK_SIZE), (const_DES_cblock *)(result+DES_BLOCK_SIZE), &akey, DES_ENCRYPT);
	DES_ecb_encrypt((const_DES_cblock *)(sha256Digest+2*DES_BLOCK_SIZE), (const_DES_cblock *)(result+2*DES_BLOCK_SIZE), &akey, DES_ENCRYPT);
	DES_ecb_encrypt((const_DES_cblock *)(sha256Digest+3*DES_BLOCK_SIZE), (const_DES_cblock *)(result+3*DES_BLOCK_SIZE), &akey, DES_ENCRYPT);

	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
