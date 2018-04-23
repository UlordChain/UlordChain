#include "c_aes128.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "common.h"

/*
 * 功能：单向函数 AES128
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_aes128(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	/** 
	 *	$hash[0:31] = sha256($input)
	 *	$hash2[0:15] = md5($hash[0:31])
	 *  $key = aes128_set_key($hash2[0:15])
	 * 	$output[ 0:15] = aes128_encrypt($key, $hash[ 0:15])
	 * 	$output[16:31] = aes128_encrypt($key, $hash[16:31])
	**/
	uint8_t sha256Digest[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX sha256_ctx;
	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, input, inputLen);
	SHA256_Final(sha256Digest, &sha256_ctx);
	
	uint8_t md5Digest[MD5_DIGEST_LENGTH];
	
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, sha256Digest, SHA256_DIGEST_LENGTH);
	MD5_Final(md5Digest, &md5_ctx);
	
	AES_KEY akey;
	if(AES_set_encrypt_key(md5Digest, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_encrypt_key failed in crypt!\n");
		abort();
	}
	uint8_t result[SHA256_DIGEST_LENGTH];
	AES_encrypt(sha256Digest, result, &akey);
	AES_encrypt(sha256Digest + AES_BLOCK_SIZE, result + AES_BLOCK_SIZE, &akey);

	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
