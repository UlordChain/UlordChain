// Copyright (c) 2016-2018 The Ulord Core Foundation
#include "c_rc4.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rc4.h>

#include "common.h"

/*
 * 功能：单向函数 RC4
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_rc4(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	/** 
	 *	$hash[0:31] = sha256($input)
	 *	$hash2[0:15] = md5($hash[0:31])
	 *  $key = RC4_set_key($hash2[0:15])
	 * 	$output[0:31] = RC4($key, $hash[0:31])
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
	
	RC4_KEY akey;
	RC4_set_key(&akey, MD5_DIGEST_LENGTH, md5Digest);
	uint8_t result[SHA256_DIGEST_LENGTH];
	RC4(&akey, SHA256_DIGEST_LENGTH, sha256Digest, result);

	memcpy(output, result, OUTPUT_LEN*sizeof(uint8_t));
}
