#include "c_hmac_md5.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#include "common.h"

/*
 * 功能：单向函数 HMAC MD5
 * 输入：1. input ：输入消息
 *		 2. output：输出结果
*/
void crypto_hmac_md5(uint8_t *input, uint32_t inputLen, uint8_t *output) {
	uint8_t hmacMd5Digest[MD5_DIGEST_LENGTH];
	unsigned int mdLen;

// "OpenSSL 1.1.0h-fips  27 Mar 2018"
#if (OPENSSL_VERSION_NUMBER >= 0x1010008fL)
	HMAC_CTX *ctx;

	ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, input, inputLen, EVP_md5(), NULL);
	HMAC_Update(ctx, input, inputLen);
	HMAC_Final(ctx, hmacMd5Digest, &mdLen);
	HMAC_CTX_free(ctx);
#else
	HMAC_CTX ctx;

	HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, input, inputLen, EVP_md5(), NULL);  
    HMAC_Update(&ctx, input, inputLen);  
    HMAC_Final(&ctx, hmacMd5Digest, &mdLen);  
    HMAC_CTX_cleanup(&ctx);
#endif
	
	uint8_t sha256Digest[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256_ctx;
	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, hmacMd5Digest, MD5_DIGEST_LENGTH);
	SHA256_Final(sha256Digest, &sha256_ctx);
	
	memcpy(output, sha256Digest, OUTPUT_LEN*sizeof(uint8_t));
}
