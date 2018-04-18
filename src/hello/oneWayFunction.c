#include "oneWayFunction.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <omp.h>

#include "my_time.h"
#include "common.h"

// OpenSSL Library
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3_256.h"
#include "whirlpool.h"
#include "ripemd160.h"
#include "blake2s256.h"
#include "aes128.h"
#include "des.h"
#include "crc32.h"
#include "hmac_md5.h"
#include "rc4.h"
#include "camellia128.h"

// JTR source code
#include "gost.h"
#include "haval5_256.h"
#include "skein512_256.h"

OneWayFunctionInfor funcInfor[FUNCTION_NUM] = {
	"SHA3-256", sha3_256,
	"SHA1", sha1,
	"SHA256", sha256,
	"SHA512", sha512,
	"Whirlpool", whirlpool,
	"RIPEMD-160", ripemd160,
	"BLAKE2s(256bits)", blake2s256,
	"AES(128bits)", aes128,
	"DES", des,
	"RC4", rc4,
	"Camellia(128bits)", camellia128,
	"CRC32", crc32,
	"HMAC(MD5)", hmac_md5,
	"GOST R 34.11-94", gost, 
	"HAVAL-256/5", haval5_256,
	"Skein-512(256bits)", skein512_256
};

void initOneWayFunction() {
	gost_init_table();
	CRC32_Table_Init();
}

void testOneWayFunction(const char *mess, const int64_t iterNum) {
	/*
	int64_t j;
	uint32_t messLen = (uint32_t)strlen(mess);

	uint8_t input[INPUT_LEN], output[FUNCTION_NUM][OUTPUT_LEN];
	memset(input, 0, INPUT_LEN*sizeof(uint8_t));
	memcpy(input, mess, messLen*sizeof(char));
	
	printf("**************************** Correctness test (One way function) ****************************\n");
	printf("Test message: %s\n", mess);
	for (int i = 0; i < FUNCTION_NUM; ++i) {
		printf("%02d ", i);
		funcInfor[i].func(input, messLen, output[i]);
		view_data_u8(funcInfor[i].funcName, output[i], OUTPUT_LEN);
	}
	printf("*********************************************************************************************\n");
	
	printf("************************************************* Performance test (One way function) *************************************************\n");
	uint8_t *result = (uint8_t *)malloc(iterNum * OUTPUT_LEN * sizeof(uint8_t));
	assert(NULL != result);
	memset(result, 0, iterNum * OUTPUT_LEN * sizeof(uint8_t));
	
	uint32_t threadNumArr[] = {1, 4, 8, 12, 16, 20, 24, 32, 48, 64};
	uint32_t threadNumTypes = sizeof(threadNumArr) / sizeof(uint32_t);
	printf("   %-18s", "Algorithm");
	for (uint32_t ix = 0; ix < threadNumTypes; ++ix)
		printf("%12d", threadNumArr[ix]);
	printf("\n");
	
	for (int i = 0; i < FUNCTION_NUM; ++i) {
		printf("%02d %-18s\t", i, funcInfor[i].funcName);
		for (uint32_t ix = 0; ix < threadNumTypes; ++ix) {
			omp_set_num_threads(threadNumArr[ix]);
			double startTime = get_wall_time();
			if (threadNumArr[ix] == 1) {
				for (j = 0; j < iterNum; ++j) {
					funcInfor[i].func(input, messLen, result + j * OUTPUT_LEN);
				}
			} else {
				#pragma omp parallel for firstprivate(input), private(j) shared(result)
				for (j = 0; j < iterNum; ++j) {
					funcInfor[i].func(input, messLen, result + j * OUTPUT_LEN);
				}
			}
			double endTime = get_wall_time();
			double costTime = endTime - startTime;
			printf("%5.0f Kps   ", iterNum / 1000 / costTime); fflush(stdout);
			
			// Check result
			for (j = 0; j < iterNum; j += 1) {
				if (memcmp(output[i], result + j * OUTPUT_LEN, OUTPUT_LEN)) {
					printf("Thread num: %u, j: %ld\n", threadNumArr[ix], j);
					view_data_u8("output", output[i], OUTPUT_LEN);
					view_data_u8("result", result + j * OUTPUT_LEN, OUTPUT_LEN);
					abort();
				}
			}
		}
		printf("\n");
	}
	if (NULL != result) {
		free(result);
		result = NULL;
	}
	*/
	printf("***************************************************************************************************************************************\n");
}
