// Copyright (c) 2016-2018 The Ulord Core Foundation
#ifndef POW_H
#define POW_H

#include <stdint.h>
#include <string.h>

#include "common.h"

#define WORK_MEMORY_SIZE (1024*1024)

#ifdef __cplusplus
extern "C" {
#endif

	/* 
	 * Step 1: Initialize working memory.
	*/
	void initWorkMemory(uint8_t *input, uint32_t inputLen, uint8_t *Maddr, const uint32_t K);
		
	/* 
	 * Step 2: Modify the working memory contents.
	*/
	void modifyWorkMemory(uint8_t *Maddr, const uint32_t L, const uint32_t C, uint8_t *result);

	/* 
	 * Step 3: Calculate the final result.
	*/
	void calculateFinalResult(uint8_t *Maddr, uint8_t *c, const uint32_t D, uint8_t *result);

	/* 
	 * Correctness & Performance test for Proof of work
	*/
	void testPowFunction(uint8_t *mess, uint32_t messLen, const int64_t iterNum);
	void powNistTest(const char *outFileName);

	/*
     * hash function
    */
    void helloHash(const uint8_t *mess, uint32_t messLen, uint8_t output[OUTPUT_LEN]);
	
#ifdef __cplusplus
}
#endif	

/* 
 * Proof of work.
*/
void powFunction(uint8_t *input, uint32_t inputLen, uint8_t *Maddr, uint8_t *output);

#endif
