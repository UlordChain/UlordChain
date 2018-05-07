// Copyright (c) 2016-2018 The Ulord Core Foundation
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "PoW.h"
#include "common.h"
#include "my_rand48_r.h"
#include "oneWayFunction.h"

int main(int argc, const char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s message\n", argv[0]);
		exit(-1);
	}
	
	const char *mess = argv[1];
	uint32_t messLen = (uint32_t)strlen(mess);

	uint8_t input[INPUT_LEN];
	memset(input, 0, INPUT_LEN*sizeof(uint8_t));
	memcpy(input, mess, messLen*sizeof(char));
	
	// Test for oneWayFunction
	initOneWayFunction();
	//testOneWayFunction(mess, messLen, 50000);
	
	testPowFunction(input, messLen, 5000);
	
	// powNistTest("./powNistTest");
	
	/* uint8_t Maddr[WORK_MEMORY_SIZE], output[OUTPUT_LEN];
	memset(Maddr, 0, WORK_MEMORY_SIZE*sizeof(uint8_t));
	
	for (int i = 0; i < 100; ++i)
		powFunction(input, messLen, Maddr, output);
	view_data_u8("PoW", output, OUTPUT_LEN); */
	
	return 0;
}
