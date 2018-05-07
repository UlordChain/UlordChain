// Copyright (c) 2016-2018 The Ulord Core Foundation
#ifndef ONE_WAY_FUNCTION_H
#define ONE_WAY_FUNCTION_H

#include <stdint.h>

typedef void (*OneWayFunction)(uint8_t *, uint32_t, uint8_t *);

typedef struct {
	const char *funcName;
	OneWayFunction func;
} OneWayFunctionInfor;

#define FUNCTION_NUM	16

extern OneWayFunctionInfor funcInfor[FUNCTION_NUM];

#ifdef __cplusplus
extern "C" {
#endif

	void initOneWayFunction();
	void testOneWayFunction(const char *mess, uint32_t messLen, const int64_t iterNum);
	
#ifdef __cplusplus
}
#endif
	
#endif
