#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef MAC_OSX
#include <sys/malloc.h>
#else
#include <malloc.h>
#endif

void view_data_u8(const char *mess, 
		uint8_t *data, uint32_t len) {
	printf("%-18s\t", mess);
	for (uint32_t i = 0; i < len; ++i)
		printf("%.2x", data[i]);
	printf("\n");
}

void view_data_u32(const char *mess, 
		uint32_t *data, uint32_t len) {
	printf("%s: ", mess);
	for (uint32_t i = 0; i < len; ++i)
		printf("%.8x ", data[i]);
	printf("\n");
}

void reduce_bit(uint8_t *input, uint32_t inputLen, 
        uint8_t *output, uint32_t bits) {                                                                                                                                                                         
    uint32_t i, outputLen = (bits) >> 3;
    memcpy(output, input, outputLen * sizeof(uint8_t));
    for (i = outputLen; i < inputLen; ++i) {
        output[i % outputLen] ^= input[i % inputLen];
    }
}
void rrs(uint8_t *input, uint32_t inputLen, 
        uint8_t *output, uint32_t bits) {
    uint32_t shiftBytes = (bits) >> 3, shiftBits = (bits) & 0x7;
    uint32_t rIndex = (inputLen) - shiftBytes;
    uint32_t lIndex = (rIndex + (inputLen) - 1) % (inputLen);
    for (uint32_t i = 0; i < inputLen; ++i) {
        output[i] = (input[(rIndex++) % (inputLen)] >> shiftBits) |
            (input[(lIndex++) % (inputLen)] << (8 - shiftBits));
    }
}
