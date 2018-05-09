#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef MAC_OSX
#include <sys/malloc.h>
#else
#include <malloc.h>
#endif

#define INPUT_LEN	140
#define OUTPUT_LEN	32

// Least common multiple
inline uint32_t lcm(uint32_t num1, uint32_t num2) {
	uint32_t m = num1, n = num2;
	while(num2) {
		uint32_t r = num1 % num2;
		num1 = num2;
		num2 = r;
	}
	uint32_t lcm = m * n / num1;
	return lcm;
}

inline void reduce_bit_2(uint8_t *input, uint32_t inputLen, 
		uint8_t *output, uint32_t bits) {
	uint32_t i, outputLen = (bits) >> 3;
	uint32_t lcmBytes = lcm(inputLen, outputLen);
	memcpy(output, input, outputLen * sizeof(uint8_t));
	for (i = outputLen; i < lcmBytes; ++i) {
		output[i % outputLen] ^= input[i % inputLen];
	}
}

void reduce_bit(uint8_t *input, uint32_t inputLen, 
		uint8_t *output, uint32_t bits);

void rrs(uint8_t *input, uint32_t inputLen, 
		uint8_t *output, uint32_t bits);

#ifdef __cplusplus
extern "C" {
#endif

	void view_data_u8(const char *mess, uint8_t *data, uint32_t len);
	void view_data_u32(const char *mess, uint32_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif	


#endif
