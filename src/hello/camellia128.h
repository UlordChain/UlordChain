#ifndef CAMELLIA128_H
#define CAMELLIA128_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	void camellia128(uint8_t *input, uint32_t inputLen, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif
