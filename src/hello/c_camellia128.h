#ifndef C_CAMELLIA128_H
#define C_CAMELLIA128_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	void crypto_camellia128(uint8_t *input, uint32_t inputLen, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif
