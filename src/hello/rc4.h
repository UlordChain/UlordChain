#ifndef RC4_H
#define RC4_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	void rc4(uint8_t *input, uint32_t inputLen, uint8_t *output) ;

#ifdef __cplusplus
}
#endif	

#endif