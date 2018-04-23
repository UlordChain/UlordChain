#ifndef C_RC4_H
#define C_RC4_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	void crypto_rc4(uint8_t *input, uint32_t inputLen, uint8_t *output) ;

#ifdef __cplusplus
}
#endif	

#endif