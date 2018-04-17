#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

/*
 * 功能：字节数组打印方法
 * 输入：1. mess：字节数组名称
 *		 2. data：字节数组地址
 *		 3. len ：字数组长度
*/
void view_data_u8(const char *mess, 
		uint8_t *data, uint32_t len) {
	printf("%-18s\t", mess);
	for (uint32_t i = 0; i < len; ++i)
		printf("%.2x", data[i]);
	printf("\n");
}

/*
 * 功能：字数组打印方法
 * 输入：1. mess：字数组名称
 *		 2. data：字数组地址
 *		 3. len ：字数组长度
*/
void view_data_u32(const char *mess, 
		uint32_t *data, uint32_t len) {
	printf("%s: ", mess);
	for (uint32_t i = 0; i < len; ++i)
		printf("%.8x ", data[i]);
	printf("\n");
}
