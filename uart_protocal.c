#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "md_5.h"

unsigned short crc16(unsigned char *ptr, int count)
{
	unsigned short crc;
	char i;

	crc = 0;
	while (--count >= 0) {
		crc = crc ^ (int)*ptr++ << 8;
		i = 8;
		do {
			if (crc & 0x8000)
				crc = crc << 1 ^ 0x1021;
			else
				crc = crc << 1;
		} while (--i);
	}

	return crc;
}

unsigned long get_file_size(const char *filename)
{
	struct stat buf;

	if (stat(filename, &buf) < 0)
		return 0;
	return (unsigned long)buf.st_size;
}


int get_md5(unsigned char *md5, const char *ptr, int lens, int type)
{
	MD5_CTX_T ctx;

	if ((type != 0) && (type != 1))
		return -1;

	md5_init(&ctx);
	if (0 == type) {
		unsigned int mem_size = 1024;
		int len = 0;
		unsigned char *pData = NULL;
		FILE *fp = NULL;

		pData = (unsigned char *)malloc(mem_size);
		if (NULL == pData) {
			printf("md5 malloc failed");
			return -1;
		}

		fp = fopen(ptr, "r");
		if (fp == NULL) {
			printf("%s md5 open failed\n", ptr);
			free(pData);
			pData = NULL;
			return -1;
		}

		while (0 != (len = fread(pData, 1, mem_size, fp)))
			md5_update(&ctx, pData, len);

		fclose(fp);
		free(pData);
		pData = NULL;
	} else if (1 == type) {
		md5_update(&ctx, (unsigned char*)ptr, lens);
	}
	md5_final(&ctx, (unsigned char *)md5);
#if 1
	char dis[33] = { 0 };
	int  i = 0;
	for (i = 0; i < 16; i++)
		sprintf(dis + 2 * i, "%02X", md5[i]);
	printf("md5: %s\n", dis);
#endif
	return 0;
}


