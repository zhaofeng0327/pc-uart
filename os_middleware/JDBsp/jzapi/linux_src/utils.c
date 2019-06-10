
#include "typedef.h"
#include "utils.h"

#define LOG_TAG "JNS_UART_MAN"

void dump_buffer(u8 * buffer,int lens)
{
#ifdef UART_VERB
	int i;
	for(i = 0;i<lens;i++){
		if((i%16)==0 && i)
			printf("\n");
		printf("%02x ",buffer[i]);
	}
    printf("\n");
#endif
}
