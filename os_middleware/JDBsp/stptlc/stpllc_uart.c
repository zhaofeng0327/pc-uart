/*
 * uart hw link layer
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 * Serial transfer protocol=STP
 * OS:linux
 *
 *
 * 串口传输采用base64 编码,0xAA 开始，0xA5结束
 * llc frame format:
 * sync |frame type| playload | eof |
 * 0xAA    0~0x09     data     0xA5
 *
 * frame type
 * 0x05: tlc layer data
 * 0x00: llc layer data
 */

#define LOG_TAG "JNS_UART_MAN"

#include "stpllc_uart.h"
#include "base64.h"
#include "ioctrl.h"
#include "utils.h"



#if( LLC_TYPE == LLC_UART )

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#ifdef WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#define SYNCHD 	0xAA
#define SYNCEOF 0xA5

#define TLC_FLAG 0x05
#define LLC_FLAG 0x00

static int uart_open(stpllc * pllc, int rate);


static int uart_read(int fd,u8 * buf, int lens) {
	return jz_uart_read_ex(fd, buf, lens);
}

static int uart_write(int fd,u8 * buf, int lens) {
#ifdef SLAVE_CTRL
	jz_io_write(GPIOA(13), 1);
#endif
	int ret = jz_uart_write_ex(fd, buf, lens);
#ifdef SLAVE_CTRL
	jz_io_write(GPIOA(13), 0);
#endif
	return ret;
}


int stpllc_read(stpllc * hw,u8 * pdata,int lens) {
	int dlens = 0;
	u8 * buf = hw->pcache;
	u8 * frame = hw->pframerx;

	if( hw->cache_lens < 1 ){
		int retl = uart_read(hw->fd,buf,LLC_PACK_SZ_MAX);
		if( retl > 0 ){
			hw->cache_lens = retl;
		}
	}

#ifdef UART_VERB
	printf("\n----- recv raw -----\n");
	dump_buffer(buf, (int)hw->cache_lens);
#endif

	if ( hw->cache_lens > 0) {

		int i;
		for (i = 0; i < hw->cache_lens;) {

			frame[hw->frame_lens++] = buf[i++];

			if ( buf[i-1] == SYNCHD ) {
				hw->frame_lens = 1;
			} else if (buf[i-1] == SYNCEOF) {

				if ( hw->frame_lens > 3 ) {

					if( lens >= (hw->frame_lens-3 ) ){//必须要能装下
						switch ( frame[1] ) {
						case TLC_FLAG:
							/*一个序列里面只可能只有一个包*/
							dlens = base64_dec((char*)pdata, frame + 2,hw->frame_lens - 3 );
							if ( dlens > 0 ) {
								if( (hw->cache_lens-i) > 0 ){
									memmove(buf,buf+i,hw->cache_lens-i);
								}
								hw->cache_lens -= i;
								hw->frame_lens = 0;
								return dlens;
							}else{
								printf(">>>>>>>>>>>>>>>>>>>base64_dec error:%d\n",hw->frame_lens);
							}
							break;
						case LLC_FLAG:
							printf("LLC_FLAG\n");
							break;
						default:
							printf("unknow data:%02x\n",frame[0]);
							break;
						}
					}else{
						printf("llc frame lens to long\n");
					}
				}else{
					printf("lens < 3 \n");
				}
				hw->frame_lens = 0;
			}
		}
		hw->cache_lens = 0;
	}
	return 0;
}

int stpllc_write(stpllc * hw, u8 * buffer, int lens) {
	int flens = base64_enc((char*)hw->pframe + 2, buffer, lens);
	hw->pframe[0] 		= SYNCHD;
	hw->pframe[1] 		= TLC_FLAG;
	hw->pframe[flens+2] = SYNCEOF;

	return uart_write(hw->fd,hw->pframe,flens+3);
}

int stpllc_write_raw(stpllc * hw, u8 * buffer, int lens) {
	return uart_write(hw->fd, buffer, lens);
}
int stpllc_read_raw(stpllc * hw,u8 * pdata,int lens) {
	return uart_read(hw->fd,pdata,lens);
}

stpllc * stpllc_open(int hwport, int rate){
	stpllc * llc;
#if( MALLOC_EN == 1 )
	llc = malloc(sizeof(stpllc));
#else
	static stpllc g_llc;
	llc = &g_llc;
#endif
	if(!llc)goto error;
	memset(llc,0,sizeof(stpllc));
	llc->hwport	  = hwport;
	llc->frame_sz = LLC_PACK_SZ_MAX;
#if( MALLOC_EN == 1 )
	llc->pcache = malloc(LLC_PACK_SZ_MAX*2);
	llc->pframe = malloc(LLC_PACK_SZ_MAX*2);
	llc->pframerx = malloc(LLC_PACK_SZ_MAX*2);
#else
	static u8 buffer[LLC_PACK_SZ_MAX*2];
	static u8 bufferrx[LLC_PACK_SZ_MAX*2];
	llc->pframe = buffer;
	llc->pframerx = bufferrx;
#endif
	llc->fd = uart_open(llc, rate);
	if( llc->fd < 0 ){
		goto error;
	}
	return llc;
error:
#if( MALLOC_EN == 1 )
	if( llc ){
		if( llc->pframe ){
			free(llc->pframe );
		}
		if( llc->pframerx )
			free(llc->pframerx );
		free(llc);
	}
#endif
	return NULL;
}

int stpllc_close(stpllc * pllc){

	if( pllc->fd > -1 ){
		close( pllc->fd );
		pllc->fd = -1;
	}

#if( MALLOC_EN == 1 )
	free(pllc->pcache);
	free(pllc->pframe);
	free(pllc->pframerx );
	free(pllc);
#endif

	return 0;
}


#define MAX_UART_PER_DEV		4

typedef struct
{
	int b_used;
	char device[128];
	void * tlc_ptr;
}UART_ENDPT_INFO_T;

static UART_ENDPT_INFO_T uart_endpt_list[MAX_UART_PER_DEV] = {{0, "", NULL}, {0, "", NULL}, {0, "", NULL}, {0, "", NULL}};

#ifdef WIN32
HANDLE mutex = NULL;
#else
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

int tpllc_set_uart_dev(char * device)
{
	int b_idel_idx = -1;
	int i;

#ifdef WIN32
	if (NULL == mutex)
	{
		mutex = CreateMutex(NULL, FALSE, NULL);
	}
#endif

#ifdef WIN32
	WaitForSingleObject(mutex, INFINITE);
#else
	pthread_mutex_lock(&mutex);
#endif

	for (i = 0; i < MAX_UART_PER_DEV; i ++)
	{
		if (0 == uart_endpt_list[i].b_used)
		{
			b_idel_idx = i;
		}
		else
		{
			if (0 == strcmp(device, uart_endpt_list[i].device))
			{
#ifdef WIN32
				ReleaseMutex(mutex);
#else
				pthread_mutex_unlock(&mutex);
#endif
				return i;
			}
		}
	}

	if (-1 == b_idel_idx)
	{
		debug("uart endpt is full \r\n");
	}
	else
	{
		strncpy(uart_endpt_list[b_idel_idx].device, device, 128);
		uart_endpt_list[b_idel_idx].b_used = 1;
	}

#ifdef WIN32
	ReleaseMutex(mutex);
#else
	pthread_mutex_unlock(&mutex);
#endif

	return b_idel_idx;
}

int tpllc_clear_uart_dev(int index)
{
	if (index < 0 || index >= 4)
	{
		dberr("invalid index:%d \r\n", index);
		return -1;
	}

#ifdef WIN32
	WaitForSingleObject(mutex, INFINITE);
#else
	pthread_mutex_lock(&mutex);
#endif

	uart_endpt_list[index].b_used = 0;

#ifdef WIN32
	ReleaseMutex(mutex);
#else
	pthread_mutex_unlock(&mutex);
#endif

	return 0;
}

int set_tlc_ptr_f_index(int index, void * tlc_ptr)
{
	if (index < 0 || index >= 4)
	{
		dberr("invalid index:%d \r\n", index);
		return -1;
	}

#ifdef WIN32
	WaitForSingleObject(mutex, INFINITE);
#else
	pthread_mutex_lock(&mutex);
#endif

	uart_endpt_list[index].tlc_ptr = tlc_ptr;

#ifdef WIN32
	ReleaseMutex(mutex);
#else
	pthread_mutex_unlock(&mutex);
#endif

	return 0;
}

void * get_tlc_ptr_f_index(int index)
{
	if (index < 0 || index >= 4)
	{
		dberr("invalid index:%d \r\n", index);
		return 0;
	}

	return uart_endpt_list[index].tlc_ptr;
}

static char * get_uart_name_from_index(int index)
{
	if (index < 0 || index >= 4)
	{
		dberr("invalid index:%d \r\n", index);
		return NULL;
	}

	return uart_endpt_list[index].device;
}

///dev/cu.usbserial-141
///dev/cu.wchusbserial1420

static int uart_open(stpllc * pllc, int rate)
{
	char * device_name = NULL;
	int fd = -1;

	if (pllc->hwport < 0 || pllc->hwport >= 4)
	{
		dberr("invalid uart port:%d \r\n", pllc->hwport);
		return -1;
	}

	device_name = get_uart_name_from_index(pllc->hwport);

	fd = jz_uart_init_ex(device_name, rate);

	debug("open uart:%s fd:%x \r\n", device_name, fd);

	return fd;
}

#endif
