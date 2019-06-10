/*
 * uart hw link layer
 * 2017-09-18
 * 盛耀微科技 版权所有
 * wxj@glinkwin.com
 * Serial transfer protocol=STP
 *
 */

#include "typedef.h"
#include "stptlc.h"

#ifndef __LLC_HH__
#define __LLC_HH__

#define LLC_HD_SZ			3
#define LLC_PACK_SZ_MIN 	(TLC_FRAME_SIZE_MIN+LLC_HD_SZ)
#define LLC_PACK_SZ_MAX 	((TLC_FRAME_SIZE+LLC_HD_SZ)*2)
#define LLC_BITRATE			115200

typedef struct STPLLC {
	u8 * pframe;
	u8 * pframerx;
	u8  * pcache;
	u16 cache_lens;
	u16 tlc_data_sz;
	u16 frame_sz;
	u16 frame_lens;
	int fd;
	int hwport;
} stpllc;



int stpllc_read(stpllc * hw,u8 * pdata,int lens);
int stpllc_write(stpllc * hw,u8 * buffer,int lens);

int stpllc_write_raw(stpllc * hw, u8 * buffer, int lens);
int stpllc_read_raw(stpllc * hw,u8 * pdata,int lens);


int stpllc_close(stpllc * pllc);
stpllc * stpllc_open(int hwport, int rate);


int tpllc_set_uart_dev(char * device);
int tpllc_clear_uart_dev(int index);
int set_tlc_ptr_f_index(int index, void * tlc_ptr);
void * get_tlc_ptr_f_index(int index);

#endif



