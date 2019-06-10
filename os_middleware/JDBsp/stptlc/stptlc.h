/*
 * uart hw link layer
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 * Serial transfer protocol=STP
 *
 * 地址分三级                                                     addr     mask
 * 1: 网关地址  ---> android   x.0.0    255.0.0
 * 2: 主机地址  ---> 副控板                  0.x.0    0.255.0
 * 3: 终端地址  ---> BATT板             0.0.x     0.0.255
 *
 * 如果有中转节点，直接在链路层做转发即可，不需要要传输层地址协议
 *
 */
#ifndef __STPTLC_HH__
#define __STPTLC_HH__

#include "typedef.h"
#include "stpllc_uart.h"

/*************************************************************/
/*传输层最大数据长度*/
#define TLC_PLAYLOAD_SZ_MAX	240
/*传输层最大帧长度*/
#define TLC_FRAME_SIZE (TLC_PLAYLOAD_SZ_MAX+sizeof(tlc_hd))
/*传输层最长度*/
#define TLC_FRAME_SIZE_MIN (sizeof(tlc_hd))

#define TLC_RRT_US		(TLC_FRAME_SIZE*8*1000*1000/LLC_BITRATE*4/3)
#define TLC_RRT_MS		((TLC_FRAME_SIZE*8*1000/LLC_BITRATE*4/3))

/*************************************************************/

#define LLC_LOCK() 
#define LLC_UNLOCK() 

#define TLC_WAIT 		0
#define TLC_NOWAIT 		1

#define TLC_SEG_ACK 	0x01
#define TLC_SEG_DATA 	0x02



typedef struct TLC_ADDR {//01f 013
	union{
		struct {
			u8 lev_addr[4];
		};
		u32 addr;
	};
}tlc_addr;

typedef struct STPTLC {//01f 013
	u8 seg_max;
	tlc_addr local_mask;
	tlc_addr local_addr;
	u8 session_id;
	u8 ack_id;
	stpllc * pllc;
	u8 flag;
	u8 exit;
	float rrt_us;
	int hwport;/*给传输层选择初始化端口*/
	int (*read)	(stpllc * hw,u8 * pdata,int lens);
	int (*write)(stpllc * hw,u8 * pdata, int lens);

	int (*read_raw)	(stpllc * hw,u8 * pdata,int lens);
	int (*write_raw)(stpllc * hw,u8 * pdata, int lens);

	stpllc * (*open)(int, int);
	int (*close)(stpllc *);
} stptlc;



#pragma pack(push)
#pragma pack(1)

typedef struct TLC_HD {//01f 013
	u8 	protocol;
	tlc_addr src_addr;
	tlc_addr dst_addr;
	u8	session_id;
	struct{
		u8  last_id:1;
		u8	pack_id:7;
	};
	u8  lens;
	u8  sum;
}tlc_hd;

#pragma pack()
#pragma pack(pop)


enum{
	TLCOPT_NOWAIT 	= 1,
	TLCOPT_WAIT 	= 2,
};


#define TLC_ADDR(l1,l2,l3)	{.lev_addr[0] = 0,.lev_addr[1] = l1,.lev_addr[2] = l2,.lev_addr[3] = l3}

tlc_addr tlc_iaddr(const char * straddr );

stptlc * tlc_open(tlc_addr locladdr,tlc_addr netmask,int port, int rate);
int tlc_close(stptlc * ptlc);
int tlc_recv(stptlc * tlc ,u8 * buffer ,int lens ,tlc_addr *fromaddr);
int tlc_send( stptlc * tlc,u8 * buffer ,int datalens,tlc_addr toaddr);

int tlc_send_raw( stptlc * tlc,u8 * buffer ,int datalens);
int tlc_recv_raw(stptlc * tlc ,u8 * buffer ,int lens);

int tlc_opt( stptlc * tlc,int op,int opt);

#endif