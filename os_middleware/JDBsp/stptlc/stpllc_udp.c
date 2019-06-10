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

#include "stpllc_udp.h"
#include "base64.h"

#if( LLC_TYPE == LLC_UDP )

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#define SYNCHD 	0xAA
#define SYNCEOF 0xA5

#define TLC_FLAG 0x05
#define LLC_FLAG 0x00



static int open_udp(stpllc * pllc);



static int udp_read(int fd,u8 * buf, int lens) {
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int ret = recvfrom(fd, buf, lens, 0, (struct sockaddr*)&addr, &len);
	return ret;
}

static int udp_write(int fd,int port,u8 * buf, int lens) {
	struct sockaddr_in addr;
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if ( port == 0 ) {
		addr.sin_port = htons(9000);

	} else {
		addr.sin_port = htons(8000);

	}
	int ret = sendto(fd, buf, lens, 0, (struct sockaddr *)&addr, sizeof(addr));
	return ret;
}


int stpllc_read(stpllc * hw,u8 * pdata,int lens) {
	int dlens = 0;
	u8 * buf = hw->pcache;
	if( !hw->cache_lens ){
		int retl = udp_read(hw->fd,buf,LLC_PACK_SZ_MAX);
		if( retl > 0 ){
			hw->cache_lens = retl;
		}


	}
	if ( hw->cache_lens > 0) {
		int i;

		for (i = 0; i < hw->cache_lens; i++) {

			if (buf[i] == SYNCHD) {
				hw->frame_lens = 0;

			} else if (buf[i] == SYNCEOF) {


				if ( hw->frame_lens > 1 ) {
					if( lens >= (hw->frame_lens-1) ){//必须要能装下
						switch (hw->pframe[0]) {
						case TLC_FLAG:
							/*一个序列里面只可能只有一个包*/
							dlens = base64_dec(pdata, hw->pframe + 1,hw->frame_lens - 1 );
							if ( dlens > 0 ) {
								memmove(hw->pcache,hw->pcache+i,(hw->cache_lens-i));
								hw->cache_lens -= (i+1);
								hw->frame_lens = 0;
								return dlens;
							}
							break;
						case LLC_FLAG:
							break;
						}
					}else{
						printf("llc frame lens to long\n");
					}
				}
				hw->frame_lens = 0;
			} else {
				//printf("hw->frame_lens:%d\n",hw->frame_lens);
				hw->pframe[hw->frame_lens++] = buf[i];
			}
		}
		hw->cache_lens = 0;
	}
	return 0;
}

int stpllc_write_raw(stpllc * hw, u8 * buffer, int lens) {
	return udp_write(hw->fd,hw->hwport, buffer, lens);
}
int stpllc_read_raw(stpllc * hw,u8 * pdata,int lens) {
	return udp_read(hw->fd,pdata,lens);
}


int stpllc_write(stpllc * hw, u8 * buffer, int lens) {
	int flens = base64_enc(hw->pframe + 2, buffer, lens);
	hw->pframe[0] 		= SYNCHD;
	hw->pframe[1] 		= TLC_FLAG;
	hw->pframe[flens+2] = SYNCEOF;

	return udp_write(hw->fd,hw->hwport,hw->pframe,flens+3);
}





stpllc * stpllc_open(int hwport){
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
	#else
		static u8 buffer[LLC_PACK_SZ_MAX+2];
		llc->pframe = buffer;
	#endif


	llc->fd = open_udp(llc);
	if( llc->fd < 0 ){
		goto error;
	}
	return llc;

	error:
	#if( MALLOC_EN == 1 )
	if( llc ){
		if( llc->pframe )
			free(llc->pframe );

		if( llc->pcache )
			free(llc->pcache);

		free(llc);
	}
	#endif

}

int stpllc_close(stpllc * pllc){

	if(pllc->fd > -1 ){
		close( pllc->fd );
		pllc->fd = -1;
	}
	#if( MALLOC_EN == 1 )
		free(pllc->pcache);
		free(pllc->pframe);
		free(pllc);
	#endif
	return 0;
}


static int open_udp(stpllc * pllc) {

	int sock =  socket(AF_INET, SOCK_DGRAM, 0);
	if ( sock < 0){
		perror("open_udp\n");
	}else{

		struct sockaddr_in addr;
		bzero(&addr,sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		if ( pllc->hwport == 0 ) {
			addr.sin_port = htons(8000);
			if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				perror("bind");
				exit(1);
			}
		}else{
			addr.sin_port = htons(9000);
			if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				perror("bind");
				exit(1);
			}
		}
	}

	return sock;
}


#endif

















