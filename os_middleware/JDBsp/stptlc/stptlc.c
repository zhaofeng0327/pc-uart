 /* transport layer control
 *
 * 2017-09-18
 * 盛耀微科技版权所有
 * wxj@glinkwin.com

  * tlc frame format:
 *   4 byte     |  4 byte |   2byte   | 1byte| n bytes  | 1byte     |
 *  src addr    | dst addr|  sid +pid | lens | playload | check sum |

 * frame type
 * 0x05: tlc layer data
 * 0x00: llc layer data
 *
 * 单线程调用
 *
 * 一个send 是一个事务,完整传输需要等待事务传输完成
 *
 */
#include "stptlc.h"
#include "stpllc_uart.h"
#include "utils.h"

static int g_timeout_cnts = 0;

void sys_mdelay(int msec){
	struct timeval timeOut;
	timeOut.tv_sec 	= msec/1000;
	timeOut.tv_usec = (msec%1000)*1000;
	while( 0 != select(0, NULL, NULL, NULL, &timeOut) );
}

void sys_udelay(u32 us){
	struct timeval timeOut;
	timeOut.tv_sec 	= us/1000000;
	timeOut.tv_usec = (us%1000000);
	while( 0 != select(0, NULL, NULL, NULL, &timeOut) );
}

static void stptlc_ack(stptlc * tlc ,u8* buffer,tlc_addr toaddr);

u8 wait_ack(stptlc * tlc) {
	u8 ret = 0;
	u32 waittime = 10000;//TLC_RRT_MS*6;
	u32 tick = 4;
	while (!tlc->exit) {
		if ( tlc->ack_id == tlc->session_id ) {
			ret = 1;
			break;
		}
		sys_mdelay(tick);
		if( waittime > tick  )
			waittime -= tick;
		else
			break;
	}
	return ret;
}

tlc_addr tlc_iaddr(const char * straddr ){
	tlc_addr adr;
	u8 i,k;
	adr.addr = 0;
	u8 val = 0;
	for( k = 1, i = 0;;i++ ){
		if( (straddr[i] =='.')||(!straddr[i] )){
			adr.lev_addr[k++] = val;
			if( k > 3 ){break;}
			val = 0;
		}else{
			val *= 10;
			val += straddr[i]-'0';
		}
		if(!straddr[i])break;
	}
	return adr;
}

int tlc_opt( stptlc * tlc,int op,int opt){
	int ret = 0;
	switch( op ){
	case TLCOPT_NOWAIT:
		tlc->flag = TLC_WAIT;
		break;
	case TLCOPT_WAIT:
		tlc->flag = TLC_NOWAIT;
		break;
	}
	return ret;
}

int tlc_send_raw( stptlc * tlc,u8 * buffer ,int datalens){
	return  tlc->write_raw(tlc->pllc,buffer,datalens);
}
int tlc_recv_raw(stptlc * tlc ,u8 * buffer ,int lens){
	return  tlc->read_raw(tlc->pllc,buffer,lens);
}

u8 tlc_mksum(tlc_hd * hd,int lens){
	u8 sum = 0;
	u8 * buffer = (u8 *)hd;
	hd->sum = 0;
	while( lens > 0 ){
		lens--;
		sum += *buffer;
		buffer++;
	}
	hd->sum = sum;
	return sum;
}

int tlc_send( stptlc * tlc,u8 * buffer ,int datalens,tlc_addr toaddr){

	int ret = datalens;

	if( ( toaddr.addr & tlc->local_mask.addr ) ==
		(tlc->local_addr.addr & tlc->local_mask.addr) ){
		dberr("toaddr == local_addr\n");
		return 0;
	}

	LLC_LOCK();
	u8 sendbuf[TLC_FRAME_SIZE];
	int trycnt = 3;
	tlc->session_id++;
	u8 * pbuf;
	int lens;
	u8 id;
resend:

	pbuf = buffer;
	lens = datalens;

	id = 0;
	if(trycnt)trycnt--;
	for( ; lens > 0 ; ){
		if( tlc->exit ){
			break;
		}
		int cplens = 0;
		tlc_hd *phd = (tlc_hd*)sendbuf;
		phd->src_addr 	= tlc->local_addr;
		phd->dst_addr 	= toaddr;
		phd->protocol	=  TLC_SEG_DATA;

		if( lens <= TLC_PLAYLOAD_SZ_MAX ){
			cplens = lens;
		}else{
			cplens = TLC_PLAYLOAD_SZ_MAX;
		}

		phd->session_id = tlc->session_id;
		phd->pack_id = id++;
		lens -= cplens;
		if( !lens ){
			phd->last_id = 1;
		}else{
			phd->last_id = 0;
		}

		memcpy(sendbuf+sizeof(tlc_hd),pbuf,cplens);
		phd->lens = cplens;

		tlc_mksum((tlc_hd*)sendbuf,phd->lens+sizeof(tlc_hd));
		//struct timeval startTime,endTime;
		ret =  tlc->write(tlc->pllc,sendbuf,phd->lens+sizeof(tlc_hd));
		if( ret < 0 ){
			goto send_end;
		}else{
			sys_udelay(3*(8000000/LLC_BITRATE*(ret+4)));
		}
		pbuf += cplens;
	}

	if( !tlc->exit ){
		if( tlc->flag == TLC_WAIT ){
			if( !wait_ack(tlc) ){
				printf("resend try %d >>>>>\n", 3-trycnt);
				//printf("wait ack failed exit >>>>>\n");
				//exit(0);
				if(trycnt){
					goto resend;
				}else{
					ret = -1;
					debug(">>>>>>>>>>>>>>send timeout:%d\n", ++g_timeout_cnts);
				}
			}
		}
	}
send_end:
	LLC_UNLOCK();
	return ret;
}

int tlc_recv(stptlc * tlc ,u8 * buffer ,int lens ,tlc_addr *fromaddr){

	int ret = 0;
	u8 id = 0;
	int rdlens = 0;

	//rdbuf要大于TLC_FRAME_SIZE/3*4
	u8 rdbuf[TLC_FRAME_SIZE*2];

	while( !tlc->exit ){

		LLC_LOCK();
		//ret = tlc->read(tlc->pllc,rdbuf,lens);
		ret = tlc->read(tlc->pllc,rdbuf,sizeof(rdbuf));
		LLC_UNLOCK();

		if( ret < 1 ){
			sys_msleep(4);
			continue;
		}

		tlc_hd *phd = (tlc_hd*)rdbuf;

#if 0
		if( ( phd->dst_addr.addr & tlc->local_mask.addr ) !=
				(tlc->local_addr.addr & tlc->local_mask.addr) ){
			printf("dst addr invalid. dst_addr:%d src_addr:%d \n", phd->dst_addr.addr, tlc->local_addr.addr);
			continue;
		}
#endif
		u8 sum = phd->sum;
		if( sum != tlc_mksum((tlc_hd*)rdbuf,ret) ){
			printf("tlc data sum error\n");
			continue;
		}

#ifdef UART_VERB
		printf("\n----- recv decode -----\n");
		dump_buffer(rdbuf, ret);
#endif
		switch( phd->protocol ){
		case TLC_SEG_ACK:
			if( phd->session_id == tlc->session_id ){
				tlc->ack_id = tlc->session_id;
			}
			break;
		case TLC_SEG_DATA:
			if( !phd->pack_id ){id = 0;rdlens = 0;}
			if( phd->pack_id == id ){

				if( (rdlens + phd->lens ) >= lens ){
					printf("buffer is min error\n");
					return -1;
				}
				memcpy(buffer+rdlens,rdbuf+sizeof(tlc_hd),phd->lens);
				rdlens += phd->lens;
				if( phd->last_id ){
					*fromaddr = phd->src_addr;
					if( tlc->flag == TLC_WAIT ){
						stptlc_ack(tlc,rdbuf,phd->src_addr);
						usleep(9000);
					}
					ret = rdlens;
					goto read_end;
				}
				id++;
			}
			break;
		}
	}
read_end:

	return ret;
}

static void stptlc_ack(stptlc * tlc ,u8 * buffer,tlc_addr toaddr){
	tlc_hd *phd = (tlc_hd *)buffer;
	phd->src_addr = tlc->local_addr;
	phd->dst_addr = toaddr;
	phd->protocol = TLC_SEG_ACK;
	phd->lens = 0;

	tlc_mksum((tlc_hd*)buffer,phd->lens+sizeof(tlc_hd));

	tlc->write(tlc->pllc,buffer,phd->lens+sizeof(tlc_hd));
#ifdef UART_VERB
	printf("send ack\n");
	dump_buffer(buffer, phd->lens+sizeof(tlc_hd));
#endif
}


stptlc * tlc_open(
		tlc_addr locladdr,
		tlc_addr netmask,
		int port,
		int rate){

#if( MALLOC_EN == 1 )
	stptlc * ptlc = malloc(sizeof(stptlc));
	if( !ptlc )
		return NULL;
#else
	static stptlc g_tlc;
	stptlc * ptlc = &g_tlc;
#endif

	memset(ptlc,0,sizeof(stptlc));
	ptlc->local_mask 	= netmask;
	ptlc->local_addr 	= locladdr;
	ptlc->flag 			= TLC_WAIT;
	ptlc->hwport 		= port;

	ptlc->read 			= stpllc_read;
	ptlc->write 		= stpllc_write;

	ptlc->read_raw 			= stpllc_read_raw;
	ptlc->write_raw 		= stpllc_write_raw;

	ptlc->open 			= stpllc_open;
	ptlc->close			= stpllc_close;
	ptlc->pllc 			= ptlc->open(ptlc->hwport, rate);
	if( !ptlc->pllc ){
#if( MALLOC_EN == 1 )
		free(ptlc);
#endif
		return NULL;
	}
	return ptlc;
}


int tlc_close(stptlc * ptlc){
	ptlc->close(ptlc->pllc);

#if( MALLOC_EN == 1 )
	free(ptlc);
#else

#endif
	return 0;
}














