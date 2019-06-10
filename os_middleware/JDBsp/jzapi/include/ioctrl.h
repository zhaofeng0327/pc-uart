/*
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 */
#ifndef __JZIOCTRL_HH__
#define __JZIOCTRL_HH__

#include "typedef.h"

enum{
	IOCMD_IO_R				= 0xD0,
	IOCMD_IO_W				= 0xE0,
	IOCMD_INIT				= 0xF0,
};




#define GPIOA(pin) (((u32)'A' << 24)|pin)
#define GPIOB(pin) (((u32)'B' << 24)|pin)
#define GPIOC(pin) (((u32)'C' << 24)|pin)
#define GPIOD(pin) (((u32)'D' << 24)|pin)
#define GPIOE(pin) (((u32)'E' << 24)|pin)
#define GPIOF(pin) (((u32)'F' << 24)|pin)

struct IODEF{
	union{
		struct {
			int group	:8;
			int pin		:8;
			int pull	:8;
			int out		:1;
			int value	:1;
		};
		int ival;
	};
};

//读编码开关
EXPORT_API u8 jz_io_sw_code(); 
//控制muc电源 no:0~11 哪一路mcu, on:0=off/1=on
EXPORT_API int jz_io_mcu_pw(int no,int on);
//KEY_IN SET_KEY ONEKEY_RETURN
//读取按键no:0~2 ，有三路按键
EXPORT_API int jz_io_get_key(int no);

//WORK_LED LED_B LED_R
//led控制:no: 0~2 ，有三路LED ,on:0=off/1=on
EXPORT_API int jz_io_led(int no,int on);//0~2
//打开电池控制串口 no:0~11 哪一路uart, on:0=off/1=on
EXPORT_API int jz_io_setuart(int uartno,int on);
//初始化io
EXPORT_API int jz_io_init();

//一下可以不用
EXPORT_API int jz_io_write(int io,int val);
EXPORT_API int jz_io_read(int io);
EXPORT_API int jz_io_set(int io,int out,int val);

#endif



