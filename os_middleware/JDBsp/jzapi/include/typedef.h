/*
 * typedef
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 */



#ifndef __TYPEDEF_HH__
#define __TYPEDEF_HH__

#ifdef WIN32
	#include <Windows.h>
#else
	#include <sys/ioctl.h>
	#include <termios.h>
	#include <sys/time.h>
	#include <pthread.h>
	#include "unistd.h"
#endif

#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define LLC_UART	0
#define LLC_UDP		1

#define MALLOC_EN	1
#define LLC_TYPE	LLC_UART

#if 0
#include "model_default.h"
#else
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
#endif

//#define bool u8
#define true 1
#define false 0

#ifdef WIN32
#define sys_msleep(ms) Sleep(ms*1000)
#else
#define sys_msleep(ms) usleep(ms*1000)
#endif

#define dberr printf
#define debug printf
#define dump dump_buffer

#define app_exit() exit(0)

#define EXPORT_API

#endif
