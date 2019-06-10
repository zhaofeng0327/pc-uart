/*
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 */
#ifndef __JZUART_HH__
#define __JZUART_HH__


#ifdef WIN32
#else
	#include "typedef.h"

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>
	#include <fcntl.h>
	#include <errno.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <semaphore.h>
	#include <sys/select.h>
	#include <sys/time.h>
	#include <termios.h>
	#define CMSPAR    010000000000

	/*	BAUD rate setting	*/
	#if 0
	#define BAUD_50			0x00
	#define BAUD_75			0x01
	#define BAUD_110		0x02
	#define BAUD_134		0x03
	#define BAUD_150		0x04
	#define BAUD_300		0x05
	#define BAUD_600		0x06
	#define BAUD_1200		0x07
	#define BAUD_1800		0x08
	#define BAUD_2400		0x09
	#define BAUD_4800		0x0A
	#define BAUD_7200		0x0B
	#define BAUD_9600		0x0C
	#define BAUD_19200		0x0D
	#define BAUD_38400		0x0E
	#define BAUD_57600		0x0F
	#define BAUD_115200 	0x10
	#define BAUD_230400 	0x11
	#define BAUD_460800 	0x12
	#define BAUD_921600 	0x13


	/*
	 * Standard speeds
	 */
	#define B0	0
	#define B50	50
	#define B75	75
	#define B110	110
	#define B134	134
	#define B150	150
	#define B200	200
	#define B300	300
	#define B600	600
	#define B1200	1200
	#define	B1800	1800
	#define B2400	2400
	#define B4800	4800
	#define B9600	9600
	#define B19200	19200
	#define B38400	38400
	#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
	#define B7200	7200
	#define B14400	14400
	#define B28800	28800
	#define B57600	57600
	#define B76800	76800
	#define B115200	115200
	#define B230400	230400
	#define EXTA	19200
	#define EXTB	38400
	#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
	#endif


	/*	MODE setting		*/
	#define BIT_5			0x00			/* Word length define	    */
	#define BIT_6			0x01
	#define BIT_7			0x02
	#define BIT_8			0x03

	#define STOP_1			0x00			/* Stop bits define	        */
	#define STOP_2			0x04

	#define P_EVEN			0x18			/* Parity define	        */
	#define P_ODD			0x08
	#define P_SPC			0x38
	#define P_MRK			0x28
	#define P_NONE			0x00

	/* Flow control setting 	*/
	#define F_NONE          0x00            /* No flow control          */
	#define F_CTS			0x01			/* CTS flow control         */
	#define F_RTS			0x02			/* RTS flow control         */
	#define F_HW			0x03			/* Hardware flowcontrol     */
	#define F_TXSW			0x04			/* Tx XON/XOFF flow control */
	#define F_RXSW			0x08			/* Rx XON/XOFF flow control */
	#define F_SW			0x0C			/* Sofeware flowcontrol     */


	/* error code */
	#define UART_OK				0
	#define UART_BADPORT			-1		/* no such port or port not opened          */
	#define UART_OUTCONTROL		-2		/* can't control the board                  */
	#define UART_NODATA			-4		/* no data to read or no buffer to write    */
	#define UART_OPENFAIL		-5		/* no such port or port has be opened       */
	#define UART_RTS_BY_HW		-6      /* RTS can't set because H/W flowctrl       */
	#define UART_BADPARM			-7		/* bad parameter                            */
	#define UART_WIN32FAIL		-8		/* call win32 function fail, please call    */
										/* GetLastError to get the error code       */
	#define UART_BOARDNOTSUPPORT -9		/* Does not support this board              */
	#define UART_FAIL			-10		/* PComm function run result fail           */
	#define UART_ABORTWRITE		-11		/* write has blocked, and user abort write  */
	#define UART_WRITETIMEOUT    -12 	/* write timeoue has happened               */
	#define UART_SETERROR		-13       /*set the port error*/
	#define SET_BAUNDNULL		-14      /*the speed is no exist*/



	EXPORT_API int jz_uart_init(int rate);
	EXPORT_API int jz_uart_write(u8 * buffer,int lens);
	EXPORT_API int jz_uart_read(u8 * buffer,int lens);
	//115200 waitus>=4000
	EXPORT_API int jz_uart_read_wait(u8 * buffer,int lens,int waitus);
	EXPORT_API int jz_uart_init_ex(const char * name,int rate);
	EXPORT_API int jz_uart_write_ex(int fd,u8 * buffer,int lens);
	EXPORT_API int jz_uart_read_ex(int fd,u8 * buffer,int lens);
	//115200 waitus>=4000
	EXPORT_API int jz_uart_read_ex_waitus(int fd,u8 * buffer,int lens,int waitus);
	EXPORT_API int jz_uart_read_ex_timeout(int fd,u8 * buffer,int lens,int waitus,int timeoutus);

#endif

#endif