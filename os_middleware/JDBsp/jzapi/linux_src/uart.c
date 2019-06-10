#include "typedef.h"
#include "uart.h"
#include "utils.h"

int serial_Open(const char *cSerialName,int speed,int mode)
{
	int fd = open(cSerialName, O_RDWR | O_NOCTTY  | O_NDELAY);
	if ( fd == -1 )
	{
		perror("open_port:");
		return -1;
	}
	else
	{
		struct termios options;
		tcgetattr(fd, &options);
		options.c_cflag |= (CLOCAL | CREAD);	//设置控制模式状态，本地连接，接收使能
		options.c_cflag &= ~CSIZE;				//字符长度，设置数据位之前一定要屏掉这个位
		options.c_cflag &= ~CRTSCTS;			//无硬件流控
		options.c_cflag |= CS8;					//8位数据长度
		options.c_cflag &= ~CSTOPB;				//1位停止位
		options.c_iflag |= IGNPAR;				//无奇偶检验位
		options.c_iflag &= ~(IXON|IXOFF|IXANY);
		options.c_oflag = 0; 					//输出模式
		options.c_lflag = 0; 					//不激活终端模式
		options.c_cc[VTIME] = 1;
		options.c_cc[VMIN] = 1;

		int rate = B115200;
		if( -1 == cfsetospeed(&options, rate) )
		{//设置波特率
			perror("cfsetospeed");
			debug("cfsetospeed error\n");
		}
		else
		{
		}

		/**3. 设置新属性，TCSANOW：所有改变立即生效*/
		tcflush(fd, TCIOFLUSH);//溢出数据可以接收，但不读
		tcsetattr(fd, TCSANOW, &options);
		//fcntl(fd, F_SETFL, FNDELAY);
		fcntl(fd, F_SETFL, 0);
		return (fd);
	}
}


int jz_uart_init_ex(const char * name, int rate)
{
    int ret;
    ret = serial_Open(name, rate, BIT_8 | STOP_1 |P_NONE);
    return ret;
}

int jz_uart_write_ex(int fd, u8 * buffer, int lens)
{
    int ret;
    ret = write(fd, buffer, lens);
#ifdef UART_VERB
	printf("\n----- send raw ------\n");
	dump_buffer(buffer, ret);
#endif
    return ret;
}

int jz_uart_read_ex_waitus(int fd, u8 * buffer, int lens, int waitus)
{
	int ret;
    ret = read(fd, buffer, lens);

    return ret;
}

int jz_uart_read_ex(int fd, u8 * buffer, int lens)
{
    int ret;
    ret = read(fd, buffer, lens);

    return ret;
}

/*-----------------------------EOF-----------------------------------*/

#if 0
int main()
{
	int rfd,ret;
	char value=0xf0;
	rfd=serial_Open("/dev/ttySP4",BAUD_9600,BIT_8 | STOP_1 |P_NONE );
//	Camera_Com_Init(rfd,BAUD_9600);
	char cmd[5]={0x52,0x44,0xff,0xf1,0x0d};
	char rcmd[128]={0};
	printf("the fd is [%d]\n",rfd);

#if 0

	while(1)
	{
		ret =read(rfd,rcmd,2);
		printf("ret =%d read is [%d]\n",ret,rcmd[0]);
	}
	ret =write(rfd,cmd,sizeof(cmd));
	return 0;
	while(1)
		{
		msleep(10);

		ret =write(rfd,&value,sizeof(value));
		printf("write  is [%d]\n",ret);

	}
	#else
	//ibea_set_param(Major,(char *)&value,2);
	while(1)
		{
		//usleep(10000);
		msleep(10);
		ret =write(rfd,cmd,5);
		printf("write  is [%d]\n",ret);
		ret =read(rfd,rcmd,2);
		printf("ret =%d read is [%d]\n",ret,rcmd[0]);
		}
	ret =read(rfd,rcmd,2);
	printf("ret =%d read is [%d]\n",ret,rcmd[0]);
	//}
#endif
	return 0;
}
#endif

