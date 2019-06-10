#ifndef __DOCK_UART_H__
#define __DOCK_UART_H__

#include "uart_protocal.h"
#include "jd_os_middleware.h"

typedef struct {
	int version;
	char file_path[256];
	FILE * file_handle;
	unsigned long size;
	unsigned char md5[MD5_SIZE];
	unsigned int packet_id;
	unsigned long offset;
	unsigned char aes_key[MAX_DOCK_PASSWORD_SIZE];
	char result;
}__attribute__((packed)) UPDATE_FILE_DES;


typedef struct {
	JD_OM_QUEUE send_queue;
	JD_OM_QUEUE recv_queue;
	pthread_t thread_handle_send;
	pthread_t thread_handle_recv;
}__attribute__((packed))UART_COMM_DES_T;

struct msgbuf {
	long type;
	char data[BUFSIZ];
};

typedef struct {
	void (*uart_get_dock_info_cb)(void *param);
	void (*uart_set_dock_password_cb)(void *param);
	void (*uart_get_dock_time_cb)(void *param);
	void (*uart_set_dock_time_cb)(void *param);
	void (*uart_show_status_msg_cb)(void *param);
	void (*uart_send_file_end_cb)(void *param);
	void (*uart_complete_all_files_cb)(void *param);
	void (*uart_set_dock_device_id_cb)(void *param);
	void (*uart_set_dock_sn_cb)(void *param);
	void (*uart_set_dock_volume_cb)(void *param);
	void (*uart_set_battery_ageing_cb)(void *param);
	void (*uart_get_battery_ageing_info_cb)(void *param);
} UART_RECV_CALLBACK_T;


void *thread_scan_uart_device(void *param);
int init_dock_service(char *port, char *addr, char *mask, void *hdl);
int jd_uart_get_dock_info();
int jd_uart_set_dock_password(char *password, int len);
int jd_uart_get_dock_time();
int jd_uart_set_dock_time(unsigned long time_sec, unsigned long time_usec);
int jd_uart_show_stat_msg(unsigned short service_code, unsigned char keep_alive);
int jd_uart_start_send_file(unsigned char type, char *file_path, unsigned char *md5);
int jd_uart_set_dock_device_id(unsigned char *device_id, int len);
int jd_uart_set_dock_sn(unsigned char *sn, int len);
int jd_uart_set_dock_volume(unsigned char volume);
int jd_uart_complete_all_files();
unsigned char jd_uart_is_dock_ready();
int jd_uart_is_initialized(void);
UART_RECV_CALLBACK_T *get_uart_recv_callback();
void reset_dock_update_file_info();

//int jd_uart_set_battery_ageing(unsigned char slot_num, ENUM_BATTERY_AGEING_SETTING type, unsigned int param, unsigned char param2);
int jd_uart_get_battery_ageing_info(unsigned char slot_num);




#endif
