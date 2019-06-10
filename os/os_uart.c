#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <libgen.h>

#include "uart.h"
//#include "raw_uart.h"
#include "os_upgrade.h"
#ifdef J182J
#include "j182j.h"
#endif
#include "openssl/aes.h"
#include "openssl/evp.h"
//#include "compat-1.3.h"


#ifdef OMW
#include "jd_os_middleware.h"
#endif


#ifndef DOCK_TEST
#include "logcat.h"
#define LOG_TAG "BATTERY_AGEING"
#else
#define dzlog_info(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_debug(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_error(...) do { printf(__VA_ARGS__); } while (0)
#endif


#if 0
#include "api_ble.h"
#include "thread_ble_read.h"
static pthread_t thread_handle_ble;
#endif

#ifdef OMW
static jd_om_comm *uart_handle;
#else
#define MSQ_SND_ID (2000)
#define MSQ_RCV_ID (2001)
static int uart_handle = -1;
static int msqid_send;
static int msqid_recv;
#endif

#define WAIT_RESPONSE_TIME_OUT (6000)
static pthread_t thread_handle_uart_recv;


static UPDATE_FILE_DES update_file_des;

static const UART_RECV_CALLBACK_T *uart_recv_callback = NULL;


static UART_COMM_DES_T uart_comm_des[MAX_DOCK_COUNT];
static int uart_man_initialized = 0;

static unsigned char active_req;
static unsigned char active_res;
static int slave_map;
static int last_packet_id = -1;

static unsigned char is_uart_data_encoded;
static unsigned char uart_packet_id = 0;


static pthread_mutex_t mutex_active_req;
static pthread_mutex_t mutex_active_res;
static pthread_mutex_t mutex_slave_map;
static pthread_mutex_t mutex_get_uart_packet_info;

extern const UART_RECV_CALLBACK_T J182UartCallback;


static int aes_enc(unsigned char *src, int *src_len, unsigned char *des, int *des_len)
{
	int outLen1 = 0; int outLen2 = 0;
	unsigned char ivec[16] = { 0 };
	EVP_CIPHER_CTX ctx;

	int ret = EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), update_file_des.aes_key, ivec);

	if (1 != ret)
		return -1;
	ret = EVP_EncryptUpdate(&ctx, des, &outLen1, src, *src_len);
	if (1 != ret)
		return -1;
	ret = EVP_EncryptFinal(&ctx, des + outLen1, &outLen2);
	if (1 != ret)
		return -1;
	*des_len = outLen1 + outLen2;
	return 0;
}

void jd_dock_thread_delay(int msec)
{
	struct timeval timeOut;

	timeOut.tv_sec = msec / 1000;   //000;
	timeOut.tv_usec = 0;            //msec%1000;//000;
	while (0 != select(0, NULL, NULL, NULL, &timeOut)) ;
}

static unsigned char is_req_type_valid(unsigned char type)
{
	if (type > 0xCF || type < 0xC0) {
		dzlog_error("invalid req type\n");
		return 0;
	} else {
		return 1;
	}
}

static unsigned char is_res_type_valid(unsigned char type)
{
	if (type > 0xAF || type < 0xA0) {
		dzlog_error("invalid res type\n");
		return 0;
	} else {
		return 1;
	}
}

static unsigned char get_uart_packet_info()
{
	unsigned char ret;

	if (is_uart_data_encoded)
		ret = (((uart_packet_id++) & 0x7F) | 0x80);
	else
		ret = (uart_packet_id++) & 0x7F;
	return ret;
}

void print_hex(char *data, int len)
{
#ifdef UART_VERB
	int i;
	char hex[128] = { 0 };

	for (i = 0; i < len; i++) {
		if (0 == i % 16) {
			printf("%s\n", hex);
			memset(hex, 0, 128);
		}
		sprintf(hex + 3 * (i % 16), "%02x ", (unsigned char)data[i]);
	}
	printf("%s\n", hex);
#endif
}

static unsigned int get_slave_map()
{
	unsigned int ret;

	pthread_mutex_lock(&mutex_slave_map);
	ret = slave_map;
	pthread_mutex_unlock(&mutex_slave_map);
	return ret;
}

static void set_slave_map(unsigned int map)
{
	pthread_mutex_lock(&mutex_slave_map);
	slave_map = map;
	pthread_mutex_unlock(&mutex_slave_map);
	//dzlog_debug("set slave map as 0x%x\n", map);
}

static unsigned char get_active_res()
{
	unsigned char res = 0;

	pthread_mutex_lock(&mutex_active_res);
	res = active_res;
	pthread_mutex_unlock(&mutex_active_res);
	return res;
}

static void set_active_res(unsigned char res)
{
	pthread_mutex_lock(&mutex_active_res);
	active_res = res;
	pthread_mutex_unlock(&mutex_active_res);
	//dzlog_debug("set active res as 0x%02x\n", res);
}

static unsigned char get_active_req()
{
	unsigned char req = 0;

	pthread_mutex_lock(&mutex_active_req);
	req = active_req;
	pthread_mutex_unlock(&mutex_active_req);
	return req;
}

static void set_active_req(unsigned char req)
{
	pthread_mutex_lock(&mutex_active_req);
	active_req = req;
	pthread_mutex_unlock(&mutex_active_req);
	//dzlog_debug("set active req as 0x%02x\n", req);
}

unsigned char wait_response(int slave)
{
	unsigned char res;
	unsigned char req;
	int cnt = WAIT_RESPONSE_TIME_OUT;

	req = get_active_req();

	switch (req) {
	case REQ_SEND_FILE_HEAD:
	case REQ_SEND_FILE_BODY:
	case REQ_SEND_FILE_END:
	case REQ_COMPLETE_ALL_FILES:
		cnt = WAIT_RESPONSE_TIME_OUT * 3;
		break;
	default:
		cnt = WAIT_RESPONSE_TIME_OUT;
	}

	while (cnt--) {
		res = get_active_res();
		if (0 != res) {
			req = get_active_req();

			res &= 0xf;
			req &= 0xf;

			if (res == req)
				return 0;
		}
		usleep(1000);
	}

	return 1;
}

static unsigned int get_encrypted_file_len(unsigned int file_len)
{
	int cnt = file_len / MAX_UPDATE_DATA_PAYLOAD_SIZE;

	if (file_len % MAX_UPDATE_DATA_PAYLOAD_SIZE) {
		int end = ((file_len % MAX_UPDATE_DATA_PAYLOAD_SIZE) / 16 + 1) * 16;
		return cnt * (16 + MAX_UPDATE_DATA_PAYLOAD_SIZE) + end;
	} else {
		return cnt * (16 + MAX_UPDATE_DATA_PAYLOAD_SIZE);
	}
}


static void stop_current_file_transmission(char *file_name)
{
	dzlog_error("stop %s transmission\n", file_name);
	reset_dock_update_file_info();
	if (uart_recv_callback) {
		if (uart_recv_callback->uart_send_file_end_cb) {
			RES_SEND_FILE_END_T res;
			res.code = 1;
			uart_recv_callback->uart_send_file_end_cb((void *)&res);
		}
	}
}


static int send_file_start(unsigned char type, char *file_path, unsigned char *md5)
{
	int ret = 1;

	reset_dock_update_file_info();

	if (is_dock_encrypted()) {
		ret = get_dock_password(update_file_des.aes_key);
		if (0 != ret) {
			dzlog_error("fail to get dock passwd, ret %d\n", ret);
			stop_current_file_transmission(file_path);
			return ret;
		}
	}

	memcpy(update_file_des.file_path, file_path, strlen(file_path));
	memcpy(update_file_des.md5, md5, MD5_SIZE);

	update_file_des.size = get_file_size(update_file_des.file_path);
	if (0 >= update_file_des.size)
		return 1;

	update_file_des.file_handle = fopen(update_file_des.file_path, "r");
	if (NULL == update_file_des.file_handle) {
		dzlog_error("open update file fail.file:%s \n file copy:%s error:%s\n",
			    file_path, update_file_des.file_path, strerror(errno));
		return 1;
	}

	int payload_len = sizeof(REQ_SEND_FILE_HEAD_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->pack_info = get_uart_packet_info();
	head->type = REQ_SEND_FILE_HEAD;
	head->payload_len = payload_len;

	REQ_SEND_FILE_HEAD_T *req = (REQ_SEND_FILE_HEAD_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->type = type;
	req->size = is_dock_encrypted() ? get_encrypted_file_len(update_file_des.size) : update_file_des.size;

	char *bsname = basename(file_path);
	strcpy(req->file_name, bsname);
	printf("send file name : %s\n", bsname);

	memcpy(req->md5, md5, MD5_SIZE);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (0 == ret) {
		return 0;
	} else {
		dzlog_error("send file start to queue error\n");
		return 1;
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	free(pt);
	if (-1 == ret) {
		dzlog_error("%s send msg error %d\n", __func__, errno);
		return 1;
	} else {
		return 0;
	}

#endif
}


static int send_file_end()
{
	int ret = 1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SEND_FILE_END;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (0 == ret) {
		return 0;
	} else {
		dzlog_error("send file end to queue error\n");
		return 1;
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	free(pt);
	if (-1 == ret) {
		dzlog_error("%s send msg error %d\n", __func__, errno);
		return 1;
	} else {
		return 0;
	}
#endif
}

static int send_file_data(int packet_id, unsigned char code)
{
	int ret = 1, payload_len = 0, data_len = 0;
	unsigned char data[MAX_UPDATE_DATA_PAYLOAD_SIZE] = { 0 };
	unsigned char cypher[MAX_UPDATE_DATA_PAYLOAD_SIZE * 2] = { 0 };

	//dzlog_debug("==== %s packet_id %d code %d llast %d====\n", __func__, packet_id, code, last_packet_id);
	if ((0 != code && 1 != code) || (packet_id != update_file_des.packet_id &&
					 packet_id != update_file_des.packet_id - 1)) {
		dzlog_error("update data invalid param, code %d packet_id %d\n", code, packet_id);
		return 1;
	}

	if (1 == code) {
		update_file_des.packet_id = packet_id;
		update_file_des.offset = packet_id * MAX_UPDATE_DATA_PAYLOAD_SIZE;
		dzlog_debug("resend data\n");
	} else {
		if (last_packet_id < packet_id) {
			last_packet_id = packet_id;
		} else {
			if (packet_id > 0) {
				dzlog_debug("repeat update data ack\n");
				return 0;
			}
		}
	}

	if (update_file_des.offset == update_file_des.size) {
		reset_dock_update_file_info();
		send_file_end();
		return 0;
	}

	fseek(update_file_des.file_handle, update_file_des.offset, SEEK_SET);
	data_len = fread(data, 1, MAX_UPDATE_DATA_PAYLOAD_SIZE, update_file_des.file_handle);

	if (data_len < MAX_UPDATE_DATA_PAYLOAD_SIZE &&
	    data_len + update_file_des.offset != update_file_des.size) {
		dzlog_error("read update file error\n");
		stop_current_file_transmission(update_file_des.file_path);
		return 1;
	}

	if (is_dock_encrypted()) {
		if (0 != aes_enc(data, &data_len, cypher, &payload_len)) {
			dzlog_error("%s data aes encode error\n", update_file_des.file_path);
			stop_current_file_transmission(update_file_des.file_path);
			return 1;
		}
	} else {
		payload_len = data_len;
	}

	payload_len += 4;

	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SEND_FILE_BODY;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SEND_FILE_BODY_T *req = (REQ_SEND_FILE_BODY_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->packet_id = update_file_des.packet_id;

	if (is_dock_encrypted())
		memcpy((char *)&(req->packet_id) + 4, cypher, payload_len - 4);
	else
		memcpy((char *)&(req->packet_id) + 4, data, payload_len - 4);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (0 == ret) {
#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	free(pt);
	if (0 < ret) {
#endif

		update_file_des.packet_id++;
		update_file_des.offset += data_len;
		printf("sending file %s: %lu/%lu  pkt %d\r",
		       basename(update_file_des.file_path), update_file_des.offset,
		       update_file_des.size, update_file_des.packet_id);
		fflush(stdout);
		return 0;
	} else {
		dzlog_error("send file to queue error\n");
		return 1;
	}
}

int jd_uart_get_dock_info()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GET_DOCK_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}
#else

	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);

	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}


int jd_uart_set_dock_password(char *password, int len)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_DOCK_PSW_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_DOCK_PSW;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_DOCK_PSW_T *req = (REQ_SET_DOCK_PSW_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->cipher_len = len;
	memcpy(req->cipher, password, len);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else

	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);

	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}



int jd_uart_get_dock_time()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GET_DOCK_TIME;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_set_dock_time(unsigned long time_sec, unsigned long time_usec)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_DOCK_TIME_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_DOCK_TIME;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_DOCK_TIME_T *req = (REQ_SET_DOCK_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->time_sec = time_sec;
	req->time_usec = time_usec;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_complete_all_files()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_COMPLETE_ALL_FILES;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_set_dock_sn(unsigned char *sn, int len)
{
	if (NULL == sn)
		return -1;

	int ret = -1;

	int payload_len = sizeof(REQ_SET_DOCK_SN_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_DOCK_SN;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_DOCK_SN_T *req = (REQ_SET_DOCK_SN_T *)(pt + sizeof(MSG_UART_HEAD_T));
	memcpy(req->sn, sn, len);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_set_dock_device_id(unsigned char *device_id, int len)
{
	if (NULL == device_id)
		return -1;

	int ret = -1;
	int payload_len = sizeof(REQ_SET_DOCK_DEVICE_ID_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_DOCK_DEVICE_ID;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_DOCK_DEVICE_ID_T *req = (REQ_SET_DOCK_DEVICE_ID_T *)(pt + sizeof(MSG_UART_HEAD_T));
	memcpy(req->device_id, device_id, len);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_set_dock_volume(unsigned char volume)
{
	int ret = -1;

	int payload_len = sizeof(REQ_SET_DOCK_VOLUME_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_DOCK_VOLUME;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_DOCK_VOLUME_T *req = (REQ_SET_DOCK_VOLUME_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->volume = volume;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}

int jd_uart_show_stat_msg(unsigned short service_code, unsigned char keep_alive)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SHOW_STAT_MSG_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SHOW_STAT_MSG;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SHOW_STAT_MSG_T *req = (REQ_SHOW_STAT_MSG_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->service_code = service_code;
	req->keep_alive = keep_alive;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;
}


int jd_uart_start_send_file(unsigned char type, char *file_path, unsigned char *md5)
{
	int ret = 1;

	ret = send_file_start(type, file_path, md5);
	return ret;
}

int jd_uart_set_battery_ageing(unsigned char slot_num, ENUM_BATTERY_AGEING_SETTING type, unsigned int param, unsigned char param2)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_BATTERY_AGEING_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_BATTERY_AGEING;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_BATTERY_AGEING_T *req = (REQ_SET_BATTERY_AGEING_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->type = type;
	req->slot_num = slot_num;
	req->reserved = param;
	req->reserved2 = param2;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;

}

int jd_uart_get_battery_ageing_info(unsigned char slot_num)
{
	int ret = -1;
	int payload_len = sizeof(RES_GET_BATTERY_AGEING_INFO_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;
	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GET_BATTERY_AGEING_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_GET_BATTERY_AGEING_INFO_T *req = (REQ_GET_BATTERY_AGEING_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot_num;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);

#ifdef OMW
	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}

#else
	struct msgbuf msg;
	msg.type = 1;
	memcpy(msg.data, pt, pkt_len);
	ret = msgsnd(msqid_send, (void *)&msg, pkt_len, 0);
	if (-1 == ret)
		dzlog_error("%s send msg error %d\n", __func__, errno);
	free(pt);
#endif
	return ret;

}


static void *thread_uart_recv(void *p)
{
	pthread_detach(pthread_self());

	int r_len;
	char buf[MAX_QUEUE_ELEMENT_SIZE] = { 0 };

	while (1) {
		memset(buf, 0, MAX_QUEUE_ELEMENT_SIZE);
#ifdef OMW
		jd_om_comm_addr from_addr;
		r_len = jd_om_recv(uart_handle, &from_addr, buf, MAX_QUEUE_ELEMENT_SIZE);
		if (r_len > 0) {
			//dzlog_debug("uart recv from %d.%d.%d.%d\n",
			//	    from_addr.addr.lev_addr[0],
			//	    from_addr.addr.lev_addr[1],
			//	    from_addr.addr.lev_addr[2],
			//	    from_addr.addr.lev_addr[3]);
			print_hex(buf, r_len);

			char *pt = calloc(r_len, 1);
			//dzlog_debug("recv calloc addr 0x%x\n", pt);
			memcpy(pt, buf, r_len);

			//int slave = from_addr.addr.lev_addr[3] - SLAVE_START_ADDR;
			if (jd_om_mq_send(uart_comm_des[0].recv_queue, pt, r_len, 0)) {
				dzlog_error("%s:send recv queue error\n", __func__);
				free(pt);
			}
		}
#else
		r_len = read_uart_package(uart_handle, buf, MAX_QUEUE_ELEMENT_SIZE, 0);

		if (r_len > 0) {
			struct msgbuf msg;
			msg.type = 1;
			memcpy(&msg.data, buf, r_len);

			if (msgsnd(msqid_recv, (void *)&msg, r_len, 0) == -1)
				dzlog_error("%s send msg error\n", __func__);
		}
#endif
	}
	return 0;
}

static char recv_data_dispatch(unsigned char slave, void *pt, unsigned int len)
{
	static int old_ptk_id = -1;
	char payload[MAX_QUEUE_ELEMENT_SIZE] = { 0 };

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;
	// 获取start字段
	unsigned char start = head->start;

	//	判断start字段值是否正确
	if (START_CMD != start) {
		dzlog_error("invalid uart packet head\n");
		goto FREE;
	}

	//获取type字段
	unsigned char type = head->type;

	//判断type字段值是否正确
	if (is_res_type_valid(type)) {
		set_active_res(type);
	} else {
		dzlog_error("invalid uart packet type\n");
		goto FREE;
	}

	//获取加密标志
	unsigned char enc_flag = (head->pack_info) >> 7;
	if (is_uart_data_encoded != enc_flag) {
		dzlog_error("uart data encode flag dismatch\n");
		goto FREE;
	}
#if 0
	//获取pack_id
	unsigned char pack_id = (head->pack_info) & 0x7f;
	if (old_ptk_id != pack_id) {
		old_ptk_id = pack_id;
	} else {
		dzlog_error("repeat uart packet id\n");
		goto FREE;
	}
#endif
	//获取payload_len字段
	unsigned int payload_len = head->payload_len;

	//校验payload_len合法性
	if (payload_len >= MAX_QUEUE_ELEMENT_SIZE) {
		dzlog_error("invalid uart payload len %d\n", payload_len);
		goto FREE;
	}

	// 获取payload
	memset(payload, 0, MAX_QUEUE_ELEMENT_SIZE);
	memcpy(payload, pt + sizeof(MSG_UART_HEAD_T), payload_len);

	unsigned short chksum;
	memcpy(&chksum, pt + sizeof(MSG_UART_HEAD_T) + payload_len, sizeof(chksum));
	if (chksum != crc16(pt, len - CHECKSUM_SIZE)) {
		dzlog_error("checksum wrong");
		goto FREE;
	}

	switch (type) {
	case RES_GET_DOCK_INFO:
	{
		RES_GET_DOCK_INFO_T *res = (RES_GET_DOCK_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
		res->sn[MAX_DOCK_SN_SIZE - 1] = 0;
		//dzlog_debug("get dock info response\n");
		printf("dock fw version : %d.%d.%d\n", res->fw_ver[1],
		       res->fw_ver[2], res->fw_ver[3]);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_get_dock_info_cb)
				uart_recv_callback->uart_get_dock_info_cb((void *)res);
		break;
	}

	case RES_SET_DOCK_PSW:
	{
		RES_SET_DOCK_PSW_T *res = (RES_SET_DOCK_PSW_T *)(pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("set dock password response, code %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_dock_password_cb)
				uart_recv_callback->uart_set_dock_password_cb((void *)res);

		break;
	}

	case RES_GET_DOCK_TIME:
	{
		RES_GET_DOCK_TIME_T *res = (RES_GET_DOCK_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));
		//dzlog_debug("get dock time response, time %ld:%ld\n", res->time_sec, res->time_usec);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_get_dock_time_cb)
				uart_recv_callback->uart_get_dock_time_cb((void *)res);

		break;
	}

	case RES_SET_DOCK_TIME:
	{
		RES_SET_DOCK_TIME_T *res = (RES_SET_DOCK_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));
		//dzlog_debug("set dock time response, code %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_dock_time_cb)
				uart_recv_callback->uart_set_dock_time_cb((void *)res);

		break;
	}

	case RES_SHOW_STAT_MSG:
	{
		RES_SHOW_STAT_MSG_T *res = (RES_SHOW_STAT_MSG_T *)(pt + sizeof(MSG_UART_HEAD_T));
		//dzlog_debug("show status response, code %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_show_status_msg_cb)
				uart_recv_callback->uart_show_status_msg_cb((void *)res);

		break;
	}

	case RES_SEND_FILE_HEAD:
	{
		old_ptk_id = 1;
		RES_SEND_FILE_HEAD_T *res = (RES_SEND_FILE_HEAD_T *)(pt + sizeof(MSG_UART_HEAD_T));
		if (0 == res->code) {
			send_file_data(0, 0);
		} else {
			dzlog_error("send file head of %s to dock response %d\n", update_file_des.file_path, res->code);
			stop_current_file_transmission(update_file_des.file_path);
		}
		break;
	}

	case RES_SEND_FILE_BODY:
	{
		RES_SEND_FILE_BODY_T *res = (RES_SEND_FILE_BODY_T *)(pt + sizeof(MSG_UART_HEAD_T));
		if (old_ptk_id != res->packet_id) {
			old_ptk_id = res->packet_id;
			send_file_data(res->packet_id, res->code);
		}

		break;
	}

	case RES_SEND_FILE_END:
	{
		RES_SEND_FILE_END_T *res = (RES_SEND_FILE_END_T *)(pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("send file end code %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_send_file_end_cb)
				uart_recv_callback->uart_send_file_end_cb((void *)res);

		break;
	}

	case RES_COMPLETE_ALL_FILES:
	{
		RES_COMPLETE_ALL_FILES_T *res = (RES_COMPLETE_ALL_FILES_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("complete all files response %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_complete_all_files_cb)
				uart_recv_callback->uart_complete_all_files_cb((void *)res);

		break;
	}

	case RES_SET_DOCK_SN:
	{
		RES_SET_DOCK_SN_T *res = (RES_SET_DOCK_SN_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("set sn response %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_dock_sn_cb)
				uart_recv_callback->uart_set_dock_sn_cb((void *)res);

		break;
	}


	case RES_SET_DOCK_DEVICE_ID:
	{
		RES_SET_DOCK_DEVICE_ID_T *res = (RES_SET_DOCK_DEVICE_ID_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("set device id response %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_dock_device_id_cb)
				uart_recv_callback->uart_set_dock_device_id_cb((void *)res);

		break;
	}

	case RES_SET_DOCK_VOLUME:
	{
		RES_SET_DOCK_VOLUME_T *res = (RES_SET_DOCK_VOLUME_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("set volume response %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_dock_volume_cb)
				uart_recv_callback->uart_set_dock_volume_cb((void *)res);

		break;
	}

	case RES_SET_BATTERY_AGEING:
	{
		RES_SET_BATTERY_AGEING_T *res = (RES_SET_BATTERY_AGEING_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("set battery ageing response %d\n", res->code);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_set_battery_ageing_cb)
				uart_recv_callback->uart_set_battery_ageing_cb((void *)res);

		break;
	}

	case RES_GET_BATTERY_AGEING_INFO:
	{
		RES_GET_BATTERY_AGEING_INFO_T *res = (RES_GET_BATTERY_AGEING_INFO_T *)((char *)pt + sizeof(MSG_UART_HEAD_T));
		dzlog_debug("get battery ageing info total %d\n", res->total_slot_num);

		if (uart_recv_callback)
			if (uart_recv_callback->uart_get_battery_ageing_info_cb)
				uart_recv_callback->uart_get_battery_ageing_info_cb((void *)res);

		break;
	}


	default:
		break;
	}

FREE:

#ifdef OMW
	free(pt);
#endif

	return 0;
}

static void *thread_recv_queue(void *p)
{
	pthread_detach(pthread_self());

	while (1) {
#ifdef OMW
		//jd_dock_thread_delay(1);
		void *pt = NULL;
		int pkt_len = jd_om_mq_recv(uart_comm_des[0].recv_queue, &pt, 0);

		if (pkt_len >= 0) {
			//dzlog_debug("get recv queue %d len %d, pt=0x%x\n", 0, pkt_len, (unsigned int)(long)pt);
		} else {
			dzlog_error("get recv queue %d err:%d\n", 0, pkt_len);
			continue;
		}
		print_hex(pt, pkt_len);
		recv_data_dispatch(0, (void *)pt, pkt_len);
#else
		struct msgbuf msg;
		int msg_len = msgrcv(msqid_recv, (void *)&msg, BUFSIZ, 1, 0);
		if (msg_len == -1) {
			dzlog_error("%s msgrecv error %d\n", __func__, errno);
		} else {
			dzlog_debug("%s recv msg len = %d\n", __func__, msg_len);
			print_hex(msg.data, msg_len);
		}
		recv_data_dispatch(0, (void *)&msg.data, msg_len);
#endif
	}
	return 0;
}


static void *thread_send_queue(void *p)
{
	pthread_detach(pthread_self());

	int ret;
	int lens;

	void *pt = NULL;
	int cnt_resend = 0;
	unsigned char sleep_array[] = { 1, 2, 3, 5, 10, 15, 20 };
	unsigned char sleep_count = 0;

	while (1) {
#ifdef OMW
		jd_om_comm_addr to_addr;
		char slave_addr[16] = { 0 };
		lens = jd_om_mq_recv(uart_comm_des[0].send_queue, &pt, 0);
#else

#if 0
		struct msqid_ds buf;
		if (msgctl(msqid_send, IPC_STAT, &buf) == -1)
			fprintf(stderr, "thread_send get msq status fail\n");
		else
			printf("before recv msg queue num : %ld\n, cur_size %ld , max_size %ld\n",
			       buf.msg_qnum, buf.__msg_cbytes, buf.msg_qbytes);

#endif

		struct msgbuf msg;
		lens = msgrcv(msqid_send, (void *)&msg, BUFSIZ, 1, MSG_NOERROR);
		if (lens == -1)
			dzlog_error("%s msgrecv error %d\n", __func__, lens);
		else
			dzlog_debug("%s recv msg len = %d\n", __func__, lens);

		pt = (void *)msg.data;
#endif
		print_hex(pt, lens);

		if (lens >= 0) {
			MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;
			unsigned char rq = head->type;
			sleep_count = 0;
			if (!is_req_type_valid(rq)) {
				dzlog_error("invalid request 0x%02x\n", rq);
#ifdef OMW
				free(pt);
#endif
				continue;
			}

			set_active_req(head->type);
			cnt_resend = 1;
RESEND_DATA:
			set_active_res(0);
#ifdef OMW
			sprintf(slave_addr, DOCK_ADDR);
			to_addr.addr = tlc_iaddr(slave_addr);
			ret = jd_om_send(uart_handle, &to_addr, pt, lens, 0);
			if (ret <= 0) {
				LOGD("send to dock uart fail\n");
				if (rq == REQ_SEND_FILE_BODY) {
					if (cnt_resend++ <= 3) {
						sleep(2);
						goto RESEND_DATA;
					}
				}
			} else if (1 == wait_response(0)) {
				dzlog_error("wait for response of 0x%02x timeout\n", rq);

				/* 传输文件中响应超时按失败处理 */
				switch (rq) {
				case REQ_SEND_FILE_HEAD:
				case REQ_SEND_FILE_BODY:
				case REQ_SEND_FILE_END:
				{
					stop_current_file_transmission(update_file_des.file_path);
					break;
				}
				default:
					break;
				}
			}

			set_active_res(0xa0 | (0xf & get_active_req()));
			free(pt);

#else
			//ret = write_uart_package(uart_handle, pt, lens);
			ret = write(uart_handle, pt, lens);
			printf("write to uart %d len %d\n", uart_handle, ret);
			if (ret <= 0)
				LOGD("uart send to dock fail\n");
			else if (wait_response(0))
				dzlog_error("dock uart response time out\n");
			set_active_res(0xa0 | (0xf & get_active_req()));

#endif
			if (get_slave_map()) {
				if (cnt_resend > 3)
					set_slave_map(0x0);
			} else {
				if (cnt_resend <= 3)
					set_slave_map(0x1);
			}
		} else {
			dzlog_error("get send queue err:%d\n", lens);
#ifdef OMW


			dzlog_error("get send queue err:%d queue %s\n",
				    lens, jd_om_mq_destroyed(uart_comm_des[0].send_queue) ? "destroyed" : "normal");
			if (jd_om_mq_destroyed(uart_comm_des[0].send_queue))
				jd_om_thread_delay(1000 * sleep_array[sleep_count++]);
			else
				jd_om_thread_delay(1000);
			if (sleep_count >= sizeof(sleep_array))
				sleep_count--;
#endif
		}
	}
	return 0;
}


int init_dock_service(char *port, char *addr, char *mask, void *hdl)
{
	int ret;

	/* 1. mutex init */
	if (pthread_mutex_init(&mutex_active_req, NULL) < 0) {
		dzlog_error("mutex_active_req init error\n");
		return -1;
	}

	if (pthread_mutex_init(&mutex_active_res, NULL) < 0) {
		dzlog_error("mutex_active_res init error\n");
		return -2;
	}

	if (pthread_mutex_init(&mutex_slave_map, NULL) < 0) {
		dzlog_error("mutex_slave_map init error\n");
		return -3;
	}

	if (pthread_mutex_init(&mutex_get_uart_packet_info, NULL) < 0) {
		dzlog_error("mutex_mutex_get_uart_packet_info error\n");
		return -6;
	}

#ifdef J182J
#ifndef DOCK_TEST
	uart_recv_callback = &J182UartCallback;
#else
	extern UART_RECV_CALLBACK_T uart_recv_callback_test;
	uart_recv_callback = &uart_recv_callback_test;
#endif
#else
	extern UART_RECV_CALLBACK_T battery_ageing_uart_recv_cb;
	uart_recv_callback = &battery_ageing_uart_recv_cb;
#endif
	/* 2. uart init */
#ifdef OMW

	jd_om_comm_addr local_addr;
	jd_om_comm_addr addr_mask;

	local_addr.addr = tlc_iaddr(addr);
	addr_mask.addr = tlc_iaddr(mask);


	ret = jd_om_comm_open((jd_om_comm *)hdl, port, &local_addr, &addr_mask, UART_SPEED);
	if (0 != ret) {
		dzlog_error("open uart port %s fail ret %d\n", port, ret);
		return ret;
	}

	uart_handle = hdl;


#else

	if (0 > uart_handle) {
		uart_handle = open_uart(port);
		if (0 > uart_handle) {
			dzlog_error("open uart port %s fail ret %d\n", port, uart_handle);
			return -7;
		}
	}

#endif


	/* 3.create send msg queue and recv msg queue */
#ifdef OMW
	uart_comm_des[0].send_queue = jd_om_mq_create(MAX_QUEUE_SIZE);
	uart_comm_des[0].recv_queue = jd_om_mq_create(MAX_QUEUE_SIZE);
#else

	msqid_send = msgget((key_t)MSQ_SND_ID, 0666 | IPC_CREAT);
	if (-1 == msqid_send) {
		dzlog_error("create msq error %d\n", msqid_send);
		return -9;
	}

	msqid_recv = msgget((key_t)MSQ_RCV_ID, 0666 | IPC_CREAT);
	if (-1 == msqid_recv) {
		dzlog_error("create msq error %d\n", msqid_recv);
		return -10;
	}

#endif

	set_active_res(0);
	set_active_req(0);

	/* 4. create send msg thread and recv msg thread */
	pthread_create(&thread_handle_uart_recv, NULL, thread_uart_recv, NULL);
	usleep(1000);
	pthread_create(&uart_comm_des[0].thread_handle_recv, NULL, thread_recv_queue, NULL);
	usleep(1000);
	pthread_create(&uart_comm_des[0].thread_handle_send, NULL, thread_send_queue, NULL);

	uart_man_initialized = 1;

	return 0;
}

int jd_uart_is_initialized(void)
{
	return uart_man_initialized;
}

unsigned char jd_uart_is_dock_ready()
{
	return !!(get_slave_map());
}


int jd_uart_exit(void)
{
#ifdef OMW
	if (NULL == uart_handle)
		return 0;
	jd_om_comm_close(uart_handle);

	for (int i = 0; i < MAX_DOCK_COUNT; i++) {
		jd_om_delete_mq(uart_comm_des[i].recv_queue);
		jd_om_delete_mq(uart_comm_des[i].send_queue);
	}

#else
	if (-1 == uart_handle)
		return 0;
	close(uart_handle);
#endif

	return 0;
}

#if 0
void *thread_scan_uart_device(void *param)
{
	pthread_detach(pthread_self());

	char buf[128] = { 0 };
	int ret;
	char *dev_name = (char *)param;

	if (NULL == dev_name) {
		printf("empty uart device name\n");
		return 0;
	}

	while (1) {
		/* 1. init uart */
		if (0 > uart_handle) {
			uart_handle = open_uart(dev_name);
			if (0 > uart_handle) {
				sleep(1);
				continue;
			}
		}

		/* 2. get uart device name */
		if (operater_bluetooth_mode(uart_handle, 0, buf, sizeof(buf)) < 0) {
			sleep(1);
			continue;
		}

		dzlog_info("get uart device name : %s\n", buf);

		/* 3. init uart device service */
		if (strstr(buf, DOCK_NAME)) {
			ret = init_dock_service(dev_name, "1.0.0", "255.0.0", NULL);
			if (ret != 0)
				dzlog_error("init dock uart error %d\n", ret);
			break;
		} else {
#ifndef DOCK_TEST
			ret = pthread_create(&thread_handle_ble, NULL, thread_ble_recv_msg, NULL);
			if (ret != 0)
				dzlog_error("create blue recv msg pthread fail %d\n", ret);

#endif
			break;
		}
	}

	return 0;
}
#endif

void reset_dock_update_file_info()
{
	last_packet_id = -1;
	if (update_file_des.file_handle)
		fclose(update_file_des.file_handle);
	memset(&update_file_des, 0, sizeof(update_file_des));
}
