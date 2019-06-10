#define _GNU_SOURCE 		/* See feature_test_macros(7) */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>

#include "jd_os_middleware.h"
#include "uart_protocal.h"
#include "os_uart.h"
#include "logcat.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

#define BATTERY_SN "JieDianTestBattery"

UART_COMM_DES_T uart_comm_des[1];
jd_om_comm uart_hdl;
static unsigned char active_req;
static unsigned char active_res;
static int last_packet_id = -1;
volatile unsigned char uart_packet_id = 0;


static UPDATE_FILE_DES update_file_des;

static pthread_mutex_t mutex_active_req = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_active_res = PTHREAD_MUTEX_INITIALIZER;

#define WAIT_RESPONSE_TIME_OUT (6000)
typedef enum {
	TYPE_INVALID = 0,
	TYPE_REQ,
	TYPE_RES,
} CMD_TYPE_T;

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

static unsigned char get_uart_packet_info()
{
	return uart_packet_id++;
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


void jd_dock_thread_delay(int msec)
{
	struct timeval timeOut;

	timeOut.tv_sec = msec / 1000;   //000;
	timeOut.tv_usec = 0;            //msec%1000;//000;
	while (0 != select(0, NULL, NULL, NULL, &timeOut)) ;
}

CMD_TYPE_T get_cmd_typte(unsigned char type)
{
	if ((type >= 0xC0 &&  type <= 0xDF) || (type >= 0xF0)) {
		return TYPE_REQ;
	}
	else if ((type >= 0xA0 && type <= 0xBF) || (type >= 0xE0 &&  type <= 0xEF)) {
		return TYPE_RES;
	}
	else {
		return TYPE_INVALID;
	}
}

static unsigned char is_req_type_valid(unsigned char type)
{
	if (type >= 0xC0 &&  type <= 0xDF || type >= 0xF0 &&  type <= 0xFF) {
		return 1;
	} else {
		//dzlog_error("invalid req type\r\n");
		return 0;
	}
}


static unsigned char is_res_type_valid(unsigned char type)
{
	if (type >= 0xA0 && type <= 0xBF || type >= 0xE0 &&  type <= 0xEF) {
		return 1;
	} else {
		//dzlog_error("invalid res type\r\n");
		return 0;
	}
}


unsigned char wait_response(int slave)
{
	unsigned char res;
	unsigned char req;
	int cnt = WAIT_RESPONSE_TIME_OUT;	//6s等待串口回应超时
	req = get_active_req();

	if (req == REQ_GPRS_CONNECT)
		cnt = WAIT_RESPONSE_TIME_OUT*10;

	while (cnt--) {
		res = get_active_res();
		if (0 != res) {
			req = get_active_req();

			res &= 0x0f;
			req &= 0x0f;

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

void reset_update_file_info()
{
	last_packet_id = -1;
	if (update_file_des.file_handle)
		fclose(update_file_des.file_handle);
	memset(&update_file_des, 0, sizeof(update_file_des));
}

static void stop_current_file_transmission(char *file_name)
{
	dzlog_error("stop %s transmission\n", file_name);
	reset_update_file_info();
#if 0
	if (uart_recv_callback) {
		if (uart_recv_callback->uart_send_file_end_cb) {
			RES_SEND_FILE_END_T res;
			res.code = 1;
			uart_recv_callback->uart_send_file_end_cb((void *)&res);
		}
	}
#endif
}


unsigned char g_cpu_id[12];

int get_encrypt_password(unsigned char *password)
{
#if 1
	char blank_device_id[12] = { 0 };
	if (0 == memcmp(blank_device_id, g_cpu_id, sizeof(g_cpu_id))) {
		dzlog_error("dock device id is blank\n");
		return -1;
	} else {
		unsigned char md5[16] = { 0 };
		get_md5(md5, g_cpu_id, 12, 1);
		for (int i = 0; i < 16; i++) {
			sprintf(&password[i * 2], "%02x", (unsigned int)md5[i]);
		}
		printf("password: %s\n", password);
		return 0;
	}
#else
	unsigned char t[MAX_DOCK_PASSWORD_SIZE] = {
		0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37,
		0x38, 0x38, 0x39, 0x39, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43, 0x44, 0x44, 0x45, 0x45, 0x46, 0x46
	};
	memcpy(password, t, MAX_DOCK_PASSWORD_SIZE);
	return 0;
#endif
}

bool is_trans_encrypted()
{
	return true;
}

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

static int send_file_start(unsigned char type, char *file_path, unsigned char *md5)
{
	int ret = 1;

	reset_update_file_info();

	if (is_trans_encrypted()) {
		ret = get_encrypt_password(update_file_des.aes_key);
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
	head->type = REQ_TRANS_FILE_HEAD;
	head->payload_len = payload_len;

	REQ_SEND_FILE_HEAD_T *req = (REQ_SEND_FILE_HEAD_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->type = type;
	req->size = is_trans_encrypted() ? get_encrypted_file_len(update_file_des.size) : update_file_des.size;

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
	head->type = REQ_TRANS_FILE_END;
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
		reset_update_file_info();
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

	if (is_trans_encrypted()) {
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
	head->type = REQ_TRANS_FILE_DATA;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SEND_FILE_BODY_T *req = (REQ_SEND_FILE_BODY_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->packet_id = update_file_des.packet_id;

	if (is_trans_encrypted())
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

int jd_uart_start_send_file(unsigned char type, char *file_path, unsigned char *md5)
{
	int ret = 1;

	ret = send_file_start(type, file_path, md5);
	return ret;
}

/*
RES_BAT_SET_SN_PSW
RES_BAT_GET_INFO
RES_BAT_ENCODE
RES_BAT_DECODE
RES_BAT_VIRTUAL_PWR_INFO
RES_BAT_DISCHARGE_LEVEL
RES_BAT_CHARGE_STATUS
RES_BAT_PROTOCAL_VERSION
RES_BAT_PPASSWD_CHKSUM
*/
int res_bat_set_sn()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_SET_SN_PSW_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_SET_SN_PSW;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_SET_SN_PSW_T *res = (RES_BAT_SET_SN_PSW_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->code = 5;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}
//RES_BAT_GET_INFO
int res_bat_get_info()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_GET_INFO_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_GET_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_GET_INFO_T *res = (RES_BAT_GET_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->code = 0;

	res->sn_len = strlen(BATTERY_SN);
	snprintf(res->sn, 32, "%s", BATTERY_SN);
	res->Temp = 23;
	res->Vol_H = 12;
	res->Vol_L = 34;
	res->ratio = 88;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//RES_BAT_ENCODE
int res_bat_encode()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_ENCODE_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_ENCODE;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_ENCODE_T *res = (RES_BAT_ENCODE_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->code = 3;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}
//RES_BAT_DECODE
int res_bat_decode()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_DECODE_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_DECODE;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_DECODE_T *res = (RES_BAT_DECODE_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->code = 2;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//RES_BAT_VIRTUAL_PWR_INFO
int res_bat_virt_pwr_info()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_VIRTUAL_PWR_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_VIRTUAL_PWR_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_VIRTUAL_PWR_T *res = (RES_BAT_VIRTUAL_PWR_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->data[0] = 56;
	res->data[1] = 44;
	res->data[2] = 78;
	res->data[3] = 65;
	res->data[4] = 1;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}
//RES_BAT_DISCHARGE_LEVEL
int res_bat_discharge_level()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_DISCHARGE_LEVEL_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_DISCHARGE_LEVEL;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_DISCHARGE_LEVEL_T *res = (RES_BAT_DISCHARGE_LEVEL_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->code = 1;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}
//RES_BAT_CHARGE_STATUS
int res_bat_charge_status()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_CHARGE_STATUS_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_CHARGE_STATUS;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_CHARGE_STATUS_T *res = (RES_BAT_CHARGE_STATUS_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->data[0] = 1;
	res->data[1] = 2;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//RES_BAT_PROTOCAL_VERSION
int res_bat_protocal_version()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_PROTOCAL_VERSION_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_PROTOCAL_VERSION;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_PROTOCAL_VERSION_T *res = (RES_BAT_PROTOCAL_VERSION_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->ver_len = 3;
	res->ver[0] = 1;
	res->ver[1] = 2;
	res->ver[2] = 3;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}
int res_bat_passwd_chksum()
{
	int ret = -1;
	int payload_len = sizeof(RES_BAT_PASSWD_CHKSUM_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = RES_BAT_PASSWD_CHKSUM;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	RES_BAT_PASSWD_CHKSUM_T *res = (RES_BAT_PASSWD_CHKSUM_T *)(pt + sizeof(MSG_UART_HEAD_T));
	res->crc[0] = 0x12;
	res->crc[1] = 0x34;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
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
	}
	else if (is_req_type_valid(type)) {
	}
	else {
		dzlog_error("invalid uart packet type\n");
		goto FREE;
	}

#if 0

	//获取加密标志
	unsigned char enc_flag = (head->pack_info) >> 7;
	if (is_uart_data_encoded != enc_flag) {
		dzlog_error("uart data encode flag dismatch\n");
		goto FREE;
	}

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
		case RES_DEVICE_INFO:
		{
			RES_DEVICE_INFO_T *res = (RES_DEVICE_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
			u32 cpuid[3];
			memcpy((char *)cpuid, res->cpuid, 12);
			dzlog_debug("get device info code %d sn:%s cpuid %08x-%08x-%08x, fw_ver %d.%d.%d hw_ver %d.%d.%d encrypted %d\n",
				res->code, res->sn, cpuid[2], cpuid[1], cpuid[0], res->fw_ver[0],res->fw_ver[1],res->fw_ver[2],
				res->hw_ver[0],res->hw_ver[1],res->hw_ver[2],res->Encrypted);
			memcpy(g_cpu_id, res->cpuid, 12);
			break;
		}
		case RES_SET_SN:
		{
			RES_SET_SN_T *res = (RES_SET_SN_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set sn ret %d\r\n", res->code);
			break;
		}

		case RES_GET_TIME:
		{
			RES_GET_TIME_T *res = (RES_GET_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));

			time_t rawtime = res->time_sec;
			struct tm *tmp = gmtime(&rawtime);
			char str[32] = { 0 };
			strftime(str, sizeof(str), "%x - %I:%M%p", tmp);

			dzlog_debug("get rtc time response, time %u.%u, %s \n", res->time_sec, res->time_usec, str);

			break;
		}


		case RES_SET_TIME:
		{
			RES_SET_TIME_T *res = (RES_SET_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set rtc time res %d\n", res->code);
			break;
		}

		case RES_FLASH_LED:
		{
			RES_SET_FLASH_LED_T *res = (RES_SET_FLASH_LED_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set flash led res %d\n", res->code);
			break;
		}
		case RES_SLOT_LED:
		{
			RES_SET_SLOT_LED_T *res = (RES_SET_SLOT_LED_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set slot led res %d\n", res->code);
			break;
		}
		case RES_SLOT_ELOCK:
		{
			RES_SET_SLOT_ELOCK_T *res = (RES_SET_SLOT_ELOCK_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set slot elock res %d\n", res->code);
			break;
		}
		case RES_SLOT_POWER:
		{
			RES_SET_SLOT_POWER_T *res = (RES_SET_SLOT_POWER_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("set slot power res %d\n", res->code);
			break;
		}
		case RES_SLOT_KEY_STAT:
		{
			RES_GET_SLOT_KEY_T *res = (RES_GET_SLOT_KEY_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("get slot key status %d code %d\n", res->key_status, res->code);
			break;
		}

		case RES_TRANS_FILE_HEAD:
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

		case RES_TRANS_FILE_DATA:
		{
			RES_SEND_FILE_BODY_T *res = (RES_SEND_FILE_BODY_T *)(pt + sizeof(MSG_UART_HEAD_T));
			if (old_ptk_id != res->packet_id) {
				old_ptk_id = res->packet_id;
				send_file_data(res->packet_id, res->code);
			}

			break;
		}

		case RES_TRANS_FILE_END:
		{
			RES_SEND_FILE_END_T *res = (RES_SEND_FILE_END_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("send file end code %d\n", res->code);
#if 0
			if (uart_recv_callback)
				if (uart_recv_callback->uart_send_file_end_cb)
					uart_recv_callback->uart_send_file_end_cb((void *)res);
#endif
			break;
		}



		case RES_BATTERY_ENCRYPT:
		{
			RES_BATTERY_ENCRYPT_T *res = (RES_BATTERY_ENCRYPT_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("battery encrtyp resonse %d\n", res->code);
			break;
		}
		case RES_BATTERY_INFO:
		{
			RES_BATTERY_INFO_T *res = (RES_BATTERY_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("get battery info code %d, sn %s temp %d vol %d ratio %d\n", res->code,
			res->sn,
			res->temperature,	//温度
			res->voltage,	//电压
			res->ratio);
			break;
		}
		case RES_GPRS_MODULE_INFO:
		{
			RES_GPRS_MODULE_INFO_T *res = (RES_GPRS_MODULE_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("get gprs module info res code %d, name %s iccid %s module %d simdcard %d gprs %d rssi %d\n",
				res->code,
				res->module_name,
				res->Iccid,
				res->module_ready,
				res->simcard_ready,
				res->gprs_ready,
				res->rssi);
			break;
		}
		case RES_GPRS_CONNECT:
		{
			RES_GPRS_CONNECT_T *res = (RES_GPRS_CONNECT_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("gprs connect resonse %d\n", res->code);
			break;
		}
		case RES_DEVICE_AGEING:
		{
			RES_AGEING_T *res = (RES_AGEING_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("device ageing resonse %d\n", res->code);
			break;
		}
		case RES_ENV_TEMPRATURE:
		{
			RES_TEMPRATURE_T *res = (RES_TEMPRATURE_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("get temperature resonse %d temperature %d\n", res->code, res->temperature);
			break;
		}

		case REQ_BAT_SET_SN_PSW:
		{
			REQ_BAT_SET_SN_PSW_T *req = (REQ_BAT_SET_SN_PSW_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("++++++set battery sn len %d sn %s psw_len %d psw %s\n",
				req->sn_len, req->sn, req->passwd_len, req->passwd);
			res_bat_set_sn();
			break;
		}
		case REQ_BAT_GET_INFO:
		{
			REQ_BAT_GET_INFO_T * req = (REQ_BAT_GET_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("++++++req get bat info opt %d\n", req->opt);
			res_bat_get_info();
			break;
		}
		case REQ_BAT_ENCODE:
		{
			dzlog_debug("++++++req bat encode\n");
			res_bat_encode();
			break;
		}
		case REQ_BAT_DECODE:
		{
			REQ_BAT_DECODE_T *req = (REQ_BAT_DECODE_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("++++++req bat decode passwd %s len %d\n", req->passwd, req->passwd_len);
			res_bat_decode();
			break;
		}
		case REQ_BAT_VIRTUAL_PWR_INFO:
		{
			dzlog_debug("++++++req virtual pwr info\n");
			res_bat_virt_pwr_info();
			break;
		}
		case REQ_BAT_DISCHARGE_LEVEL:
		{
			REQ_BAT_DISCHARGE_LEVEL_T *req = (REQ_BAT_DISCHARGE_LEVEL_T *)(pt + sizeof(MSG_UART_HEAD_T));
			dzlog_debug("++++++req discharge level %d\n", req->data[0]);
			res_bat_discharge_level();
			break;
		}case REQ_BAT_CHARGE_STATUS:
		{
			dzlog_debug("++++++req charge status\n");
			res_bat_charge_status();
			break;
		}
		case REQ_BAT_PROTOCAL_VERSION:
		{
			dzlog_debug("++++++req protocal version\n");
			res_bat_protocal_version();
			break;
		}
		case REQ_BAT_PASSWD_CHKSUM:
		{
			dzlog_debug("++++++req passwd chksum\n");
			res_bat_passwd_chksum();
			break;
		}
		default:
			break;
	}

FREE:
	free(pt);
	return 0;
}

static void *thread_uart_recv(void *p)
{
	int r_len;
	char buf[MAX_QUEUE_ELEMENT_SIZE] = { 0 };

	pthread_detach(pthread_self());

	while (1) {
		memset(buf, 0, MAX_QUEUE_ELEMENT_SIZE);
		jd_om_comm_addr from_addr;
		r_len = jd_om_recv(&uart_hdl, &from_addr, buf, MAX_QUEUE_ELEMENT_SIZE);
		if (r_len > 0) {
			//print_hex(buf, r_len);

			char *pt = calloc(r_len, 1);
			//dzlog_debug("recv calloc addr 0x%x\n", pt);
			memcpy(pt, buf, r_len);

			if (jd_om_mq_send(uart_comm_des[0].recv_queue, pt, r_len, 0))
				dzlog_error("%s:send recv queue error\n", __func__);
		}
	}
	return 0;
}

static void *thread_recv_queue(void *p)
{
	static char recv_update_reset_date[6]= {0xFF,12,0x5A,0x0,0x1,0xA5};
	pthread_detach(pthread_self());
	while (1) {
		//jd_dock_thread_delay(1);
		void *pt = NULL;
		int pkt_len = jd_om_mq_recv(uart_comm_des[0].recv_queue, &pt, 0);

		if (pkt_len >= 0) {
			//dzlog_debug("get recv queue %d len %d, pt=0x%x\n", 0, pkt_len, (unsigned int)(long)pt);
		} else {
			dzlog_error("get recv queue %d err:%d\n", 0, pkt_len);
			continue;
		}
		recv_data_dispatch(0, (void *)pt, pkt_len);
	}
	return 0;
}

static void *thread_send_queue(void *p)
{
	int ret;
	int lens;

	void *pt = NULL;
	int cnt_resend = 0;
	unsigned char sleep_array[] = {1, 2, 3, 5, 10, 15, 20 };
	unsigned char sleep_count = 0;

	pthread_detach(pthread_self());
	while (1) {
		jd_om_comm_addr to_addr;
		char slave_addr[16] = { 0 };
		lens = jd_om_mq_recv(uart_comm_des[0].send_queue, &pt, 0);

		print_hex(pt, lens);

		if (lens >= 0) {
			MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;
			unsigned char rq = head->type;
			sleep_count = 0;

			switch (get_cmd_typte(rq)) {
				case TYPE_INVALID:
				{
					dzlog_error("invalid type 0x%02x\n", rq);
					free(pt);
					continue;
				}
				case TYPE_RES:
				{
					sprintf(slave_addr, DOCK_ADDR);
					to_addr.addr = tlc_iaddr(slave_addr);
					ret = jd_om_send(&uart_hdl, &to_addr, pt, lens, 0);
					if (ret <= 0)
						dzlog_error("send to batt uart fail\n");
					continue;
				}
				case TYPE_REQ:
					goto SEND_REQ;
				default:
					break;
			}

SEND_REQ:
			set_active_req(head->type);
			cnt_resend = 1;
RESEND_DATA:
			set_active_res(0);

			sprintf(slave_addr, DOCK_ADDR);
			to_addr.addr = tlc_iaddr(slave_addr);
			ret = jd_om_send(&uart_hdl, &to_addr, pt, lens, 0);
			if (ret <= 0) {
				dzlog_error("send to batt uart fail\n");
				if (rq == REQ_TRANS_FILE_DATA) {
					if (cnt_resend++ <= 3) {
						sleep(2);
						goto RESEND_DATA;
					}
				}
			} else if (1 == wait_response(0)) {
				dzlog_error("response time out\n");
			}

			set_active_res(0xa0 | (0xf & get_active_req()));
			free(pt);

			if(cnt_resend > 3){
				//set_update_result_flag(false);
				//send_file_end_callback();//唤醒等待
			}
		} else {
			dzlog_error("get send queue err:%d\n", lens);
			dzlog_error("get send queue err:%d queue %s\n",
				    lens, jd_om_mq_destroyed(uart_comm_des[0].send_queue) ? "destroyed" : "normal");
			if (jd_om_mq_destroyed(uart_comm_des[0].send_queue))
				jd_om_thread_delay(1000 * sleep_array[sleep_count++]);
			else
				jd_om_thread_delay(1000);
			if (sleep_count >= sizeof(sleep_array))
				sleep_count--;
		}
	}
	return 0;
}



//REQ_DEVICE_INFO
int uart_get_device_info()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_DEVICE_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_SET_SN
int uart_set_sn(const char * sn)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_SN_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_SN;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_SN_T *req = (REQ_SET_SN_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->sn_len = 10;
	snprintf(req->sn, 16, "%s", sn);
	get_md5(req->sn_md5, req->sn, strlen(req->sn), 1);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_GET_TIME
int uart_get_rtc_time()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GET_TIME;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_SET_TIME
int uart_set_rtc_time(unsigned int seconds)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_TIME_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SET_TIME;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_TIME_T *req = (REQ_SET_TIME_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->time_sec = seconds;
	req->time_usec = 0;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_FLASH_LED
int uart_set_flash_led(u8 status)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_FLASH_LED_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_FLASH_LED;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_FLASH_LED_T *req = (REQ_SET_FLASH_LED_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->led_status = status;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}



//REQ_SLOT_LED
int uart_set_slot_led(u8 slot, u8 status)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_SLOT_LED_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SLOT_LED;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_SLOT_LED_T *req = (REQ_SET_SLOT_LED_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot;
	req->led_status= status;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_SLOT_ELOCK
int uart_set_slot_eclock(u8 slot, u8 stat)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_SLOT_ELOCK_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SLOT_ELOCK;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_SLOT_ELOCK_T *req = (REQ_SET_SLOT_ELOCK_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot;
	req->elock_status= stat;
	req->keep_time = 1200;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_SLOT_POWER
int uart_set_slot_power(u8 slot, u8 stat)
{
	int ret = -1;
	int payload_len = sizeof(REQ_SET_SLOT_POWER_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SLOT_POWER;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_SET_SLOT_POWER_T *req = (REQ_SET_SLOT_POWER_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot;
	req->power_status= stat;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_SLOT_KEY_STAT
int uart_get_slot_key_stat(u8 slot)
{
	int ret = -1;
	int payload_len = sizeof(REQ_GET_SLOT_KEY_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_SLOT_KEY_STAT;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_GET_SLOT_KEY_T *req = (REQ_GET_SLOT_KEY_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_BATTERY_ENCRYPT
int uart_battery_encrtypt()
{
	int ret = -1;
	int payload_len = sizeof(REQ_BATTERY_ENCRYPT_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_BATTERY_ENCRYPT;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_BATTERY_ENCRYPT_T *req = (REQ_BATTERY_ENCRYPT_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = 2;
	req->opt = 1;
	req->psw_len = 10;
	memcpy(req->psw, "1234567890", 10);

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_BATTERY_INFO
int uart_get_battery_info(int slot_num)
{
	int ret = -1;
	int payload_len = sizeof(REQ_BATTERY_INFO_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_BATTERY_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_BATTERY_INFO_T *req = (REQ_BATTERY_INFO_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->slot_num = slot_num;
	req->opt = 1;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_GPRS_MODULE_INFO
int uart_get_gprs_module_info()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GPRS_MODULE_INFO;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_GPRS_CONNECT
int uart_gprs_connect(u8 connect)
{
	int ret = -1;
	int payload_len = sizeof(REQ_GPRS_CONNECT_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_GPRS_CONNECT;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_GPRS_CONNECT_T *req = (REQ_GPRS_CONNECT_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->opt = connect;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}


//REQ_DEVICE_AGEING
int uart_device_ageing(u8 start, u32 seconds)
{
	int ret = -1;
	int payload_len = sizeof(REQ_AGEING_T);
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_DEVICE_AGEING;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	REQ_AGEING_T *req = (REQ_AGEING_T *)(pt + sizeof(MSG_UART_HEAD_T));
	req->opt = start ? 1 : 0;

	if (req->opt) {
		req->slot_list[0] = 0;
		req->slot_list[1] = 0;
		req->slot_list[2] = 0;
		req->slot_list[3] = 0;
	} else {
		req->slot_list[0] = 1;
		req->slot_list[1] = 1;
		req->slot_list[2] = 1;
		req->slot_list[3] = 1;
	}

	req->slot_list[4] = 1;
	req->slot_list[5] = 1;
	req->slot_list[6] = 1;
	req->slot_list[7] = 1;

	req->time_sec = seconds;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}

//REQ_ENV_TEMPRATURE
int uart_get_env_temperature()
{
	int ret = -1;
	int payload_len = 0;
	int pkt_len = sizeof(MSG_UART_HEAD_T) + payload_len + CHECKSUM_SIZE;

	unsigned char *pt = calloc(pkt_len, 1);

	MSG_UART_HEAD_T *head = (MSG_UART_HEAD_T *)pt;

	head->start = START_CMD;
	head->type = REQ_ENV_TEMPRATURE;
	head->pack_info = get_uart_packet_info();
	head->payload_len = payload_len;

	unsigned short checksum = crc16(pt, pkt_len - CHECKSUM_SIZE);
	memcpy((char *)pt + pkt_len - CHECKSUM_SIZE, &checksum, CHECKSUM_SIZE);


	ret = jd_om_mq_send(uart_comm_des[0].send_queue, pt, pkt_len, 0);
	if (ret) {
		dzlog_error("%s send msg error\n", __func__);
		free(pt);
	}


	return ret;
}



char str2hex(char str)
{
	if (str >= '0' && str <= '9')
		return str - '0';
	else if (str >= 'A' && str <= 'F')
		return str - 'A' + 0xA;
	else if (str >= 'a' && str <= 'f')
		return str - 'a' + 0xA;
	else
		return 0;
}

char * main_menu = "main menu\n"
"[01] device info\n"
"[02] write device sn\n"
"[03] read rtc\n"
"[04] write rtc\n"
"[05] led test\n"
"[06] elock test\n"
"[07] slot charge\n"
"[08] slot key\n"
"[09] battery info\n"
"[10] battery encrypt\n"
"[11] read gprs info\n"
"[12] gprs connect\n"
"[13] gprs disconnect\n"
"[14] ageing start\n"
"[15] ageing stop\n"
"[16] env temperature\n"
"[17] send file\n"
"[18] stress test\n"
"[00] exit\n";

char *led_menu = "led menu\n"
"0: off 1:on 2:blink\n"
"[1] led1\n"
"[2] led2\n"
"[3] led3\n"
"[4] led4\n"
"[5] led5\n"
"[6] led6\n"
"[7] led7\n"
"[8] led8\n"
"[9] qr led\n"
"[10] exit";

char *elock_menu = "elock menu\n"
"0: off 1:on\n"
"[1] lock1\n"
"[2] lock2\n"
"[3] lock3\n"
"[4] lock4\n"
"[5] lock5\n"
"[6] lock6\n"
"[7] lock7\n"
"[8] lock8\n"
"[9] exit";


char *charge_menu = "charge menu\n"
"0: off 1:on\n"
"[1] charge1\n"
"[2] charge2\n"
"[3] charge3\n"
"[4] charge4\n"
"[5] charge5\n"
"[6] charge6\n"
"[7] charge7\n"
"[8] charge8\n"
"[9] exit";

char *key_menu = "slot key menu\n"
"[1] key1\n"
"[2] key2\n"
"[3] key3\n"
"[4] key4\n"
"[5] key5\n"
"[6] key6\n"
"[7] key7\n"
"[8] key8\n"
"[9] exit";

char *battery_menu = "slot batterry menu\n"
"[1] batterry1\n"
"[2] batterry2\n"
"[3] batterry3\n"
"[4] batterry4\n"
"[5] batterry5\n"
"[6] batterry6\n"
"[7] batterry7\n"
"[8] batterry8\n"
"[9] exit";

static pthread_t thread_handle_uart_recv;

int main(int argc, char **argv)
{
	time_t t;
	time(&t);
	uart_packet_id = t % 255;
	printf("pkt id %d \n", uart_packet_id);

	jd_om_comm_addr local_addr;
	jd_om_comm_addr addr_mask;

	local_addr.addr = tlc_iaddr("1.0.0");
	addr_mask.addr = tlc_iaddr("255.255.255");

	if (argc < 2) {
		printf("need input uart num\n");
		return 0;
	}

	char port[16] = { 0 };
	snprintf(port, 16, "/dev/ttyUSB%d", atoi(argv[1]));

	int ret = jd_om_comm_open((jd_om_comm *)&uart_hdl, port, &local_addr, &addr_mask, 115200);
	if (0 != ret) {
		dzlog_error("open uart port %s fail ret %d\n", port, ret);
		return ret;
	}

	uart_comm_des[0].recv_queue = jd_om_mq_create(MAX_QUEUE_SIZE);
	uart_comm_des[0].send_queue = jd_om_mq_create(MAX_QUEUE_SIZE);

	pthread_create(&thread_handle_uart_recv, NULL, thread_uart_recv, NULL);
	usleep(1000);
	pthread_create(&uart_comm_des[0].thread_handle_recv, NULL, thread_recv_queue, NULL);
	usleep(1000);
	pthread_create(&uart_comm_des[0].thread_handle_send, NULL, thread_send_queue, NULL);
/*
	char *cpu_id = "393632363137510E0019003B";
	printf("cpuid:\n");
	for(int i = 0; i < 12; i++) {
		g_cpu_id[11-i] = 16*str2hex(cpu_id[2*i]) + str2hex(cpu_id[2*i+1]);
		printf("%02x", g_cpu_id[11-i]);
	}
	printf("\n");

*/


	while (1) {

MAIN_MENU:
		printf("%s",main_menu);
		int in = 0;

		//char str[128] = { 0 };
		//if (NULL == fgets(str, sizeof(str), stdin))
		//	continue;

		if (1 != fscanf(stdin, "%u", &in))
			continue;

		switch (in) {
			case 0:
				exit(0) ;
			case 1:
				uart_get_device_info();
				break;
			case 2:
				uart_set_sn("R323SA1234");
				break;

			case 3:
				uart_get_rtc_time();
				break;
			case 4:
			{
				time_t rawtime;
				time(&rawtime);
				uart_set_rtc_time(rawtime);
				break;
			}

			case 5:
				while (1) {
					printf("%s\n", led_menu);
					char s[32] = { 0 };

					if (NULL == fgets(s, sizeof(s), stdin))
						continue;

					u32 i = 0, t = 0;
					if (0 == sscanf(s, "%u %u", &i, &t))
						continue;

					switch (i) {
						case 1:
						case 2:
						case 3:
						case 4:
						case 5:
						case 6:
						case 7:
						case 8:
							uart_set_slot_led(i, t);
							break;
						case 9:
							uart_set_flash_led(t);
							break;
						case 10:
							goto MAIN_MENU;
					}
				}
				break;
			case 6:
				while (1) {
					printf("%s\n", elock_menu);
					char s[32] = { 0 };

					if (NULL == fgets(s, sizeof(s), stdin))
						continue;

					u32 i = 0, t = 0;
					if (0 == sscanf(s, "%u %u", &i, &t))
						continue;

					switch (i) {
						case 1:
						case 2:
						case 3:
						case 4:
						case 5:
						case 6:
						case 7:
						case 8:
							uart_set_slot_eclock(i, t);
							break;
						case 9:
							goto MAIN_MENU;
					}
				}
				break;
			case 7:
				while (1) {
					printf("%s\n", charge_menu);
					char s[32] = { 0 };

					if (NULL == fgets(s, sizeof(s), stdin))
						continue;

					u32 i = 0, t = 0;
					if (0 == sscanf(s, "%u %u", &i, &t))
						continue;

					switch (i) {
						case 1:
						case 2:
						case 3:
						case 4:
						case 5:
						case 6:
						case 7:
						case 8:
							uart_set_slot_power(i, t);
							break;
						case 9:
							goto MAIN_MENU;
					}
				}
				break;
			case 8:
				while (1) {
					printf("%s\n", key_menu);
					char s[32] = { 0 };

					if (NULL == fgets(s, sizeof(s), stdin))
						continue;

					u32 i = 0, t = 0;
					if (0 == sscanf(s, "%u %u", &i, &t))
						continue;

					switch (i) {
						case 1:
						case 2:
						case 3:
						case 4:
						case 5:
						case 6:
						case 7:
						case 8:
							uart_get_slot_key_stat(i);
							break;
						case 9:
							goto MAIN_MENU;
					}
				}
				break;

			case 9:
				while (1) {
					printf("%s\n", battery_menu);
					char s[32] = { 0 };

					if (NULL == fgets(s, sizeof(s), stdin))
						continue;

					u32 i = 0;
					if (0 == sscanf(s, "%u", &i))
						continue;

					switch (i) {
						case 1:
						case 2:
						case 3:
						case 4:
						case 5:
						case 6:
						case 7:
						case 8:
							uart_get_battery_info(i);
							break;
						case 9:
							goto MAIN_MENU;
					}
				}
				break;
			case 10:
				break;
			case 11:
				uart_get_gprs_module_info();
				break;
			case 12:
				uart_gprs_connect(1);
				break;
			case 13:
				uart_gprs_connect(0);
				break;
			case 14:
				uart_device_ageing(1, 10);
				break;
			case 15:
				uart_device_ageing(0, 0);
				break;
			case 16:
				uart_get_env_temperature();
				break;
			case 17:
				{
					uart_get_device_info();
					sleep(3);
					char cwd[256];
					if (getcwd(cwd, sizeof(cwd)) != NULL) {
						printf("Current working dir: %s\n", cwd);
					} else {
						perror("getcwd() error");
						break;
					}

					char file_path[256] = { 0 };//"/home/zf/work/y_embed/application/y_battery_ageing/pc/1.hex";
					snprintf(file_path, sizeof(file_path), "%s/%s", cwd, "1.hex");

					unsigned char md5[16] = { 0 };
					get_md5(md5, file_path, 0, 0);
					jd_uart_start_send_file(FW_FILE, file_path, md5);
				}
				break;
			case 18:
				while (1) {
					for (u8 i = 1; i <= 8; i++) {
						uart_set_slot_led(i, 1);
						sleep(1);
						uart_get_device_info();
						sleep(1);;
						uart_get_rtc_time();
						sleep(1);;
						uart_get_slot_key_stat(i);
						sleep(1);;
						uart_set_slot_led(i, 0);
						sleep(1);;
					}
				}
				break;
			default:
				break;
		}
	}

	while(1) {
		sleep(3);
#if 0
		uart_get_battery_info(2);
#endif

		continue;


		sleep(3);
		uart_set_sn("R201SA1012");
		sleep(3);
		time_t rawtime;
		time(&rawtime);
		uart_set_rtc_time(rawtime);
		sleep(3);
		uart_get_rtc_time();
		sleep(3);
		uart_set_flash_led(1);
		sleep(3);
		uart_set_slot_led(2, 1);
		//sleep(3);
		//uart_set_slot_eclock();
		sleep(3);
		uart_set_slot_power(2, 0);
		sleep(3);
		uart_get_slot_key_stat(2);
		sleep(3);
		uart_battery_encrtypt();
		sleep(3);
		uart_get_battery_info(2);
		sleep(3);
		uart_gprs_connect(1);
		sleep(3);
		uart_get_gprs_module_info();
		sleep(3);
		uart_device_ageing(0, 0);
		sleep(3);
		uart_get_env_temperature();
		sleep(3);
	}

	return 0;
}
