#ifndef  _DOCK_UPGRADE_H_
#define  _DOCK_UPGRADE_H_

#include "uart_protocal.h"

#ifdef ARCH_ARM
#define UPGRADE_FW_BASE         "/root/data/j182j/"
#define UPGRADE_FW_FOLDER       "/root/data/j182j/upgrade/"
#define DOCK_ADV_FOLDER         "/root/data/j182j/adv/"
#define DOCK_ADV_MD5_FOLDER     "/root/data/j182j/adv/md5/"
#define DOCK_AUDIO_FOLDER       "/root/data/j182j/audio/"
#else
#define UPGRADE_FW_BASE         "/home/zf/work/y_embed/application/y_j182j/"
#define UPGRADE_FW_FOLDER       "/home/zf/work/y_embed/application/y_j182j/fw/"
#define DOCK_ADV_FOLDER         "/home/zf/work/y_embed/application/y_j182j/adv/"
#define DOCK_ADV_MD5_FOLDER     "/home/zf/work/y_embed/application/y_j182j/adv/md5/"
#define DOCK_AUDIO_FOLDER       "/home/zf/work/y_embed/application/y_j182j/audio/"
#endif

#define UPGRADE_FW_FILE_PREFIX  "JD-J182J-APP_"
#define UPGRADE_FW_FILE_SUFFIX  ".bin"
#define MD5_FILE_SUFFIX         ".md5"
#define SCHEDUAL_FILE_SUFFIX    ".txt"
#define JPG_FILE_SUFFIX         ".jpg"
#define BMP_FILE_SUFFIX         ".bmp"
#define PNG_FILE_SUFFIX         ".png"
#define MP3_FILE_SUFFIX         ".mp3"

#define MAX_SCHEDULE_FILE_SIZE  (1024 * 1024 * 2)
#define MAX_FILE_PATH_SIZE      (256)
#define MAX_MATERARIAL_CNT      (256)
#define MAX_FILE_NAME_LEN       (16)

#define GET_DOCK_INFO_TIMEOUT         (12)
#define SEND_FW_FILE_TIMEOUT          (300)
#define SEND_SCHEDULE_FILE_TIMEOUT    (30)
#define SEND_MATERIAL_FILE_TIMEOUT    (300)
#define GET_DOCK_INFO_CYCLE           (60)
#define WAIT_DOCK_UPGRADE_TIME        (10)

typedef enum _SEND_FILE_STATUS_T {
	NO_FILE_SENDING = 0,
	FW_FILE_SENDING,
	SCHEDULE_FILE_SENDING,
	PICTURE_FILE_SENDING,
	AUDIO_FILE_SENDING,
} SEND_FILE_STATUS_T;

typedef struct {
	unsigned char need_upgrade;
	unsigned int id;
    char name[MAX_FILE_NAME_LEN];
	unsigned char md5[MD5_SIZE];
}__attribute__((packed)) MATERIAL_UPGRADE_INFO_T;

typedef struct {
	MATERIAL_UPGRADE_INFO_T picture;
	MATERIAL_UPGRADE_INFO_T audio;
}__attribute__((packed)) ITEM_UPGRADE_INFO_T;

typedef struct {
	unsigned char need_upgrade;
	unsigned int id;
    char name[MAX_FILE_NAME_LEN];
	unsigned char md5[MD5_SIZE];
	int item_cnt;
	ITEM_UPGRADE_INFO_T *item;
}__attribute__((packed)) SCHEDULE_UPGRADE_INFO_T;


typedef struct {
	unsigned char is_busy;
    char is_encrypted;
	unsigned char dock_fw_ver[DOCK_VERSION_SIZE];
	unsigned char dock_hw_ver[DOCK_VERSION_SIZE];
	char sn[MAX_DOCK_SN_SIZE];
	char device_id[MAX_DOCK_DEVICE_ID_SIZE];
	unsigned char need_upgrade_fw;
	unsigned char need_upgrade_schedule;
	SEND_FILE_STATUS_T upgrade_status;
	unsigned int sending_item_id;
	SCHEDULE_UPGRADE_INFO_T schedule;
}__attribute__((packed)) DOCK_UPGRADE_INFO_T;

typedef enum _UPGRADE_STATUS {
	UPGRADE_STATUS_UPGRADE_INQUIRY	= 0,
	UPGRADE_STATUS_UPGRADE_NONE	= 1,
	UPGRADE_STATUS_UPGRADE_ON_GOING = 2
} UPGRADE_STATUS;

typedef struct {
	int id;
	char name[MAX_FILE_NAME_LEN];
	unsigned char md5[MD5_SIZE];
} MAT_INFO_T;

typedef struct {
	MAT_INFO_T picture;
	MAT_INFO_T audio;
} ITEM_INFO_T;

typedef struct {
	int sch_id;
	int item_cnt;
	ITEM_INFO_T item[MAX_MATERARIAL_CNT];
} SCH_FILE_INFO_T;

typedef struct {
	int id;
	char	file_name[MAX_FILE_NAME_LEN];
	int file_mtime;
} FILE_INFO_T;

int dock_upgrade_init();
UPGRADE_STATUS dock_upgrade_status(void);
void update_dock_upgrade_status_cb(int sub_num, int upgrade_status);
void sync_dock_board_time(void);
void *dock_upgrade_process_thread(void *arg);

int get_local_adv_file_info();
void force_dock_schedule_info();
void print_dock_info();
int compare_adv_files();
int get_local_fw_file_info(unsigned char *version, char *file_name, unsigned char *md5);
void get_dock_info_callback(void *p);
void send_file_end_callback(void *p);
int dock_upgrade_init();
void wake_upgrade();
char is_dock_encrypted();
int copy_file(const char *to, const char *from);
int remove_other_upgrade_files(char *name);
int get_dock_password(unsigned char *password);
int wait_dock_response(int type, int sec);



#endif
