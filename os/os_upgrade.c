#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "os_uart.h"
#include "os_upgrade.h"
#include "cJSON.h"

#ifdef J182J
#include "j182j.h"
#endif

#ifndef DOCK_TEST
#include "logcat.h"
#define LOG_TAG "J182"
#else
#define dzlog_info(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_debug(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_error(...) do { printf(__VA_ARGS__); } while (0)
#endif

static SCHEDULE_UPGRADE_INFO_T *g_local_sch = NULL;
static SCHEDULE_UPGRADE_INFO_T *g_dock_sch = NULL;


static DOCK_UPGRADE_INFO_T g_upgrade_info;
static bool g_recv_upgrade_cmd = false;
static volatile bool is_dock_info_read = true;
pthread_t thread_dock_upgrade;

pthread_cond_t res_end_file_cond;
pthread_cond_t res_get_info_cond;
pthread_cond_t res_set_battery_ageing_cond;
pthread_cond_t res_get_battery_ageing_info_cond;
pthread_mutex_t res_mutex;

typedef struct {
	int	type;
	int	sec;
} WAIT_PARAM_T;

void *thread_wait_time(void *p)
{
	WAIT_PARAM_T *wait_p = (WAIT_PARAM_T *)p;
	void *ret = calloc(sizeof(int), 1);
	int sec = wait_p->sec;
	int type = wait_p->type;

	struct timeval now;
	struct timespec time_out;

	if (NULL == ret) {
		dzlog_error("calloc fail\n");
		return 0;
	}

	pthread_mutex_lock(&res_mutex);
	gettimeofday(&now, NULL);
	time_out.tv_sec = now.tv_sec + sec;
	time_out.tv_nsec = 0;
	switch (type) {
#ifdef J182J
	case RES_SEND_FILE_END:
	{
		*(int *)ret = pthread_cond_timedwait(&res_end_file_cond, &res_mutex, &time_out);
		if (*(int *)ret)
			LOGD("send file end timedwait ret %d\n", *(int *)ret);
	} break;

	case RES_GET_DOCK_INFO:
	{
		*(int *)ret = pthread_cond_timedwait(&res_get_info_cond, &res_mutex, &time_out);
		if (*(int *)ret)
			LOGD("get dock info timedwait ret %d\n", *(int *)ret);
	} break;

#else

	case RES_SET_BATTERY_AGEING:
	{
		*(int *)ret = pthread_cond_timedwait(&res_set_battery_ageing_cond, &res_mutex, &time_out);
		if (*(int *)ret)
			LOGD("set battery discharge ret %d\n", *(int *)ret);

	} break;

	case RES_GET_BATTERY_AGEING_INFO:
	{
		*(int *)ret = pthread_cond_timedwait(&res_get_battery_ageing_info_cond, &res_mutex, &time_out);
		if (*(int *)ret)
			LOGD("get battery discharge info ret %d\n", *(int *)ret);

	} break;

#endif
	default:
		*(int *)ret = -1;
		break;
	}
	pthread_mutex_unlock(&res_mutex);

	return ret;
}

int wait_dock_response(int type, int sec)
{
	pthread_t thread_wait;
	WAIT_PARAM_T p;
	int ret = -1;

	p.type = type;
	p.sec = sec;

	if (pthread_create(&thread_wait, NULL, thread_wait_time, &p)) {
		dzlog_error("error when create pthread,%d\n", errno);
		return 1;
	}

	void *n = 0;
	pthread_join(thread_wait, &n);
	if (NULL == n) {
		ret = -1;
	} else {
		ret = *(int *)n;
		free(n);
	}

	return ret;
}

void get_dock_info_callback(void *p)
{
	if (NULL == p)
		return;

	if (!is_dock_info_read)
		return;
	else
		is_dock_info_read = false;

	RES_GET_DOCK_INFO_T *dock_info = (RES_GET_DOCK_INFO_T *)p;

	if (!dock_info->ready) {
		g_upgrade_info.is_busy = 1;
		goto CB_END;
	} else {
		g_upgrade_info.is_busy = 0;
	}

	int num = dock_info->schedule.material_num;

	if (0 > num || MAX_MATERARIAL_CNT < num) {
		dzlog_error("invalid material num : %d\n", num);
		return;
	}

	if (g_dock_sch) {
		free(g_dock_sch);
		g_dock_sch = NULL;
	}

	int size = sizeof(SCHEDULE_UPGRADE_INFO_T) + num * sizeof(ITEM_UPGRADE_INFO_T);

	g_dock_sch = calloc(size, 1);
	if (NULL == g_dock_sch) {
		dzlog_error("calloc fail\n");
		return;
	}

	g_dock_sch->id = dock_info->schedule.schedule_id;
	g_dock_sch->item_cnt = dock_info->schedule.material_num;
	memcpy(g_dock_sch->md5, dock_info->schedule.schedule_md5, MD5_SIZE);

	for (int i = 0; i < num; i++) {
		AdvMaterialInfo *mat_dock = (AdvMaterialInfo *)((char *)dock_info +
								sizeof(RES_GET_DOCK_INFO_T) + i * sizeof(AdvMaterialInfo));

		ITEM_UPGRADE_INFO_T *item = (ITEM_UPGRADE_INFO_T *)((char *)g_dock_sch +
								    sizeof(SCHEDULE_UPGRADE_INFO_T) + i * sizeof(ITEM_UPGRADE_INFO_T));
		g_dock_sch->item = item;

		item->picture.id = mat_dock->pic_material_id;
		memcpy(item->picture.md5, mat_dock->pic_md5, MD5_SIZE);

		item->audio.id = mat_dock->voice_material_id;
		memcpy(item->audio.md5, mat_dock->voice_md5, MD5_SIZE);
	}

	g_upgrade_info.is_encrypted = dock_info->Encrypted;
	memcpy(g_upgrade_info.dock_fw_ver, dock_info->fw_ver, DOCK_VERSION_SIZE);
	memcpy(g_upgrade_info.dock_hw_ver, dock_info->hw_ver, DOCK_VERSION_SIZE);
	snprintf(g_upgrade_info.sn, MAX_DOCK_SN_SIZE, "%s", dock_info->sn);
	snprintf(g_upgrade_info.device_id, MAX_DOCK_DEVICE_ID_SIZE, "%s", dock_info->device_id);

CB_END:
	pthread_mutex_lock(&res_mutex);
	pthread_cond_signal(&res_get_info_cond);
	pthread_mutex_unlock(&res_mutex);
}

char is_dock_encrypted()
{
	return g_upgrade_info.is_encrypted;
}

void wake_upgrade()
{
	g_recv_upgrade_cmd = true;
}

int get_dock_password(unsigned char *password)
{
#ifdef J182J

#ifndef DOCK_TEST
	char blank_device_id[MAX_DOCK_DEVICE_ID_SIZE] = { 0 };
	if (0 == memcmp(blank_device_id, g_upgrade_info.device_id, MAX_DOCK_DEVICE_ID_SIZE)) {
		dzlog_error("dock device id is blank\n");
		return -1;
	} else {
		char psw_dec[MAX_DOCK_PASSWORD_SIZE] = { 0 };
		int ret = j182_password_get_api(g_upgrade_info.device_id, psw_dec);
		if (0 == ret) {
			memcpy(password, psw_dec, MAX_DOCK_PASSWORD_SIZE);
			return 0;
		} else {
			return -1;
		}
	}
#else
	unsigned char t[MAX_DOCK_PASSWORD_SIZE] = {
		0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37,
		0x38, 0x38, 0x39, 0x39, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43, 0x44, 0x44, 0x45, 0x45, 0x46, 0x46
	};
	memcpy(password, t, MAX_DOCK_PASSWORD_SIZE);
	return 0;
#endif

#endif
}

static int get_current_sending_picture_index()
{
	int ret = -1;

	if (g_upgrade_info.need_upgrade_schedule &&
	    g_upgrade_info.schedule.item[g_upgrade_info.sending_item_id].picture.need_upgrade)
		ret = g_upgrade_info.sending_item_id;
	return ret;
}

static int get_current_sending_audio_index()
{
	int ret = -1;

	if (g_upgrade_info.need_upgrade_schedule &&
	    g_upgrade_info.schedule.item[g_upgrade_info.sending_item_id].audio.need_upgrade)
		ret = g_upgrade_info.sending_item_id;
	return ret;
}

void send_file_end_callback(void *p)
{
	if (NULL == p)
		return;

	RES_SEND_FILE_END_T *ret = (RES_SEND_FILE_END_T *)p;

	switch (g_upgrade_info.upgrade_status) {
	case FW_FILE_SENDING:
	{
		if (ret->code == 0)
			g_upgrade_info.need_upgrade_fw = 0;
	}
	break;
	case SCHEDULE_FILE_SENDING:
	{
		if (ret->code == 0)
			g_upgrade_info.schedule.need_upgrade = 0;
	}
	break;
	case PICTURE_FILE_SENDING:
	{
		int i = get_current_sending_picture_index();
		if (0 <= i)
			if (ret->code == 0)
				g_upgrade_info.schedule.item[i].picture.need_upgrade = 0;
	}
	break;
	case AUDIO_FILE_SENDING:
	{
		int i = get_current_sending_audio_index();
		if (0 <= i)
			if (ret->code == 0)
				g_upgrade_info.schedule.item[i].audio.need_upgrade = 0;
	}
	break;
	default:
		break;
	}

	bool all_materials_completed = true;
	for (int i = 0; i < g_upgrade_info.schedule.item_cnt; i++) {
		if (g_upgrade_info.schedule.item[i].picture.need_upgrade ||
		    g_upgrade_info.schedule.item[i].audio.need_upgrade)
			all_materials_completed = false;
	}

	if (!g_upgrade_info.schedule.need_upgrade && all_materials_completed)
		g_upgrade_info.need_upgrade_schedule = 0;

	pthread_mutex_lock(&res_mutex);
	pthread_cond_signal(&res_end_file_cond);
	pthread_mutex_unlock(&res_mutex);
}

#if 0
static int starts_with(const char *haystack, const char *needle)
{
	int nlen = strlen(needle);
	int hlen = strlen(haystack);

	if (nlen > hlen)
		return 0;

	return memcmp(haystack, needle, nlen) ? 0 : 1;
}
#endif

static int ends_with(const char *haystack, const char *needle)
{
	const char *end;
	int nlen = strlen(needle);
	int hlen = strlen(haystack);

	if (nlen > hlen)
		return 0;
	end = haystack + hlen - nlen;

	return strcasecmp(end, needle) ? 0 : 1;
}

static void parse_fw_version_by_file_name(char *file_name, unsigned char *out_ver, int out_ver_len)
{
	int x, y, z;

	sscanf(file_name, "%d_%d_%d"UPGRADE_FW_FILE_SUFFIX,
	       &x, &y, &z);
	out_ver[0] = 0;
	out_ver[1] = x;
	out_ver[2] = y;
	out_ver[3] = z;
}


static char char_to_hex(char c)
{
	if ((c >= '0') && (c <= '9'))
		return c - 0x30;
	else if ((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;
	else
		return 0;
}

#if 0
static void order_list(int *list, int cnt)
{
	for (int i = 0; i < cnt - 1; i++) {
		for (int j = 0; j < (cnt - i - 1); j++) {
			if (list[j] > list[j + 1]) {
				int t = list[j];
				list[j] = list[j + 1];
				list[j + 1] = t;
			}
		}
	}
}
#endif

static int get_index_of_picture(ITEM_UPGRADE_INFO_T *list, int len, int value)
{
	if (len <= 0)
		return -1;

	for (int i = 0; i < len; i++)
		if (list[i].picture.id == value)
			return i;
	return -1;
}

static int get_index_of_audio(ITEM_UPGRADE_INFO_T *list, int len, int value)
{
	if (len <= 0)
		return -1;

	for (int i = 0; i < len; i++)
		if (list[i].audio.id == value)
			return i;
	return -1;
}


int get_adv_file_md5(char *path, unsigned char *md5)
{
	int ret = -1;
	char temp[2 * MD5_SIZE + 1] = { 0 };


	if (NULL == path || NULL == md5) {
		dzlog_error("%s : param is null\n", __func__);
		return -1;
	}
#if 0
	if (access(path, R_OK)) {
		dzlog_error("can not access file %s\n", path);
		return -2;
	}
#endif
	FILE *fp = fopen(path, "r");
	if (NULL == fp) {
		dzlog_error("can not open file %s\n", path);
		fprintf(stderr, "%s\n", strerror(errno));
		return -3;
	}

	ret = fread(temp, 1, 2 * MD5_SIZE, fp);
	if (ret != 2 * MD5_SIZE) {
		dzlog_error("read file %s ret %d\n", path, ret);
		fclose(fp);
		return -4;
	}

	for (int i = 0; i < MD5_SIZE; i++)
		md5[i] = ((char_to_hex(temp[2 * i]) & 0xF) << 4) |
			 (char_to_hex(temp[2 * i + 1]) & 0xF);

	fclose(fp);

	return 0;
}

static bool check_local_file_md5(char *file_name, unsigned char *md5)
{
	unsigned char temp[MD5_SIZE] = { 0 };
	char file_path[MAX_FILE_PATH_SIZE] = { 0 };
	char md5_path[MAX_FILE_PATH_SIZE] = { 0 };

	if (ends_with(file_name, UPGRADE_FW_FILE_SUFFIX)) {
		sprintf(file_path, UPGRADE_FW_FOLDER "%s", file_name);
		sprintf(md5_path, UPGRADE_FW_FOLDER "%s" MD5_FILE_SUFFIX, file_name);
	} else if (ends_with(file_name, SCHEDUAL_FILE_SUFFIX)) {
		sprintf(file_path, DOCK_ADV_FOLDER "%s", file_name);
		sprintf(md5_path, DOCK_ADV_MD5_FOLDER "%s" MD5_FILE_SUFFIX, file_name);
	}

	if (0 > get_adv_file_md5(md5_path, md5)) {
		dzlog_error("fail to read md5 in %s\n", md5_path);
		return false;
	}

	if (0 != get_md5(temp, file_path, 0, 0)) {
		dzlog_error("fail to calculate md5 of %s\n", file_path);
		return false;
	}

	if (memcmp(md5, temp, MD5_SIZE)) {
		dzlog_error("file %s md5 value different from md5 file\n", file_path);
		return false;
	}

	return true;
}

static bool is_file_name_valid(int type, char *name)
{
	char file_base_name[MAX_FILE_PATH_SIZE] = { 0 };
	char file_suffix[MAX_FILE_PATH_SIZE] = { 0 };
	int base_len = 0, suffix_len = 0;
	bool ret = false;

	sscanf(name, "%[^.]s.%*s", file_base_name);
	sscanf(name, "%*[^.].%s", file_suffix);

	base_len = strlen(file_base_name);
	suffix_len = strlen(file_suffix);


	if (base_len > 0 && base_len <= 8 && suffix_len == 3) {
		switch (type) {
		case FW_FILE:
		{
			if (ends_with(name, UPGRADE_FW_FILE_SUFFIX)) {
				int x, y, z;
				if (3 == sscanf(name, "%d_%d_%d"UPGRADE_FW_FILE_SUFFIX,
						&x, &y, &z))
					ret = true;
			}
			break;
		}
		case SCHEDULE_FILE:
		{
			if (ends_with(name, SCHEDUAL_FILE_SUFFIX))
				ret = true;
			break;
		}
		case PICTURE_FILE:
		{
			if (ends_with(name, JPG_FILE_SUFFIX) ||
			    ends_with(name, BMP_FILE_SUFFIX) ||
			    ends_with(name, PNG_FILE_SUFFIX))
				ret = true;
			break;
		}
		case AUDIO_FILE:
		{
			if (ends_with(name, MP3_FILE_SUFFIX))
				ret = true;
			break;
		}
		default:
			break;
		}
	}

	return ret;
}

bool is_array_blank(unsigned char *array, int len)
{
	for (int i = 0; i < len; i++)
		if (0 != array[i])
			return false;

	return true;
}

static int scan_local_picture_files(char *sch_name, char **picture_name)
{
	DIR *directory;
	struct dirent *file;
	char path[MAX_FILE_PATH_SIZE] = { 0 };
	int picture_cnt = 0;
	int sch_cnt = 0;
	FILE_INFO_T local_sch_list[MAX_MATERARIAL_CNT];
	FILE_INFO_T local_sch_newest;

	bzero(local_sch_list, sizeof(FILE_INFO_T) * MAX_MATERARIAL_CNT);
	bzero(&local_sch_newest, sizeof(FILE_INFO_T));

	directory = opendir(DOCK_ADV_FOLDER);
	if (directory == NULL) {
		mkdir(UPGRADE_FW_BASE, 0755);
		mkdir(DOCK_ADV_FOLDER, 0755);
		mkdir(DOCK_ADV_MD5_FOLDER, 0755);
		directory = opendir(DOCK_ADV_FOLDER);
		if (directory == NULL) {
			dzlog_error("open dir %s fail\n", DOCK_ADV_FOLDER);
			return -1;
		}
	}

	do {
		file = readdir(directory);
		if (NULL == file)
			break;

		if (strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0)  ///current dir OR parrent dir
			continue;
		if (file->d_type != 8)                                                  //file type
			continue;

		if (is_file_name_valid(SCHEDULE_FILE, file->d_name)) {
			unsigned char md5[MD5_SIZE] = { 0 };
			if (!check_local_file_md5(file->d_name, md5)) {
				dzlog_error("file %s check schedule md5 err\n", file->d_name);

				bzero(path, MAX_FILE_PATH_SIZE);
				snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "%s", file->d_name);
				remove(path);
				dzlog_info("rm %s\n", path);

				bzero(path, MAX_FILE_PATH_SIZE);
				snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_MD5_FOLDER "%s" MD5_FILE_SUFFIX, file->d_name);
				remove(path);
				dzlog_info("rm %s\n", path);
			} else {
				local_sch_list[sch_cnt].id = sch_cnt;
				snprintf(local_sch_list[sch_cnt].file_name,
					 MAX_FILE_NAME_LEN, "%s", file->d_name);

				struct stat st;
				bzero(path, MAX_FILE_PATH_SIZE);
				snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "%s", local_sch_list[sch_cnt].file_name);
				stat(path, &st);
				local_sch_list[sch_cnt].file_mtime = st.st_mtime;
				printf("%s %s", path, ctime(&st.st_mtime));

				if (local_sch_list[sch_cnt].file_mtime > local_sch_newest.file_mtime) {
					local_sch_newest.id = sch_cnt;
					local_sch_newest.file_mtime = local_sch_list[sch_cnt].file_mtime;
					snprintf(local_sch_newest.file_name, MAX_FILE_NAME_LEN, "%s",
						 local_sch_list[sch_cnt].file_name);
				}
				sch_cnt++;
				//printf("sch_name = %s\n", sch_name);
			}
		} else if (is_file_name_valid(PICTURE_FILE, file->d_name)) {
			sprintf((char *)picture_name + picture_cnt * MAX_FILE_NAME_LEN, "%s", file->d_name);
			//printf("mat_name[%d] = %s\n", cnt, (char *)mat_name + cnt * MAX_FILE_NAME_LEN);
			picture_cnt++;
		} else {
			/* 删除非素材文件 */
			bzero(path, MAX_FILE_PATH_SIZE);
			snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "%s", file->d_name);
			remove(path);
			dzlog_info("rm %s\n", path);
		}
	} while (1);

	closedir(directory);

	if (sch_cnt > 0) {
		snprintf(sch_name, MAX_FILE_NAME_LEN, "%s", local_sch_newest.file_name);
		/* 删除旧的排期文件 */
		for (int i = 0; i < sch_cnt; i++) {
			if (strcmp(local_sch_newest.file_name, local_sch_list[i].file_name)) {
				bzero(path, MAX_FILE_PATH_SIZE);
				snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "%s", local_sch_list[i].file_name);
				remove(path);
				dzlog_info("rm %s\n", path);

				bzero(path, MAX_FILE_PATH_SIZE);
				snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_MD5_FOLDER "%s" MD5_FILE_SUFFIX, local_sch_list[i].file_name);
				remove(path);
				dzlog_info("rm %s\n", path);
			}
		}
		return picture_cnt;
	} else {
		dzlog_error("no local schedule file found\n");
		return -1;
	}
}

static int scan_local_audio_files(char **audio_name)
{
	DIR *directory;
	struct dirent *file;
	char path[MAX_FILE_PATH_SIZE] = { 0 };
	int audio_cnt = 0;

	directory = opendir(DOCK_AUDIO_FOLDER);
	if (directory == NULL) {
		mkdir(UPGRADE_FW_BASE, 0755);
		mkdir(DOCK_AUDIO_FOLDER, 0755);
		directory = opendir(DOCK_ADV_FOLDER);
		if (directory == NULL) {
			dzlog_error("open dir %s fail\n", DOCK_AUDIO_FOLDER);
			return -1;
		}
	}

	do {
		file = readdir(directory);
		if (NULL == file)
			break;

		if (strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0)  ///current dir OR parrent dir
			continue;
		if (file->d_type != 8)                                                  //file type
			continue;

		if (is_file_name_valid(AUDIO_FILE, file->d_name)) {
			sprintf((char *)audio_name + audio_cnt * MAX_FILE_NAME_LEN, "%s", file->d_name);
			//printf("audio_name[%d] = %s\n", audio_cnt, (char *)audio_name + audio_cnt * MAX_FILE_NAME_LEN);
			audio_cnt++;
		} else {
			/* 删除非MP3文件或命名非法文件 */
			bzero(path, MAX_FILE_PATH_SIZE);
			snprintf(path, MAX_FILE_PATH_SIZE, DOCK_AUDIO_FOLDER "%s", file->d_name);
			remove(path);
			dzlog_info("rm %s\n", path);
		}
	} while (1);

	closedir(directory);
	return audio_cnt;
}

static int parse_schedule_config_file(char *path, SCH_FILE_INFO_T *sch_file_info)
{
	char temp[MAX_SCHEDULE_FILE_SIZE] = { 0 };

	if (NULL == path || NULL == sch_file_info) {
		dzlog_error("%s param null\n", __func__);
		return -1;
	}

	FILE *fp = fopen(path, "r");

	if (NULL == fp) {
		dzlog_error("can not open file %s\n", path);
		fprintf(stderr, "%s\n", strerror(errno));
		return -3;
	}

	int ret = fread(temp, 1, MAX_SCHEDULE_FILE_SIZE, fp);

	if (ret < 0) {
		dzlog_error("read file %s ret %d\n", path, ret);
		fclose(fp);
		return -4;
	}

	fclose(fp);

	cJSON *config_json = cJSON_Parse(temp);
	if (0 == config_json) {
		dzlog_error("fail to parse schedule file\n");
		return -5;
	}

	cJSON *info_json = cJSON_GetObjectItem(config_json, "Info");
	if (0 == info_json) {
		dzlog_error("fail to parse schedule file\n");
		return -5;
	} else {
		cJSON *sch_id_json = cJSON_GetObjectItem(info_json, "scheduleId");
		if (0 == sch_id_json) {
			dzlog_error("no scheduleId config\n");
			return -5;
		} else {
			sch_file_info->sch_id = atoi(sch_id_json->valuestring);
		}
	}

	cJSON *playlist_json = cJSON_GetObjectItem(config_json, "PlayList");
	if (0 == playlist_json) {
		dzlog_error("no PlayList config\n");
		return -5;
	} else {
		int array_size = cJSON_GetArraySize(playlist_json);
		sch_file_info->item_cnt = array_size;

		for (int i = 0; i < array_size; i++) {
			cJSON *child_mat_json = cJSON_GetArrayItem(playlist_json, i);
			if (0 == child_mat_json) {
				dzlog_error("can not get play list child %d\n", i);
				return -5;
			} else {
				cJSON *mat_id_json = cJSON_GetObjectItem(child_mat_json, "picMaterialId");
				if (0 == mat_id_json) {
					dzlog_error("can not get picture id config\n");
					return -5;
				} else {
					sch_file_info->item[i].picture.id = atoi(mat_id_json->valuestring);
				}

				cJSON *mat_name_json = cJSON_GetObjectItem(child_mat_json, "picName");
				if (0 == mat_name_json) {
					dzlog_error("can not get picture name config of id %d\n", sch_file_info->item[i].picture.id);
					return -5;
				} else {
					if (is_file_name_valid(PICTURE_FILE, mat_name_json->valuestring)) {
						snprintf(sch_file_info->item[i].picture.name, MAX_FILE_NAME_LEN, "%s", mat_name_json->valuestring);
					} else {
						dzlog_error("invalid picture name config: %s\n", mat_name_json->valuestring);
						return -5;
					}
				}
				cJSON *mat_md5_json = cJSON_GetObjectItem(child_mat_json, "picMd5");
				if (0 == mat_md5_json) {
					dzlog_error("can not get picture md5 config of id %d\n", sch_file_info->item[i].picture.id);
					return -5;
				} else {
					for (int j = 0; j < MD5_SIZE; j++)
						sch_file_info->item[i].picture.md5[j] = ((char_to_hex(mat_md5_json->valuestring[2 * j]) & 0xF) << 4) |
											(char_to_hex(mat_md5_json->valuestring[2 * j + 1]) & 0xF);
				}

				sch_file_info->item[i].audio.id = 0;
				bzero(sch_file_info->item[i].audio.md5, MD5_SIZE);
				bzero(sch_file_info->item[i].audio.name, MAX_FILE_NAME_LEN);

				cJSON *voice_id_json = cJSON_GetObjectItem(child_mat_json, "voiceMaterialId");
				cJSON *voice_name_json = cJSON_GetObjectItem(child_mat_json, "voiceName");
				cJSON *voice_md5_json = cJSON_GetObjectItem(child_mat_json, "voiceMd5");

				if (0 == voice_id_json) {
#if 0
					printf("config[%3d] picture: id = %4d name = %s\n",
					       i, sch_file_info->item[i].picture.id, sch_file_info->item[i].picture.name);
#endif
					continue;
				} else {
					int id = atoi(voice_id_json->valuestring);
					if (id < 0) {
						dzlog_error("invalid config audio id : %d\n", id);
						return -5;
					} else {
						sch_file_info->item[i].audio.id = id;
					}
				}

				if (0 == voice_name_json) {
					dzlog_error("can not get audio name config of id %d\n", sch_file_info->item[i].audio.id);
					return -5;
				} else {
					if (is_file_name_valid(AUDIO_FILE, voice_name_json->valuestring)) {
						snprintf(sch_file_info->item[i].audio.name, MAX_FILE_NAME_LEN, "%s", voice_name_json->valuestring);
					} else {
						dzlog_error("invalid audio name config: %s\n", voice_name_json->valuestring);
						return -5;
					}
				}

				if (0 == voice_md5_json) {
					dzlog_error("can not get audio md5 config of id %d\n", sch_file_info->item[i].audio.id);
					return -5;;
				} else {
					for (int j = 0; j < MD5_SIZE; j++)
						sch_file_info->item[i].audio.md5[j] = ((char_to_hex(voice_md5_json->valuestring[2 * j]) & 0xF) << 4) |
										      (char_to_hex(voice_md5_json->valuestring[2 * j + 1]) & 0xF);
				}
#if 0
				printf("config[%3d] picture: id = %4d name = %s audio: id = %4d name = %s\n",
				       i, sch_file_info->item[i].picture.id, sch_file_info->item[i].picture.name,
				       sch_file_info->item[i].audio.id, sch_file_info->item[i].audio.name);
#endif
			}
		}
		//order_list(mat_id, array_size);

		return array_size;
	}

	return 0;
}

int remove_unused_adv_files(SCH_FILE_INFO_T *sch_cfg, void *local_mat, int local_mat_cnt)
{
	bool is_found = false;

	for (int i = 0; i < local_mat_cnt; i++) {
		is_found = false;
		for (int j = 0; j < sch_cfg->item_cnt; j++) {
			if (0 == strcmp((char *)local_mat + i * MAX_FILE_NAME_LEN,
					sch_cfg->item[j].picture.name))
				is_found = true;
		}
		if (!is_found) {
			char path[MAX_FILE_PATH_SIZE] = { 0 };
			snprintf(path, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "%s", (char *)local_mat + i * MAX_FILE_NAME_LEN);
			remove(path);
			dzlog_info("rm %s\n", path);
		}
	}
	return 0;
}


int remove_unused_audio_files(SCH_FILE_INFO_T *sch_cfg, void *local_audio, int local_audio_cnt)
{
	bool is_found = false;

	for (int i = 0; i < local_audio_cnt; i++) {
		is_found = false;
		for (int j = 0; j < sch_cfg->item_cnt; j++) {
			if (0 == strcmp((char *)local_audio + i * MAX_FILE_NAME_LEN,
					sch_cfg->item[j].audio.name))
				is_found = true;
		}
		if (!is_found) {
			char path[MAX_FILE_PATH_SIZE] = { 0 };
			snprintf(path, MAX_FILE_PATH_SIZE, DOCK_AUDIO_FOLDER "%s", (char *)local_audio + i * MAX_FILE_NAME_LEN);
			remove(path);
			dzlog_info("rm %s\n", path);
		}
	}
	return 0;
}

bool is_dock_file_copy_completed()
{
	char file[MAX_FILE_PATH_SIZE] = { 0 };

	snprintf(file, MAX_FILE_PATH_SIZE, DOCK_ADV_FOLDER "flag");
	if (0 != access(file, F_OK))
		return true;
	else
		return false;
}

int get_local_adv_file_info()
{
	unsigned char md5[MD5_SIZE] = { 0 };
	SCH_FILE_INFO_T sch_file_info;

	char local_sch[MAX_FILE_NAME_LEN] = { 0 };
	char local_picture_name[MAX_MATERARIAL_CNT][MAX_FILE_NAME_LEN] = { 0 };
	char local_audio_name[MAX_MATERARIAL_CNT][MAX_FILE_NAME_LEN] = { 0 };
	int local_picture_cnt = scan_local_picture_files(local_sch, (char **)local_picture_name);
	int local_audio_cnt = scan_local_audio_files((char **)local_audio_name);

	if (local_picture_cnt < 0) {
		dzlog_error("no local material file found\n");
		return -1;
	}

	char path[MAX_FILE_PATH_SIZE] = { 0 };
	sprintf(path, DOCK_ADV_FOLDER "%s", local_sch);

	bzero(&sch_file_info, sizeof(SCH_FILE_INFO_T));
	parse_schedule_config_file(path, &sch_file_info);
	if (sch_file_info.item_cnt < 0) {
		dzlog_error("failed to parse schedule file\n");
		return -1;
	}

	/* 删除不使用的广告图片 */
	remove_unused_adv_files(&sch_file_info, local_picture_name, local_picture_cnt);

	/* 删除不使用的音频文件 */
	remove_unused_audio_files(&sch_file_info, local_audio_name, local_audio_cnt);

	int item_cnt = sch_file_info.item_cnt;

	/* 核对广告图片文件的文件名和md5 */
	for (int i = 0; i < item_cnt; i++) {
		bool found = false;
		for (int j = 0; j < local_picture_cnt; j++) {
			if (0 == strcmp(sch_file_info.item[i].picture.name,
					local_picture_name[j])) {
				bzero(path, MAX_FILE_PATH_SIZE);
				sprintf(path, DOCK_ADV_FOLDER "%s", sch_file_info.item[i].picture.name);
				bzero(md5, MD5_SIZE);

				if (0 != get_md5(md5, path, 0, 0)) {
					dzlog_error("get md5 of %s err\n", path);
					return -2;
				} else {
					if (memcmp(sch_file_info.item[i].picture.md5, md5, MD5_SIZE)) {
						dzlog_error("%s config md5 different from md5 file\n",
							    sch_file_info.item[i].picture.name);
						return -2;
					} else {
						found = true;
						break;
					}
				}
			}
		}

		if (!found) {
			dzlog_error("picture %s not found\n", sch_file_info.item[i].picture.name);
			return -1;
		}
	}


	/* 核对音频文件的文件名和md5 */
	for (int i = 0; i < item_cnt; i++) {
		if (!is_file_name_valid(AUDIO_FILE, sch_file_info.item[i].audio.name))
			continue;

		bool found = false;
		for (int j = 0; j < local_audio_cnt; j++) {
			if (0 == strcmp(sch_file_info.item[i].audio.name,
					local_audio_name[j])) {
				bzero(path, MAX_FILE_PATH_SIZE);
				sprintf(path, DOCK_AUDIO_FOLDER "%s", sch_file_info.item[i].audio.name);
				bzero(md5, MD5_SIZE);

				if (0 != get_md5(md5, path, 0, 0)) {
					dzlog_error("get md5 of %s err\n", path);
					return -2;
				} else {
					if (memcmp(sch_file_info.item[i].audio.md5, md5, MD5_SIZE)) {
						dzlog_error("%s config md5 different from md5 file\n",
							    sch_file_info.item[i].audio.name);
						return -2;
					} else {
						found = true;
						break;
					}
				}
			}
		}

		if (!found) {
			dzlog_error("audio %s not found\n", sch_file_info.item[i].audio.name);
			return -1;
		}
	}

	if (g_local_sch) {
		free(g_local_sch);
		g_local_sch = NULL;
	}

	g_local_sch = calloc(sizeof(SCHEDULE_UPGRADE_INFO_T) +
			     item_cnt * sizeof(ITEM_UPGRADE_INFO_T), 1);

	if (NULL == g_local_sch) {
		dzlog_error("calloc fail\n");
		return -1;
	}

	g_local_sch->item_cnt = item_cnt;

	ITEM_UPGRADE_INFO_T *item = NULL;
	if (item_cnt > 0) {
		item = (ITEM_UPGRADE_INFO_T *)((char *)g_local_sch +
					       sizeof(SCHEDULE_UPGRADE_INFO_T));
		g_local_sch->item = item;
	}
	sprintf(path, DOCK_ADV_MD5_FOLDER "%s" MD5_FILE_SUFFIX, local_sch);
	bzero(md5, MD5_SIZE);
	if (get_adv_file_md5(path, md5)) {
		dzlog_error("no md5 of %s\n", path);
		return -2;
	} else {
		g_local_sch->id = sch_file_info.sch_id;
		memcpy(g_local_sch->md5, md5, MD5_SIZE);
		snprintf(g_local_sch->name, MAX_FILE_NAME_LEN, "%s", local_sch);
	}

	char dis[33] = { 0 };
	for (int i = 0; i < 16; i++)
		sprintf(dis + 2 * i, "%02x", md5[i]);
	printf("local schedule %s, id = %d, md5: %s\n", g_local_sch->name, g_local_sch->id, dis);

	printf("\n%6s%8s%14s%36s%8s%14s%36s\n", "local", "PicId", "PicName", "PicMd5", "AudioId", "AudioName", "AudioMd5");

	for (int i = 0; i < item_cnt; i++) {
		item[i].picture.id = sch_file_info.item[i].picture.id;
		memcpy(item[i].picture.md5, (char *)sch_file_info.item[i].picture.md5, MD5_SIZE);
		snprintf(item[i].picture.name, MAX_FILE_NAME_LEN, "%s", sch_file_info.item[i].picture.name);

		bzero(dis, 33);
		for (int j = 0; j < MD5_SIZE; j++)
			sprintf(dis + 2 * j, "%02x", item[i].picture.md5[j]);

		printf("%6d%8d%14s%36s", i, item[i].picture.id, item[i].picture.name, dis);

		if (!is_array_blank(sch_file_info.item[i].audio.md5, MD5_SIZE)) {
			item[i].audio.id = sch_file_info.item[i].audio.id;
			memcpy(item[i].audio.md5, (char *)sch_file_info.item[i].audio.md5, MD5_SIZE);
			snprintf(item[i].audio.name, MAX_FILE_NAME_LEN, "%s", sch_file_info.item[i].audio.name);

			bzero(dis, 33);
			for (int j = 0; j < MD5_SIZE; j++)
				sprintf(dis + 2 * j, "%02x", item[i].audio.md5[j]);

			printf("%8d%14s%36s", item[i].audio.id, item[i].audio.name, dis);
		}
		printf("\n");
	}
	printf("\n");
	return 0;
}

int compare_adv_files()
{
	int index_upgrade_picture[MAX_MATERARIAL_CNT];
	int index_upgrade_audio[MAX_MATERARIAL_CNT];
	char print_names[MAX_MATERARIAL_CNT * MAX_FILE_NAME_LEN * 2] = { 0 };

	for (int i = 0; i < MAX_MATERARIAL_CNT; i++) {
		index_upgrade_picture[i] = -1;
		index_upgrade_audio[i] = -1;
	}

	if (NULL == g_local_sch || NULL == g_dock_sch)
		return -1;

	if (g_local_sch->item_cnt <= 0)
		return -2;

	g_upgrade_info.need_upgrade_schedule = 0;
	g_upgrade_info.schedule.item_cnt = 0;
	g_upgrade_info.sending_item_id = -1;

	/* 比较schedule文件md5 */
	if (memcmp(g_local_sch->md5,
		   g_dock_sch->md5, MD5_SIZE)) {
		g_upgrade_info.schedule.need_upgrade = 1;
		g_upgrade_info.schedule.id = g_local_sch->id;
		memcpy(g_upgrade_info.schedule.md5, g_local_sch->md5, MD5_SIZE);
		snprintf(g_upgrade_info.schedule.name, MAX_FILE_NAME_LEN, "%s", g_local_sch->name);
		dzlog_info("need upgrade %s\n", g_upgrade_info.schedule.name);
	} else {
		g_upgrade_info.schedule.need_upgrade = 0;
	}

	int j = g_local_sch->item_cnt;

	/* 比较文件实际md5 */
	ITEM_UPGRADE_INFO_T *item_local = (ITEM_UPGRADE_INFO_T *)((char *)g_local_sch +
								  sizeof(SCHEDULE_UPGRADE_INFO_T));
	if (g_dock_sch->item_cnt > 0) {
		ITEM_UPGRADE_INFO_T *item_dock = (ITEM_UPGRADE_INFO_T *)((char *)g_dock_sch +
									 sizeof(SCHEDULE_UPGRADE_INFO_T));
		if (j > 0) {
			for (int i = 0; i < j; i++) {
				int index = get_index_of_picture(item_dock, g_dock_sch->item_cnt,
								 item_local[i].picture.id);
				//printf("get index of picture id %d ret %d name %s total %d\n", item_local[i].picture.id, index, item_local[i].picture.name, g_dock_sch->item_cnt);
				if (index < 0 || memcmp(item_local[i].picture.md5,
							item_dock[index].picture.md5, MD5_SIZE))
					index_upgrade_picture[i] = i;

				if (!is_array_blank(item_local[i].audio.md5, MD5_SIZE)) {
					index = get_index_of_audio(item_dock, g_dock_sch->item_cnt,
								   item_local[i].audio.id);
					//printf("get index of audio id %d ret %d name %s total %d\n", item_local[i].audio.id, index, item_local[i].audio.name, g_dock_sch->item_cnt);
					if (index < 0 || memcmp(item_local[i].audio.md5,
								item_dock[index].audio.md5, MD5_SIZE))
						index_upgrade_audio[i] = i;
				}

				if (index_upgrade_picture[i] >= 0 || index_upgrade_audio[i] >= 0)
					g_upgrade_info.schedule.item_cnt++;
			}
		}
	} else {
		for (int i = 0; i < j; i++) {
			index_upgrade_picture[i] = i;
			if (!is_array_blank(item_local[i].audio.md5, MD5_SIZE))
				index_upgrade_audio[i] = i;
			g_upgrade_info.schedule.item_cnt++;
		}
	}

	if (g_upgrade_info.schedule.item_cnt > 0 ||
	    g_upgrade_info.schedule.need_upgrade)
		g_upgrade_info.need_upgrade_schedule = 1;

	if (g_upgrade_info.schedule.item_cnt > 0) {
		if (g_upgrade_info.schedule.item) {
			free(g_upgrade_info.schedule.item);
			g_upgrade_info.schedule.item = NULL;
		}

		g_upgrade_info.schedule.item = calloc(
			sizeof(ITEM_UPGRADE_INFO_T) * g_upgrade_info.schedule.item_cnt, 1);

		if (NULL == g_upgrade_info.schedule.item) {
			dzlog_error("calloc fail\n");
			return -3;
		}

		ITEM_UPGRADE_INFO_T *item_local = (ITEM_UPGRADE_INFO_T *)((char *)g_local_sch +
									  sizeof(SCHEDULE_UPGRADE_INFO_T));

		for (int i = 0, k = 0; i < j; i++) {
			int index_picture = index_upgrade_picture[i];
			int index_audio = index_upgrade_audio[i];

			if (0 > index_picture && 0 > index_audio)
				continue;

			if (index_picture >= 0) {
				//printf("picture[%d] id %d name %s\n", k, index_picture, g_local_sch->item[index_picture].picture.name);
				g_upgrade_info.schedule.item[k].picture.need_upgrade = 1;
				g_upgrade_info.schedule.item[k].picture.id = item_local[index_picture].picture.id;
				snprintf(g_upgrade_info.schedule.item[k].picture.name, MAX_FILE_NAME_LEN, "%s",
					 item_local[index_picture].picture.name);
				memcpy(g_upgrade_info.schedule.item[k].picture.md5,
				       item_local[index_picture].picture.md5, MD5_SIZE);
			} else {
				memset(&g_upgrade_info.schedule.item[k].picture, 0, sizeof(MATERIAL_UPGRADE_INFO_T));
			}

			if (index_audio >= 0) {
				//printf("audio[%d] id %d name %s\n", k, index_audio, g_local_sch->item[index_audio].audio.name);
				g_upgrade_info.schedule.item[k].audio.need_upgrade = 1;
				g_upgrade_info.schedule.item[k].audio.id = item_local[index_audio].audio.id;
				snprintf(g_upgrade_info.schedule.item[k].audio.name, MAX_FILE_NAME_LEN, "%s",
					 item_local[index_audio].audio.name);
				memcpy(g_upgrade_info.schedule.item[k].audio.md5,
				       item_local[index_audio].audio.md5, MD5_SIZE);
			} else {
				memset(&g_upgrade_info.schedule.item[k].audio, 0, sizeof(MATERIAL_UPGRADE_INFO_T));
			}

			if (index_picture >= 0 || index_audio >= 0)
				k++;
		}

		sprintf(print_names, "\nfiles to be sent to dock:\n");
		for (int i = 0, k = 0; i < g_upgrade_info.schedule.item_cnt; i++) {
			char name[MAX_FILE_NAME_LEN];

			if (g_upgrade_info.schedule.item[i].picture.need_upgrade) {
				snprintf(name, MAX_FILE_NAME_LEN, "%13s ", g_upgrade_info.schedule.item[i].picture.name);
				strcat(print_names, name);
				k++;
			}


			if (g_upgrade_info.schedule.item[i].audio.need_upgrade) {
				snprintf(name, MAX_FILE_NAME_LEN, "%13s ", g_upgrade_info.schedule.item[i].audio.name);
				strcat(print_names, name);
				k++;
			}

			if (0 == k % 8)
				strncat(print_names, "\n", MAX_FILE_NAME_LEN);
		}
		dzlog_info("%s\n\n", (char *)print_names);
	}
	return 0;
}


int copy_file(const char *to, const char *from)
{
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;

	fd_from = open(from, O_RDONLY);
	if (fd_from < 0) {
		dzlog_error("open file %s fail\n", from);
		return -1;
	}
	fd_to = open(to, O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd_to < 0) {
		dzlog_error("open file %s fail\n", to);
		goto out_error;
	}

	while (nread = read(fd_from, buf, sizeof buf), nread > 0) {
		char *out_ptr = buf;
		ssize_t nwritten;

		do {
			nwritten = write(fd_to, out_ptr, nread);
			if (nwritten >= 0) {
				nread -= nwritten;
				out_ptr += nwritten;
			} else if (errno != EINTR) {
				dzlog_error("write file %s fail\n", to);
				goto out_error;
			}
		} while (nread > 0);
	}

	if (nread == 0) {
		if (close(fd_to) < 0) {
			fd_to = -1;
			dzlog_error("close file %s fail\n", to);
			goto out_error;
		}
		close(fd_from);

		/* Success! */
		return 0;
	}

out_error:
	saved_errno = errno;

	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);

	errno = saved_errno;
	return errno;
}

int remove_other_upgrade_files(char *name)
{
	DIR *directory;
	struct dirent *file;

	directory = opendir(UPGRADE_FW_FOLDER);
	if (directory == NULL) {
		mkdir(UPGRADE_FW_BASE, 0755);
		directory = opendir(UPGRADE_FW_FOLDER);
		if (directory == NULL) {
			dzlog_error("open dir %s fail\n", UPGRADE_FW_FOLDER);
			return -1;
		}
	}

	do {
		file = readdir(directory);
		if (NULL == file)
			break;

		if (strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0)  ///current dir OR parrent dir
			continue;
		if (file->d_type != 8)                                                  //file type
			continue;

		if (strncmp(file->d_name, name, strlen(name))) {
			char file_path[MAX_FILE_PATH_SIZE] = { 0 };
			snprintf(file_path, MAX_FILE_PATH_SIZE, UPGRADE_FW_FOLDER "%s", file->d_name);
			remove(file_path);
			dzlog_info("rm %s\n", file_path);
		}
	} while (1);

	closedir(directory);

	return 0;
}

int get_local_fw_file_info(unsigned char *version, char *file_name, unsigned char *md5)
{
	DIR *directory;
	struct dirent *file;
	int cnt = 0;

	FILE_INFO_T fw_info[MAX_MATERARIAL_CNT];
	FILE_INFO_T fw_newest;

	bzero(fw_info, sizeof(FILE_INFO_T) * MAX_MATERARIAL_CNT);
	bzero(&fw_newest, sizeof(FILE_INFO_T));

	if (NULL == version || NULL == file_name) {
		dzlog_error("param is null\n");
		return -1;
	}

	directory = opendir(UPGRADE_FW_FOLDER);
	if (directory == NULL) {
		mkdir(UPGRADE_FW_BASE, 0755);
		mkdir(UPGRADE_FW_FOLDER, 0755);
		directory = opendir(UPGRADE_FW_FOLDER);
		if (directory == NULL) {
			dzlog_error("%s:open dir %s fail !\n", __func__, UPGRADE_FW_FOLDER);
			return -1;
		}
	}

	while ((file = readdir(directory)) != NULL) {
		if (is_file_name_valid(FW_FILE, file->d_name)) {
			fw_info[cnt].id = cnt;
			snprintf(fw_info[cnt].file_name, MAX_FILE_NAME_LEN, "%s", file->d_name);

			struct stat st;
			char path[MAX_FILE_PATH_SIZE] = { 0 };
			snprintf(path, MAX_FILE_PATH_SIZE, UPGRADE_FW_FOLDER "%s", fw_info[cnt].file_name);
			stat(path, &st);
			fw_info[cnt].file_mtime = st.st_mtime;
			printf("%s %s", path, ctime(&st.st_mtime));

			if (fw_info[cnt].file_mtime > fw_newest.file_mtime) {
				fw_newest.id = fw_info[cnt].id;
				fw_newest.file_mtime = fw_info[cnt].file_mtime;
				snprintf(fw_newest.file_name, MAX_FILE_NAME_LEN, "%s", fw_info[cnt].file_name);
			}
			cnt++;
		}
	}

	closedir(directory);

	if (strlen(fw_newest.file_name) > 0) {
		if (check_local_file_md5(fw_newest.file_name, md5)) {
			parse_fw_version_by_file_name(fw_newest.file_name, version, DOCK_VERSION_SIZE);
			snprintf(file_name, MAX_FILE_PATH_SIZE, "%s", fw_newest.file_name);
			/* 删除旧的固件 */
			remove_other_upgrade_files(fw_newest.file_name);
			return 1;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

static unsigned char compare_firmware_version(unsigned char *local_versin, unsigned char *dock_version)
{
	if (0 == dock_version[1] && 0 == dock_version[2] && 0 == dock_version[3])
		return 0;

	if (memcmp(local_versin + 1, dock_version + 1, DOCK_VERSION_SIZE - 1) > 0)
		return 1;
	else
		return 0;
}

void print_dock_info()
{
	char dis[MD5_SIZE * 2 + 1] = { 0 };

	printf("dock %s sn = %s id = %s fw version = %d.%d.%d hw version = %d.%d.%d\n",
	       g_upgrade_info.is_encrypted ? "encrypted" : "not encrypt", g_upgrade_info.sn, g_upgrade_info.device_id,
	       g_upgrade_info.dock_fw_ver[1], g_upgrade_info.dock_fw_ver[2], g_upgrade_info.dock_fw_ver[3],
	       g_upgrade_info.dock_hw_ver[1], g_upgrade_info.dock_hw_ver[2], g_upgrade_info.dock_hw_ver[3]);

	if (NULL == g_dock_sch) {
		dzlog_error("dock info is null\n");
		return;
	}

	for (int i = 0; i < MD5_SIZE; i++)
		sprintf(dis + 2 * i, "%02x", g_dock_sch->md5[i]);
	printf("dock schedual id = %d md5 = %s\n", g_dock_sch->id, dis);


	printf("\n%6s%8s%36s%8s%36s\n", "dock", "PicId", "PicMd5", "AudioId", "AudioMd5");
	if (g_dock_sch->item_cnt > 0) {
		ITEM_UPGRADE_INFO_T *item = (ITEM_UPGRADE_INFO_T *)((char *)g_dock_sch +
								    sizeof(SCHEDULE_UPGRADE_INFO_T));

		for (int i = 0; i < g_dock_sch->item_cnt; i++) {
			bzero(dis, 33);
			for (int j = 0; j < MD5_SIZE; j++)
				sprintf(dis + 2 * j, "%02x", item[i].picture.md5[j]);

			printf("%6d%8d%36s", i, item[i].picture.id, dis);

			if (!is_array_blank(item[i].audio.md5, MD5_SIZE)) {
				bzero(dis, 33);
				for (int j = 0; j < MD5_SIZE; j++)
					sprintf(dis + 2 * j, "%02x", item[i].audio.md5[j]);

				printf("%8d%36s", item[i].audio.id, dis);
			}
			printf("\n");
		}
		printf("\n");
	}
}


static int dock_send_file(int type, char *file_name, unsigned char *file_md5)
{
	int ret = 0, timeout = 0;
	char file_path[MAX_FILE_PATH_SIZE] = { 0 };

	if (NULL == file_name || NULL == file_md5)
		dzlog_error("param is null\n");

	if (!is_file_name_valid(type, file_name)) {
		dzlog_error("invalid file name %s\n", file_name);
		return -1;
	}

	switch (type) {
	case FW_FILE:
	{
		sprintf(file_path, UPGRADE_FW_FOLDER "%s", file_name);
		g_upgrade_info.upgrade_status = FW_FILE_SENDING;
		timeout = SEND_FW_FILE_TIMEOUT;
	} break;
	case SCHEDULE_FILE:
	{
		sprintf(file_path, DOCK_ADV_FOLDER "%s", file_name);
		g_upgrade_info.upgrade_status = SCHEDULE_FILE_SENDING;
		timeout = SEND_SCHEDULE_FILE_TIMEOUT;
	} break;
	case PICTURE_FILE:
	{
		sprintf(file_path, DOCK_ADV_FOLDER "%s", file_name);
		g_upgrade_info.upgrade_status = PICTURE_FILE_SENDING;
		timeout = SEND_MATERIAL_FILE_TIMEOUT;
	} break;
	case AUDIO_FILE:
	{
		sprintf(file_path, DOCK_AUDIO_FOLDER "%s", file_name);
		g_upgrade_info.upgrade_status = AUDIO_FILE_SENDING;
		timeout = SEND_MATERIAL_FILE_TIMEOUT;
	} break;
	default: {
		return -1;
	}
	}

#ifndef UART_SIMU
	jd_uart_start_send_file(type, file_path, file_md5);
#endif

	dzlog_info("start to send file %s to dock\n", file_path);

	/* 等待文件传输完成 */
	ret = wait_dock_response(RES_SEND_FILE_END, timeout);
	if (0 != ret) {
		dzlog_error("send file %s to dock fail, ret %d\n", file_path, ret);
		reset_dock_update_file_info();

#ifndef UART_SIMU
		jd_uart_complete_all_files();
#endif

#ifdef AGEING_TEST
		char cmd[256] = { 0 };
		sprintf(cmd, "date >> /ageing.log; echo %s >> /ageing.log", file_path);
		system(cmd);
#endif
	}

	return ret;
}

void *dock_upgrade_thread(void *arg)
{
	pthread_detach(pthread_self());
	unsigned char local_fw_version[DOCK_VERSION_SIZE] = { 0 };
	char fw_file_name[MAX_FILE_PATH_SIZE] = { 0 };
	unsigned char md5[MD5_SIZE] = { 0 };
	int ret = 0;
	static bool is_dock_connected = false;
	g_upgrade_info.is_encrypted = 0;

START:
	do {
		/* 等待坞托连接OK */
		do {
			if (g_upgrade_info.schedule.item) {
				free(g_upgrade_info.schedule.item);
				g_upgrade_info.schedule.item = NULL;
			}
			memset(&g_upgrade_info, 0, sizeof(DOCK_UPGRADE_INFO_T));

#ifndef UART_SIMU
			if (jd_uart_is_initialized()) {
				is_dock_info_read = true;
				jd_uart_get_dock_info();

				/* 等待接收坞托信息 */
				if (0 == wait_dock_response(RES_GET_DOCK_INFO, GET_DOCK_INFO_TIMEOUT)) {
#else
			is_dock_info_read = true;
			force_dock_schedule_info();
			if (1) {
				if (1) {
#endif
					/* 上报坞托连接成功 */
					if (!is_dock_connected) {
						is_dock_connected = true;
						dzlog_info("dock is connected\n");
#ifdef J182J
#ifndef DOCK_TEST
						j182_connect_restore();
#endif
#endif
					}

					if (g_upgrade_info.is_busy) {
						dzlog_error("dock is busy now\n");
						sleep(2);
						goto START;
					} else {
#ifndef DOCK_TEST
						/* 设置坞托密码 */
						if (0 == g_upgrade_info.is_encrypted) {
							char passwd[MAX_DOCK_PASSWORD_SIZE] = { 0 };
							ret = get_dock_password(passwd);
							if (0 == ret)
								jd_uart_set_dock_password(passwd, MAX_DOCK_PASSWORD_SIZE);
							else
								LOGV("fail to get dock password, ret %d\n", ret);
						}
#endif
						print_dock_info();
					}
				} else {
					LOGV("get dock info timeout\n");

					/* 上报坞托连接断开 */
					if (is_dock_connected) {
						is_dock_connected = false;
						dzlog_info("dock is disconnected\n");
#ifdef J182J
#ifndef DOCK_TEST
						j182_connect_lost();
#endif
#endif
					}
				}
			} else {
				dzlog_error("dock uart is not ready\n");
				sleep(1);
			}
		} while (!is_dock_connected);

		bzero(local_fw_version, DOCK_VERSION_SIZE);
		bzero(fw_file_name, MAX_FILE_PATH_SIZE);
		bzero(md5, MD5_SIZE);

		/* 判断文件是否拷贝完成 */
		if (!is_dock_file_copy_completed()) {
			dzlog_info("dock upgrade file is copying\n");
			goto UPGRADE_END;
		}

		/* 读取本地固件文件信息 */
		if (0 > get_local_fw_file_info(local_fw_version, fw_file_name, md5)) {
			LOGV("no valid local dock firmware file found!\n");
		} else {
			printf("dock version:%d.%d.%d, file version:%d.%d.%d\n", g_upgrade_info.dock_fw_ver[1],
			       g_upgrade_info.dock_fw_ver[2], g_upgrade_info.dock_fw_ver[3],
			       local_fw_version[1], local_fw_version[2], local_fw_version[3]);

			/* 判断是否需要升级固件 */
			g_upgrade_info.need_upgrade_fw = compare_firmware_version(local_fw_version,
										  g_upgrade_info.dock_fw_ver);
			if (g_upgrade_info.need_upgrade_fw) {
				/* 开始升级固件 */
				ret = dock_send_file(FW_FILE, fw_file_name, md5);
				if (0 == ret) {
					dzlog_info("send file %s to dock %s\n", fw_file_name,
						   g_upgrade_info.need_upgrade_fw ? "fail" : "ok");
					sleep(WAIT_DOCK_UPGRADE_TIME);
					continue;
				}
			}
		}

		/* 获取本地广告文件信息 */
		ret = get_local_adv_file_info();
		if (ret != 0)
			goto UPGRADE_END;

		/* 判断是否升级广告文件 */
		ret = compare_adv_files();
		if (ret != 0)
			goto UPGRADE_END;

		if (g_upgrade_info.need_upgrade_schedule) {
			/* 发送广告排期文件 */
			if (g_upgrade_info.schedule.need_upgrade) {
				ret = dock_send_file(SCHEDULE_FILE, g_upgrade_info.schedule.name, g_upgrade_info.schedule.md5);
				if (0 == ret)
					dzlog_info("send file %s to dock %s\n", g_upgrade_info.schedule.name,
						   g_upgrade_info.schedule.need_upgrade ? "fail" : "ok");

				if (g_upgrade_info.schedule.need_upgrade)
					continue;
			}

			if (g_upgrade_info.schedule.item_cnt > 0) {
				for (int i = 0; i < g_upgrade_info.schedule.item_cnt; i++) {
					g_upgrade_info.sending_item_id = i;
					/* 发送图片文件 */
					if (g_upgrade_info.schedule.item[i].picture.need_upgrade) {
						ret = dock_send_file(PICTURE_FILE, g_upgrade_info.schedule.item[i].picture.name, g_upgrade_info.schedule.item[i].picture.md5);
						if (0 == ret)
							dzlog_info("send file %s to dock %s\n", g_upgrade_info.schedule.item[i].picture.name,
								   g_upgrade_info.schedule.item[i].picture.need_upgrade ? "fail" : "ok");
					}
					/* 发送音频文件 */
					if (g_upgrade_info.schedule.item[i].audio.need_upgrade) {
						ret = dock_send_file(AUDIO_FILE, g_upgrade_info.schedule.item[i].audio.name, g_upgrade_info.schedule.item[i].audio.md5);
						if (0 == ret)
							dzlog_info("send file %s to dock %s\n", g_upgrade_info.schedule.item[i].audio.name,
								   g_upgrade_info.schedule.item[i].audio.need_upgrade ? "fail" : "ok");
					}
				}
			}

#ifndef UART_SIMU
			/* 通知坞托更新完毕 */
			jd_uart_complete_all_files();
#endif

#ifdef AGEING_TEST
			system("date >> /ageing.log; echo success >> /ageing.log");
#endif
		}

#ifdef AGEING_TEST
		if (0 == access("/root/data/j182j/adv/150.txt", F_OK))
			system("cd /root/data/j182j;rm -fr adv/*;cp -fr adv_2/* adv/");
		else
			system("cd /root/data/j182j;rm -fr adv/*;cp -fr adv_3/* adv/ && cp -fr audio_1/* audio/");

#endif

UPGRADE_END:
		sleep(GET_DOCK_INFO_CYCLE);
	} while (1);

	return NULL;
}

int dock_upgrade_init()
{
	pthread_mutex_init(&res_mutex, NULL);
	pthread_cond_init(&res_end_file_cond, NULL);
	pthread_cond_init(&res_get_info_cond, NULL);

	if (pthread_create(&thread_dock_upgrade, NULL,
			   dock_upgrade_thread, NULL)) {
		dzlog_error("create dock upgrade thread fail\n");
		return -1;
	}

	return 0;
}

#ifdef DOCK_TEST
void force_dock_schedule_info()
{
	sprintf(g_upgrade_info.sn, "A234AB1234");
	g_upgrade_info.dock_fw_ver[0] = 0;
	g_upgrade_info.dock_fw_ver[1] = 0;
	g_upgrade_info.dock_fw_ver[2] = 0;
	g_upgrade_info.dock_fw_ver[3] = 1;

	int ret = -1;
	ret = get_local_adv_file_info();
	if (0 != ret)
		return;
	int cnt = 0;
	//int size = sizeof(ITEM_UPGRADE_INFO_T) + g_local_sch->item_cnt * sizeof(ITEM_UPGRADE_INFO_T);
	int size = sizeof(ITEM_UPGRADE_INFO_T) + cnt * sizeof(ITEM_UPGRADE_INFO_T);
	if (g_dock_sch) {
		free(g_dock_sch);
		g_dock_sch = NULL;
	}

	g_dock_sch = calloc(size, 1);
	if (NULL == g_dock_sch) {
		dzlog_error("calloc fail\n");
		return;
	}

	//memcpy(g_dock_sch, g_local_sch, size);
	g_dock_sch->item_cnt = 0;

	//ITEM_UPGRADE_INFO_T *item = (ITEM_UPGRADE_INFO_T *)((char *)g_dock_sch + sizeof(SCHEDULE_UPGRADE_INFO_T));
	//item[2].audio.id = 100;
	//bzero(item[0].picture.md5, MD5_SIZE);
	//bzero(item[0].audio.md5, MD5_SIZE);
}
#endif
