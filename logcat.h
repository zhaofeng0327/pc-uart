#ifndef _LOGCAT_H_
#define _LOGCAT_H_
#define LOGI(...) do { printf(__VA_ARGS__); } while (0)
#define LOGD(...) do { printf(__VA_ARGS__); } while (0)
#define LOGE(...) do { printf(__VA_ARGS__); } while (0)
#define LOGV(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_info(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_debug(...) do { printf(__VA_ARGS__); } while (0)
#define dzlog_error(...) do { printf(__VA_ARGS__); } while (0)

#endif
