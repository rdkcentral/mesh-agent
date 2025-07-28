#ifndef _XMESH_DIAG_
#define _XMESH_DIAG_

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>

char* getFormattedTime(void);
FILE* log_file = NULL;
bool  g_flog = true;        //for logging to file
bool  g_clog = false;       //for logging to console

#define LOG_FILE_BBOX     "/rdklogs/logs/MeshBlackbox.log"
#define LOG_FILE_BBOXDMP  "/rdklogs/logs/MeshBlackboxDumps.log"
#define __LOG__(format, loglevel, file, log2console, log2file, color_start, color_end, ...)                         \
    do {                                                                                                            \
        if (g_clog && log2console) {                                                                                \
            printf("%s%s %-5s " format "%s", color_start, getFormattedTime(), loglevel, ## __VA_ARGS__, color_end); \
        }                                                                                                           \
        if (log2file) {                                                                                             \
            log_file = fopen(file, "a");                                                                            \
            if (log_file) {                                                                                         \
                fprintf(log_file, "%s %-5s " format, getFormattedTime(), loglevel, ## __VA_ARGS__);                 \
                fclose(log_file);                                                                                   \
                log_file = NULL;                                                                                    \
            }                                                                                                       \
        }                                                                                                           \
    } while (0)

#define LOGINFO(format, ...)      __LOG__(format, "INFO" , LOG_FILE_BBOX, true, g_flog, "", "", ## __VA_ARGS__)
#define LOGSUCCESS(format, ...)   __LOG__(format, "INFO" , LOG_FILE_BBOX, true, g_flog, "\033[32m", "\033[m", ## __VA_ARGS__)
#define LOGERROR(format, ...)     __LOG__(format, "ERROR", LOG_FILE_BBOX, true, g_flog, "\033[31m", "\033[m", ## __VA_ARGS__)

#define LOGDUMPINFO(format, ...)  __LOG__(format, "INFO" , LOG_FILE_BBOXDMP, false, true, "", "", ## __VA_ARGS__)
#define LOGDUMPERROR(format, ...) __LOG__(format, "ERROR", LOG_FILE_BBOXDMP, false, true, "\033[31m", "\033[m", ## __VA_ARGS__)

#define LOG_TO_CONSOLE(x) g_clog = x
#define LOG_TO_FILE(x)    g_flog = x

void xmesh_diag_start(int interval, bool dumps_enabled, bool wfo, int delay);
void xmesh_diag_stop();

#endif //_XMESH_DIAG_
