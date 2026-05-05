#include "sfw_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <rte_spinlock.h>

static FILE *log_file = NULL;
static size_t log_max_size = 0;
static char log_filename[256];
static rte_spinlock_t log_lock = RTE_SPINLOCK_INITIALIZER;

int sfw_log_init(const char *filename, size_t max_size) {
    if (filename == NULL || max_size == 0) return -1;
    
    strncpy(log_filename, filename, sizeof(log_filename) - 1);
    log_filename[sizeof(log_filename) - 1] = '\0';
    log_max_size = max_size;
    
    log_file = fopen(log_filename, "a");
    if (log_file == NULL) {
        return -1;
    }
    return 0;
}

void sfw_log_close(void) {
    rte_spinlock_lock(&log_lock);
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
    rte_spinlock_unlock(&log_lock);
}

void sfw_log_write(const char *func, int line, const char *format, ...) {
    if (log_file == NULL) return;

    rte_spinlock_lock(&log_lock);
    
    long pos = ftell(log_file);
    if (pos >= 0 && (size_t)pos >= log_max_size) {
        fclose(log_file);
        
        char backup_filename[512];
        snprintf(backup_filename, sizeof(backup_filename), "%s.1", log_filename);
        rename(log_filename, backup_filename);
        
        log_file = fopen(log_filename, "w");
        if (log_file == NULL) {
            rte_spinlock_unlock(&log_lock);
            return;
        }
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[26];
    strftime(time_buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "[%s] %s:%d - ", time_buf, func, line);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fflush(log_file);
    
    rte_spinlock_unlock(&log_lock);
}
