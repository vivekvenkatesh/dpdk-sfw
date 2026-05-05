#ifndef __SFW_LOG_H__
#define __SFW_LOG_H__

#include <stdio.h>
#include <stddef.h>

int sfw_log_init(const char *filename, size_t max_size);
void sfw_log_close(void);
void sfw_log_write(const char *func, int line, const char *format, ...);

#define SFW_LOG(fmt, ...) sfw_log_write(__func__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* __SFW_LOG_H__ */
