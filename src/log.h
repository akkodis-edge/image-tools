#ifndef LOG__H__
#define LOG__H__
#include <stdio.h>

extern int dbg;
extern int info;

void enable_debug(void);
void disable_info(void);

#define pr_dbg(fmt, ...) \
		if (dbg) {mprint(stderr, "dbg: " fmt, ##__VA_ARGS__);}
#define pr_info(fmt, ...) \
		if (info) {mprint(stdout, fmt, ##__VA_ARGS__);}
#define pr_err(fmt, ...) \
		if (1) {mprint(stderr, fmt, ##__VA_ARGS__);}

void mprint(FILE* stream, const char* fmt, ...);

#endif // LOG__H__
