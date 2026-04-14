// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LOG__H__
#define LOG__H__
#include <stdio.h>

extern int dbg__;
extern int info__;

void enable_debug(void);
void disable_info(void);

#define pr_dbg(fmt, ...) \
		if (dbg__) {mprint(stderr, "dbg: " fmt, ##__VA_ARGS__);}
#define pr_info(fmt, ...) \
		if (info__) {mprint(stdout, fmt, ##__VA_ARGS__);}
#define pr_err(fmt, ...) \
		if (1) {mprint(stderr, fmt, ##__VA_ARGS__);}

void mprint(FILE* stream, const char* fmt, ...);

#endif // LOG__H__
