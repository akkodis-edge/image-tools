// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
int dbg__ = 0;
void enable_debug(void)
{
	dbg__ = 1;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
int info__ = 1;
void disable_info(void)
{
	info__ = 0;
}

void mprint(FILE* stream, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	va_end(args);
}
