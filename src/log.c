#include <stdio.h>
#include <stdarg.h>
#include "log.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
int dbg = 0;
void enable_debug(void)
{
	dbg = 1;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
int info = 1;
void disable_info(void)
{
	info = 0;
}

void mprint(FILE* stream, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	va_end(args);
}
