#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

extern BOOL logging_enabled;

#define LOG_PUTS(msg) \
    do { if (logging_enabled) puts(msg); } while (0)

#define LOG_PRINTF(fmt, ...) \
    do { if (logging_enabled) printf(fmt, __VA_ARGS__); } while (0)

#define LOG_PUTCHAR(ch, ...) \
    do { if (logging_enabled) putchar(ch); } while (0)

uint32_t print_win_err(uint32_t err, const char *fmt, ...);

#endif
