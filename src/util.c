#include "util.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

// NOTE: This variable doesn't have an associated mutex for performance
// reasons, so don't access it from the main thread while the scan thread is
// running.
BOOL logging_enabled = FALSE;

//#define LOG_PUTS(msg) if (logging_enabled) { puts(msg); }
//#define LOG_PRINTF(msg, ...) if (logging_enabled) { printf(msg, __VA_ARGS__); }
//#define LOG_PUTCHAR(msg, ...) if (logging_enabled) { putchar(msg); }

uint32_t print_win_err(uint32_t err, const char *fmt, ...) {
	if (!logging_enabled) return err;

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	LPSTR msg = NULL;

    uint32_t flags = FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_ALLOCATE_BUFFER |
                     FORMAT_MESSAGE_IGNORE_INSERTS;

    if (FormatMessageA(flags, NULL, err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&msg, 0, NULL)) {
        printf(". Error code: 0x%x, %s", err, msg);
        LocalFree(msg);
    } else {
        printf(". Error code: 0x%x.\n", err);
    }
	return err;
}
