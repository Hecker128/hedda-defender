#ifndef _UTIL_C
#define _UTIL_C

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winerror.h>

/// Macros for using I/O functions conditionally based on logging_enabled,
/// which should be defined locally or per-file (so different threads don't
/// access the same logging_enabled).
#define LOG_PUTS(msg) if (logging_enabled) { puts(msg); }
#define LOG_PRINTF(fmt, ...) if (logging_enabled) { printf(fmt __VA_OPT__(,) __VA_ARGS__); }
#define LOG_PUTCHAR(msg) if (logging_enabled) { putchar(msg); }
#define LOG_PRINT_WIN_ERR(err, fmt, ...) if (logging_enabled) { print_win_err(err, fmt __VA_OPT__(,) __VA_ARGS__); }
#define LOG_PRINT_HRESULT(result, fmt, ...) (logging_enabled ? print_hresult(result, fmt __VA_OPT__(,) __VA_ARGS__) : result)
#define LOG_PRINT_HEX_DELTA(a, b, size) if (logging_enabled) { print_hex_delta(a, b, size); }

/// Prints formatted text, followed by the windows error code (returned by
/// functions like GetLastError) specified by `err`.
void print_win_err(uint32_t err, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	uint32_t flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
	LPSTR msg = NULL;
	if (FormatMessageA(flags, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL)) {
		printf(". Error code: 0x%x, %s", err, msg);
		LocalFree(msg);
	} else
		printf(". Error code: 0x%x.\n", err);
}

// Prints formatted text, followed by the HRESULT specified by `result`, then
// returns `result`.
HRESULT print_hresult(HRESULT result, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf(". HRESULT: 0x%lx.\n", result);
	return result;
}

/// Prints `a` as hex and highlight everything green except deltas from `b`.
void print_hex_delta(const uint8_t *a, const uint8_t *b, size_t size) {
	for (size_t i = 0; i < size; i++)
		if (a[i] == b[i]) printf("\e[0;32m""%.2x""\e[0m ", (int)a[i]);
		else printf("%.2x ", (int)a[i]);
	putchar('\n');
}

#endif // ! _UTIL_C
