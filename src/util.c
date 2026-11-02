#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winerror.h>

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

/// Prints formatted text, followed by the HRESULT specified by `result`, then
/// returns `result`.
HRESULT print_hresult(HRESULT result, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	uint32_t flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
	LPSTR msg = NULL;
	if (FormatMessageA(flags, NULL, result & 0x0000FFFF, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL)) {
		printf(". HRESULT: 0x%lx, %s", result, msg);
		LocalFree(msg);
	} else
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
