#include <stdint.h>
#include <stdio.h>
#include <windows.h>

uint32_t print_win_err(uint32_t err, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	const char *msg;
	uint32_t flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
	if (FormatMessage(flags, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char *)&msg, 0, NULL))
		printf(". Error code: 0x%x, %s", err, msg);	
	else
		printf(". Error code: 0x%x.\n", err);
	return err;
}
