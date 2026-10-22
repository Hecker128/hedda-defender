#include "main.c"

int main() {
	puts("main");
	if (!init_scanner()) {
		puts("Failed to init scanner");
		return 1;
	}
	HANDLE scanner = create_scan_thread(".");

	BOOL is_scanning = TRUE;
	while (is_scanning) {
		if (WaitForSingleObject(scan_result_mutex, INFINITE) == WAIT_OBJECT_0) {
			is_scanning = scan_result.is_scanning;
			if (!ReleaseMutex(scan_result_mutex)) {
				puts("Failed to release mutex");
				return 1;
			}
		}
	}
	CloseHandle(scanner);

	puts("scanned successfully");
}
