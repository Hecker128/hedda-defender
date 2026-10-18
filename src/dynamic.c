#include "util.c"

#include <stdint.h>
#include <stdio.h>

#include <windows.h>
#include <psapi.h>

BOOL testfunc() {
	uint64_t n_scanned = 0;
	uint64_t n_wx = 0;

	unsigned long n_pids_alloc = 1028;
	unsigned long n_pids;
	unsigned long *pids = malloc(n_pids_alloc * sizeof(unsigned long));

	do {
		if (!EnumProcesses(pids, n_pids_alloc, &n_pids)) {
			print_win_err(GetLastError(), "Failed to enumerate processes");
			return FALSE;
		}
	} while (n_pids == n_pids_alloc && (n_pids_alloc *= 2));

	for (unsigned long i = 0; i < n_pids; i++) {
		if (pids[i] == 0) continue; // System idle process can't be opened, and we don't care about it.

		HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
		if (proc == NULL) {
			print_win_err(GetLastError(), "Failed to open process (PID: %x)", pids[i]);
			continue;
		}

		uint8_t *base = NULL;
		MEMORY_BASIC_INFORMATION info;
		while (VirtualQueryEx(proc, base, &info, sizeof(info)) == sizeof(info)) {
			if (info.AllocationProtect == 0)
				puts("Unable to access memory protection option!");
			else if (info.AllocationProtect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
				puts("Executable and writable memory found (suspicious!)");
				n_scanned += 1;
				n_wx += 1;
			} else
				n_scanned += 1;
			base += info.RegionSize;
		}
	}
	printf("Scanned %lld page ranges.\n", n_scanned);
	printf("Found %lld executable and writable page ranges.\n", n_wx);
	return TRUE;
}

int main() {
	return !testfunc();
}
