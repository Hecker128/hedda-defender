#pragma once

#include <windows.h>
#ifdef USE_YARA
# include "yara-integration.h"
#endif

typedef struct {
	char *path;
	BYTE hash[32];
} FileInfo;

typedef struct {
	DWORD64 n_total;
	DWORD64 n_scanned;
	DWORD64 n_sus;
	DWORD64 n_malicious;
	FileInfo *malicious_infos;
	BOOL is_scanning;
	BOOL is_counting_files;
} ScanResult;

ScanResult *acquire_scan_result();
BOOL release_scan_result();
BOOL init_scanner(BOOL logging_enabled_
#ifdef USE_YARA
	, YR_RULES *yara_rules_
#endif
);
HANDLE create_scan_thread(char *path);
void uninit_scanner();
