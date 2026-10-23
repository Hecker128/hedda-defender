#ifndef SCANNER_H
#define SCANNER_H

#include <windows.h>
#include <stdint.h>

typedef struct {
    BOOL is_scanning;
    BOOL is_counting_files;
    uint64_t n_scanned;
    uint64_t n_total;
} ScanResult;

extern ScanResult scan_result;
extern HANDLE scan_result_mutex;

BOOL init_scanner(void);
HANDLE create_scan_thread(const char *root_path);

#endif
