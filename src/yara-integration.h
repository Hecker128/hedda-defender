#pragma once

#include <windows.h>
#include <yara.h>

YR_RULES *init_yara(BOOL logging_enabled);
BOOL yara_scan_file(YR_RULES *yara_rules, const char *path, BOOL *matched, BOOL logging_enabled);
void cleanup_yara(YR_RULES *yara_rules);
