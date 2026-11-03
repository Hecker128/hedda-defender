#pragma once

#include <windows.h>

HRESULT init_appnotifications(BOOL logging_enabled_);
HRESULT send_threat_found_notification(const char *threat_path);
void uninit_appnotifications();
