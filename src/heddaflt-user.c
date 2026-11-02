#include <stdlib.h>
#include <windows.h>
#include <fltuser.h>
#include "HeddaFlt/HeddaFlt.h"
#include "util.h"

#ifdef USE_YARA
# include "yara-integration.h"

// Yara rules for HeddaFlt message handler thread.
// Set by `create_heddaflt_message_handler_thread` before thread creation.
static YR_RULES *yara_rules;
#endif

// Logging enabled for HeddaFlt message handler thread.
// Set by `create_heddaflt_message_handler_thread` before thread creation.
static BOOL logging_enabled;

typedef struct {
	FILTER_MESSAGE_HEADER head;
	HeddaFltMsg msg;
} UserMsg;

typedef struct {
	FILTER_REPLY_HEADER head;
	HeddaFltReply reply;
} UserReply;

static HRESULT get_pre_create_heddaflt_message(HANDLE port, UserMsg *user_msg) {
	HRESULT result = FilterGetMessage(port, &user_msg->head, sizeof(UserMsg), NULL);
	if (IS_ERROR(result))
		return LOG_PRINT_HRESULT(result, "Failed to get pre-create message from HeddaFlt");

	if (user_msg->msg.kind == HEDDAFLT_MSG_PRE_CREATE) {
		LOG_PRINTF("Desired access: 0x%lx\n", user_msg->msg.kind_union.pre_create.desired_access);
		return HRESULT_FROM_WIN32(ERROR_SUCCESS);
	}

	LOG_PUTS("Unexpected HeddaFlt message kind.");

	if (user_msg->msg.kind == HEDDAFLT_MSG_ERROR) {
		LOG_PRINT_HRESULT(user_msg->msg.kind_union.error.status, "msg.kind_union.error.status");
		LOG_PRINTF("Error context: %lu\n", user_msg->msg.kind_union.error.context);
	}
	return E_UNEXPECTED;
}

static HRESULT handle_heddaflt_messages(HANDLE port) {
	static UserMsg user_msg;
	HRESULT result = get_pre_create_heddaflt_message(port, &user_msg);
	if (IS_ERROR(result)) return result;

	const size_t path_sz_full = user_msg.msg.kind_union.pre_create.path_sz;
	WCHAR *full_path;

	if (path_sz_full > sizeof(user_msg.msg.body)) {
		size_t path_sz_written = 0;
		full_path = malloc(path_sz_full);
		for (;;) {
			size_t path_sz_delta = fmin(
				path_sz_full - path_sz_written,
				sizeof(user_msg.msg.body)
			);
			memcpy(full_path + path_sz_written/2, user_msg.msg.body, path_sz_delta);
			path_sz_written += path_sz_delta;

			if (path_sz_written >= path_sz_full) break;

			result = get_pre_create_heddaflt_message(port, &user_msg);
			if (IS_ERROR(result)) {
				free(full_path);
				return result;
			}
			if (user_msg.msg.kind_union.pre_create.path_sz != path_sz_full) {
				LOG_PUTS("HeddaFlt pre-create message path size missmatch.");
				free(full_path);
				return E_UNEXPECTED;
			}
		}
	} else {
		full_path = user_msg.msg.body;
	}
	LOG_PRINTF("Full path: %.*ls\n", (int)path_sz_full, full_path);

	static UserMsg user_msg2;
	FilterGetMessage(port, &user_msg2.head, sizeof(UserMsg), NULL);
	if (IS_ERROR(result)) {
		if (path_sz_full > sizeof(user_msg.msg.body)) free(full_path);
		return LOG_PRINT_HRESULT(result, "Failed to get \"please don't ghost me\" message from HeddaFlt");
	}
	if (user_msg2.msg.kind != HEDDAFLT_MSG_PLEASE_DONT_GHOST_ME) {
		if (path_sz_full > sizeof(user_msg.msg.body)) free(full_path);
		LOG_PRINTF("Unexpected HeddaFlt message kind (expected HEDDAFLT_MSG_PLEASE_DONT_GHOST_ME, received %lu).\n", user_msg2.msg.kind);
		return HRESULT_FROM_WIN32(ERROR_SUCCESS);
		//return E_UNEXPECTED;
	}

	UserReply user_reply;
#ifdef USE_YARA
	size_t path_len_utf8 = WideCharToMultiByte(CP_UTF8, 0, full_path, path_sz_full/2, NULL, 0, NULL, NULL);
	if (path_len_utf8 == 0) {
		if (path_sz_full > sizeof(user_msg.msg.body)) free(full_path);
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get size to convert file path to UTF-8");
		return E_UNEXPECTED;
	}
	char *path_utf8 = malloc(path_len_utf8 + 1);
	if (WideCharToMultiByte(CP_UTF8, 0, full_path, path_sz_full/2, path_utf8, path_len_utf8, NULL, NULL) == 0) {
		if (path_sz_full > sizeof(user_msg.msg.body)) free(full_path);
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to convert file path to UTF-8");
		return E_UNEXPECTED;
	}
	path_utf8[path_len_utf8] = 0;

	BOOL matched;
	if (yara_scan_file(yara_rules, path_utf8, &matched, logging_enabled))
		user_reply.reply.operation_allowed = !matched;
	else
		user_reply.reply.operation_allowed = TRUE;
	free(path_utf8);
#else
	user_reply.reply.operation_allowed = TRUE;
#endif
	result = FilterReplyMessage(port, &user_reply.head, sizeof(UserReply));
	if (IS_ERROR(result))
		LOG_PRINT_HRESULT(result, "Failed to reply to \"please don't ghost me\" message from HeddaFlt");

	if (path_sz_full > sizeof(user_msg.msg.body)) free(full_path);
	return result;
}

static BOOL enable_se_load_driver_privilege() {
	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get LUID for privilege");
		return FALSE;
	}

	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to open access token");
		return FALSE;
	}

	DWORD privs_sz;
	if (GetTokenInformation(token, TokenPrivileges, NULL, 0, &privs_sz) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(token);
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get size of token privileges");
		return FALSE;
	}

	TOKEN_PRIVILEGES *privs = malloc(privs_sz);

	if (!GetTokenInformation(token, TokenPrivileges, privs, privs_sz, &privs_sz)) {
		CloseHandle(token);
		free(privs);
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get token privileges");
		return FALSE;
	}
	
	for (DWORD i = 0; i < privs->PrivilegeCount; i++)
		if (privs->Privileges[i].Luid.LowPart == luid.LowPart == privs->Privileges[i].Luid.HighPart == luid.HighPart) {
			privs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

			BOOL res = AdjustTokenPrivileges(token, FALSE, privs, privs_sz, NULL, NULL);
			CloseHandle(token);
			free(privs);

			if (!res) LOG_PRINT_WIN_ERR(GetLastError(), "Failed to enable privilege");
			return res;
		}

	CloseHandle(token);
	free(privs);
	LOG_PUTS("Failed to find privilege in access token.");
	return FALSE;
}

static DWORD WINAPI heddaflt_message_handler_routine(LPVOID lpParam) {
	HRESULT result;
	BOOL service_already_existed;
	if (enable_se_load_driver_privilege()) {
		result = FilterLoad(L"HeddaFlt");
		if (result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) || result == HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING))
			service_already_existed = TRUE;
		else if (IS_ERROR(result))
			return LOG_PRINT_HRESULT(result, "Failed to load HeddaFlt");
		else
			service_already_existed = FALSE;
	} else {
		LOG_PUTS("Assuming HeddaFlt is already loaded because SeLoadDriverPrivilege couldn't be enabled, so this process can't load it.\n" \
			"If it's not already loaded, it should be loaded manually with the default instance attached.\n" \
			"Consider running hedda-defender.exe as administrator to load HeddaFlt automatically.");
		service_already_existed = TRUE;
	}

	// TODO: Support other volumes than "C:".
	result = FilterAttach(L"HeddaFlt", L"C:\\", NULL, 0, NULL);
	if (result == ERROR_FLT_INSTANCE_ALTITUDE_COLLISION || result == ERROR_FLT_INSTANCE_NAME_COLLISION) {
		LOG_PUTS("Using existing HeddaFlt instance.");
	} else if (IS_ERROR(result)) {
		if (!service_already_existed) FilterUnload(L"HeddaFlt");
		return LOG_PRINT_HRESULT(result, "Failed to create default HeddaFlt instance");
	} else {
		LOG_PUTS("Successfully created default HeddaFlt instance.");
	}

	HANDLE port;
	result = FilterConnectCommunicationPort(L"\\HeddaFltPort", 0, NULL, 0, NULL, &port);
	if (IS_ERROR(result)) {
		if (!service_already_existed) FilterUnload(L"HeddaFlt");
		return LOG_PRINT_HRESULT(result, "Failed to connect to HeddaFlt communication port");
	}
	LOG_PUTS("Successfully connected to HeddaFlt communication port.");

	for (;;) {
		result = handle_heddaflt_messages(port);
		if (IS_ERROR(result)) {
			LOG_PRINT_HRESULT(result, "Terminating HeddaFlt message handler thread.");
			if (result != E_HANDLE) CloseHandle(port);
			break;
		}
	}

	if (!service_already_existed) FilterUnload(L"HeddaFlt");
	return 0;
}

HANDLE create_heddaflt_message_handler_thread(
	BOOL logging_enabled_
#ifdef USE_YARA
	, YR_RULES *yara_rules_
#endif
) {
	logging_enabled = logging_enabled_;
#ifdef USE_YARA
	yara_rules = yara_rules_;
#endif
	DWORD _tid;
	return CreateThread(NULL, 0, heddaflt_message_handler_routine, NULL, 0, &_tid);
}
