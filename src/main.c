#include <stdio.h>
#include <windows.h>
#include "scanner.h"
#include "gui.c"
#ifdef USE_API_HOOKS
# include "dynamic.c"
#endif
#ifdef USE_HEDDAFLT
# include "heddaflt-user.c"
#endif
#ifdef USE_APPNOTIFICATIONS
# include "appnotifications.h"
#endif
#ifdef USE_YARA
# include "yara-integration.h"
#endif

typedef struct {
	BOOL logging_enabled;
	char *root_dir;
} ParseArgsResult;

/// Parses command line arguments and acts on them.
/// Returns `FALSE` if Hedda Defender should close (e.g. if an invalid argument
/// was passed).
static BOOL parse_args(ParseArgsResult *result, int argc, char **argv) {
	static char root_dir_default[] = "C:";
	const char *usage =
		"USAGE: hedda-defender.exe [options]\n"
		"\n"
		"OPTIONS:\n"
		"  -v\t\t- verbose (i.e. enable logging to stdout)\n"
		"  -r path...\t- root directory for scanning (default is 'C:')";

	result->logging_enabled = FALSE;
	result->root_dir = root_dir_default;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			result->logging_enabled = TRUE;
		} else if (strcmp(argv[i], "-r") == 0) {
			if (++i >= argc) {
				puts(usage);
				return FALSE;
			}
			result->root_dir = argv[i];
		} else {
			puts(usage);
			return FALSE;
		}
	}
	return TRUE;
}

int main(int argc, char **argv) {
	ParseArgsResult args_result;
	if (!parse_args(&args_result, argc, argv)) return 1;
#ifdef USE_YARA
	YR_RULES *yara_rules = init_yara(args_result.logging_enabled);
	if (yara_rules == NULL) return 1;
#endif
	if (!init_scanner(
		logging_enabled
#ifdef USE_YARA
		, yara_rules
#endif
	)) {
		LOG_PUTS("Failed to initialize scanner.");
		return 1;
	}
#ifdef USE_APPNOTIFICATIONS
	HRESULT result = init_appnotifications(args_result.logging_enabled);
	if (!SUCCEEDED(result)) return result;
#endif
#ifdef USE_API_HOOKS
	HANDLE hookerThread = create_dynamic_hook_injector_thread(args_result.logging_enabled);
	if (hookerThread == NULL)
		LOG_PUTS("API hook injection will not be done because thread creation failed.");
#endif
#ifdef USE_HEDDAFLT
	HANDLE heddaflt_thread = create_heddaflt_message_handler_thread(
		args_result.logging_enabled
#ifdef USE_YARA
		, yara_rules
#endif
	);
	if (heddafltMsgThread == NULL)
		LOG_PUTS("HeddaFlt will not be used because thread creation failed.");
#endif
	guiMain(logging_enabled, args_result.root_dir, yara_rules);
#ifdef USE_HEDDAFLT
	if (heddaflt_thread != NULL) CloseHandle(heddafltMsgThread);
#endif
#ifdef USE_API_HOOKS
	if (hookerThread != NULL) CloseHandle(hookerThread);
#endif
#ifdef USE_APPNOTIFICATIONS
	uninit_appnotifications();
#endif
}
