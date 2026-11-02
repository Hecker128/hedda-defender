#include "util.h"
#include <windows.h>
#include <yara.h>

typedef struct {
	BOOL *matched;
	BOOL logging_enabled;
} YaraMatchedCallbackUserData;

static int yara_match_callback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;

        BOOL *matched = ((YaraMatchedCallbackUserData *)user_data)->matched;
	BOOL logging_enabled = ((YaraMatchedCallbackUserData *)user_data)->logging_enabled;

        *matched = TRUE;
        LOG_PRINTF("YARA match: %s\n", rule->identifier);
    }
    return CALLBACK_CONTINUE;
}   

/// Initializes yara globally and returns yara rules compiled from the YARA
/// directory.
/// Should be called once from the main thread, which can pass it to the
/// threads that use YARA (i.e. the scanner and HeddaFlt message handler
/// threads).
/// Returns `NULL` on failure.
YR_RULES *init_yara(BOOL logging_enabled) {
	int error = yr_initialize();
	if (error != ERROR_SUCCESS) {
		LOG_PRINTF("Failed to initialize YARA. Error: %d.\n", error);
		return NULL;
	}
	YR_COMPILER *compiler;
	error = yr_compiler_create(&compiler);
	if (error != ERROR_SUCCESS) {
		LOG_PRINTF("Failed to create YARA compiler. Error: %d.\n", error);
		yr_finalize();
		return NULL;
	}
	const char *rule_paths[] = {
		"src\\YARA\\RANSOM_MS17-010_Wannacrypt.yar",
		"src\\YARA\\RANSOM_Petya.yar"
	};
	for (size_t i = 0; i < sizeof(rule_paths) / sizeof(*rule_paths); i++) {
		FILE *file = fopen(rule_paths[i], "r");
		if (file == NULL) {
			LOG_PRINTF("Could not open YARA rule file: %s\n", rule_paths[i]);
			yr_compiler_destroy(compiler);
			yr_finalize();
			return NULL;
		}
		error = yr_compiler_add_file(compiler, file, NULL, rule_paths[i]);
		fclose(file);

		if (error != ERROR_SUCCESS) {
			LOG_PRINTF("Failed to compile YARA rules from \"%s\". Error: %d.\n", rule_paths[i], error);
			yr_compiler_destroy(compiler);
			yr_finalize();
			return NULL;
		}
	}

	YR_RULES *yara_rules;
	error = yr_compiler_get_rules(compiler, &yara_rules);
	yr_compiler_destroy(compiler);

	if (error != ERROR_SUCCESS) {
		LOG_PRINTF("Failed to compile the final YARA rules. Error: %d.\n", error);
		yr_finalize();
		return NULL;
	}
	LOG_PUTS("YARA rules loaded successfully.");
	return yara_rules;
}

/// Scans the file specified by `path` using `yara_rules`.
/// If the file matches the rules, `*matched` is set to `TRUE`. Otherwise it's
/// set to `FALSE`.
/// Returns `FALSE` on failure.
BOOL yara_scan_file(YR_RULES *yara_rules, const char *path, BOOL *matched, BOOL logging_enabled) {
	YaraMatchedCallbackUserData user_data = { matched, logging_enabled };
	int result = yr_rules_scan_file(yara_rules, path, SCAN_FLAGS_FAST_MODE, yara_match_callback, &user_data, 0);
	if (result == ERROR_COULD_NOT_OPEN_FILE) {
		LOG_PRINT_WIN_ERR(GetLastError(), "YARA scan failed for \"%s\" because the file couldn't be opened", path);
		return FALSE;
	} else if (result != ERROR_SUCCESS) {
		LOG_PRINTF("YARA scan failed for \"%s\". libyara error: %d.\n", path, result);
		return FALSE;
	}
	return TRUE;
}

/// Should be called once from the main thread once `yara_rules` will no longer
/// be used.
void cleanup_yara(YR_RULES *yara_rules) {
	yr_rules_destroy(yara_rules);
	yr_finalize();
}
