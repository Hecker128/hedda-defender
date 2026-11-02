#include "util.h"

#include <stdint.h>

#include <windows.h>
#include <psapi.h>

// Logging enabled for dynamic hook injector thread.
// Set by create_dynamic_hook_injector_thread before thread creation.
static BOOL logging_enabled;

static void *get_func_addr_in_proc(HMODULE proc_mod, HMODULE local_mod, const char *func_name) {
	void *addr = GetProcAddress(local_mod, func_name);
	if (!addr) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get local address of %s", func_name);
		return NULL;
	}
	return (uint8_t *)addr - (uint8_t *)local_mod + (uint8_t *)proc_mod;
}

static void *copy_to_proc_executable(HANDLE proc, void *data, size_t size) {
	void *proc_addr = VirtualAllocEx(proc, NULL, size, MEM_COMMIT, PAGE_READWRITE);
	if (proc_addr == NULL) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to allocate memory in external process address space");
		return NULL;
	}

	if (!WriteProcessMemory(proc, proc_addr, data, size, NULL)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to write to external process address space");
		return NULL;
	}

	DWORD _old_prot;
	if (!VirtualProtectEx(proc, proc_addr, size, PAGE_EXECUTE, &_old_prot)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to make data in external process address space executable");
		return NULL;
	}
	return proc_addr;
}

// FIXME: This just redirects to VirtualAllocEx in
// "api-ms-win-core-memory-11-1-0.dll". Ideally we would hook that function
// instead of this one, but I'm too lazy for that for now.
#define VIRTUALALLOCEX_BODY \
	0x48, 0xFF, 0x25, 0xB9, 0x82, 0x04, 0x00 // JMP QWORD PTR [RIP + 0x482B9]

// TODO: DRY.
static BOOL apply_VirtualAllocEx_hook(HANDLE proc, HMODULE proc_mod, HMODULE local_mod) {
	uint8_t *proc_func = get_func_addr_in_proc(proc_mod, local_mod, "VirtualAllocEx");
	uint8_t *proc_fatalappexit = get_func_addr_in_proc(proc_mod, local_mod, "FatalAppExitA");
	if (!proc_func) return FALSE;
	if (!proc_fatalappexit) return FALSE;

	uint8_t local_func[] = {
		0,0,0,0,0,0, // Space for JMP
		0,0,0,0,0,0,0,0, // Space for address for JMP
		VIRTUALALLOCEX_BODY // Where the (modified) body will be moved
	};
	if (!ReadProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to read VirtualAllocEx in external process address space");
		return FALSE;
	}

	const uint8_t body[] = { VIRTUALALLOCEX_BODY };
	size_t body_sz = sizeof(body);
	if (memcmp(local_func, body, body_sz) != 0) {
		LOG_PUTS("Unexpected data in VirtualAllocEx in external process address space:");
		LOG_PRINT_HEX_DELTA(local_func, body, body_sz);
		return FALSE;
	}

	const char msg[] = "Program is likely malicious.";
	uint8_t local_hook[5+2+6+8+3+7+6+8+sizeof(msg)];
	memcpy(local_hook, (uint8_t[5]){ 0x83, 0x7C, 0x24, 0x28, 0x40 }, 5);		// CMP 0x40, DWORD PTR [RSP + 40]
	memcpy(local_hook+5, (uint8_t[2]){ 0x74, 0x0E }, 2);				// JZ RIP + 14
	memcpy(local_hook+5+2, (uint8_t[6]){ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }, 6);	// JMP QWORD PTR [RIP]
	void *dest = proc_func + 6+8;
	memcpy(local_hook+7+6, &dest, 8); // Pointer to the (modified) body of the function
	memcpy(local_hook+7+6+8, (uint8_t[3]){ 0x48, 0x31, 0xC9 }, 3);			// XOR RCX, RCX
	memcpy(local_hook+7+6+8+3, (uint8_t[7]){ 0x48, 0x8D, 0x15, 0x0E, 0x00, 0x00, 0x00 }, 7);//LEA RDX [RIP + 14]
	memcpy(local_hook+7+6+8+3+7, (uint8_t[6]){ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 }, 6);// CALL QWORD PTR [RIP]
	memcpy(local_hook+7+6+8+10+6, &proc_fatalappexit, 8);
	memcpy(local_hook+7+6+8+16+8, msg, sizeof(msg));
	
	void *proc_hook = copy_to_proc_executable(proc, local_hook, sizeof(local_hook));
	if (proc_hook == NULL) return FALSE;

	memcpy(local_func, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	memcpy(local_func+6, &proc_hook, 8); // Address of hook
	memcpy(local_func+6+8, (uint8_t[7]){ 0x48, 0xFF, 0x25, 0xB9 - 6 - 8, 0x82, 0x04, 0x00 }, 7); // JMP QWORD PTR [RIP + 0x482B9 - 6 - 8]
	
	if (!WriteProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to inject code into VirtualAllocEx in external process address space");
		return FALSE;
	}
	return TRUE;
}

#define CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS \
    0x4C, 0x8B, 0xDC, \
    0x48, 0x83, 0xEC, 0x48, \
    0x44, 0x8B, 0x54, 0x24, 0x78, \
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00

// TODO (1): DRY.
// TODO (2): Check arguments and stuff. This hook is useless until that is implemented.
static BOOL apply_CreateRemoteThread_hook(HANDLE proc, HMODULE proc_mod, HMODULE local_mod) {
	uint8_t *proc_func = get_func_addr_in_proc(proc_mod, local_mod, "CreateRemoteThread");
	if (!proc_func) return FALSE;

	uint8_t local_func[] = { CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS };
	if (!ReadProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to read CreateRemoteThread in external process address space");
		return FALSE;
	}

	const uint8_t trampoline[] = { CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS };
	size_t trampoline_sz = sizeof(trampoline);
	if (memcmp(local_func, trampoline, trampoline_sz) != 0) {
		LOG_PUTS("Unexpected data in CreateRemoteThread in external process address space:");
		LOG_PRINT_HEX_DELTA(local_func, trampoline, trampoline_sz);
		return FALSE;
	}

	uint8_t local_hook[trampoline_sz+6+8];
    memcpy(local_hook, trampoline, trampoline_sz);
	memcpy(local_hook+trampoline_sz, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	void *dest = proc_func + trampoline_sz;
	memcpy(local_hook+trampoline_sz+6, &dest, 8); // Pointer to the rest of the function (after the trampoline instructions)
	
	void *proc_hook = copy_to_proc_executable(proc, local_hook, sizeof(local_hook));
	if (proc_hook == NULL) return FALSE;

	memcpy(local_func, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	memcpy(local_func+6, &proc_hook, 8); // Address of hook
	
	if (!WriteProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to inject code into CreateRemoteThread in external process address space");
		return FALSE;
	}
	return TRUE;
}

static BOOL inject_hooks_dynamic() {
	unsigned long pids_cb_alloc = 1028;
	unsigned long pids_cb;
	unsigned long *pids = malloc(pids_cb_alloc);
	do {
		if (!EnumProcesses(pids, pids_cb_alloc, &pids_cb)) {
			LOG_PRINT_WIN_ERR(GetLastError(), "Failed to enumerate processes");
			return FALSE;
		}
	} while (pids_cb == pids_cb_alloc && (pids_cb_alloc *= 2) && (pids = realloc(pids, pids_cb_alloc)));

	for (unsigned long i = 0; i < pids_cb / sizeof(unsigned long); i++) {
		if (pids[i] == 0) continue; // System idle process can't be opened, and we don't care about it.

		HANDLE proc = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
			FALSE,
			pids[i]
		);
		if (proc == NULL) {
			LOG_PRINT_WIN_ERR(GetLastError(), "Failed to open process (PID: %x)", pids[i]);
			continue;
		}

		unsigned long mods_cb_alloc = 1028;
		unsigned long mods_cb;
		HMODULE *mods = malloc(mods_cb_alloc);
		do {
			if (!EnumProcessModules(proc, mods, mods_cb_alloc, &mods_cb)) {
				LOG_PRINT_WIN_ERR(GetLastError(), "Failed to enumerate modules for process (PID: %x)", pids[i]);
				goto next_pid;
			}
		} while (mods_cb > mods_cb_alloc && (mods_cb_alloc = mods_cb) && (mods = realloc(mods, mods_cb_alloc)));

		for (unsigned long j = 0; j < mods_cb / sizeof(HMODULE); j++) {
			char name[MAX_PATH];
			if (!GetModuleFileNameEx(proc, mods[j], name, sizeof(name))) {
				////
				continue;
			}
			size_t name_len = strlen(name);
			size_t cmp_len = sizeof("kernel32.dll") - 1;
			if (name_len >= cmp_len && stricmp(name + name_len - cmp_len, "kernel32.dll") == 0) {
				HMODULE local_mod = LoadLibrary("kernel32.dll");
				if (local_mod == NULL) {
					////
					continue;
				}
				apply_VirtualAllocEx_hook(proc, mods[j], local_mod);
				FreeLibrary(local_mod);
			}
			////LOG_PUTS(name);
		}

	next_pid:
		free(mods);
		CloseHandle(proc);
	}
	free(pids);
	return TRUE;
}

static DWORD WINAPI dynamic_hook_injector_routine(LPVOID lpParam) {
	for (;;) {
		inject_hooks_dynamic();
		Sleep(1000);
	}
}

/// Returns the handle to the created thread.
/// Do NOT run multiple of these threads at the same time.
HANDLE create_dynamic_hook_injector_thread(BOOL logging_enabled_) {
	logging_enabled = logging_enabled_;
	DWORD _tid;
	return CreateThread(NULL, 0, dynamic_hook_injector_routine, NULL, 0, &_tid);
}
