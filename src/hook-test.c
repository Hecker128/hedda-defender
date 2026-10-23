#include "util.c"

#include <stdint.h>
#include <stdio.h>

#include <windows.h>
#include <psapi.h>

void *get_func_addr_in_proc(HMODULE proc_mod, HMODULE local_mod, const char *func_name) {
	void *addr = GetProcAddress(local_mod, func_name);
	if (!addr) {
		print_win_err(GetLastError(), "Failed to get local address of %s", func_name);
		return NULL;
	}
	return (uint8_t *)addr - (uint8_t *)local_mod + (uint8_t *)proc_mod;
}

// Print `a` as hex and highlight everything green except deltas from `b`.
void print_hex_delta(const uint8_t *a, const uint8_t *b, size_t size) {
	for (size_t i = 0; i < size; i++)
		if (a[i] == b[i]) printf("\e[0;32m""%.2x""\e[0m ", (int)a[i]);
		else printf("%.2x ", (int)a[i]);
	putchar('\n');
}

void *copy_to_proc_executable(HANDLE proc, void *data, size_t size) {
	void *proc_addr = VirtualAllocEx(proc, NULL, size, MEM_COMMIT, PAGE_READWRITE);
	if (proc_addr == NULL) {
		print_win_err(GetLastError(), "Failed to allocate memory in external process address space");
		return NULL;
	}

	if (!WriteProcessMemory(proc, proc_addr, data, size, NULL)) {
		print_win_err(GetLastError(), "Failed to write to external process address space");
		return NULL;
	}

	DWORD _old_prot;
	if (!VirtualProtectEx(proc, proc_addr, size, PAGE_EXECUTE, &_old_prot)) {
		print_win_err(GetLastError(), "Failed to make data in external process address space executable");
		return NULL;
	}
	return proc_addr;
}

#define MESSAGEBOXA_TRAMPOLINE_INSTRUCTIONS \
	0x48, 0x83, 0xEC, 0x38, \
	0x45, 0x33, 0xDB

#define MESSAGEBOXA_BODY \
	MESSAGEBOXA_TRAMPOLINE_INSTRUCTIONS, \
	0x44, 0x39, 0x1D, 0xE2, 0x3A, 0x04, 0x00, \
	0x74, 0x25, \
	0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, \
	0x4C, 0x8B, 0x50, 0x48, \
	0x33, 0xC0, \
	0xF0, 0x4C, 0x0F, 0xB1, 0x15, 0x88, 0x41, 0x04, 0x00, \
	0x75, 0x0B, \
	0x48, 0xC7, 0x05, 0x83, 0x41, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, \
	0x83, 0x4C, 0x24, 0x28, 0xFF, \
	0x66, 0x44, 0x89, 0x5C, 0x24, 0x20,  \
	0xE8, 0x0B, 0x01, 0x00, 0x00,  \
	0x48, 0x83, 0xC4, 0x38, \
	0xC3 // RET

BOOL apply_MessageBoxA_hook(HANDLE proc, HMODULE proc_mod, HMODULE local_mod) {
	uint8_t *proc_func = get_func_addr_in_proc(proc_mod, local_mod, "MessageBoxA");
	if (!proc_func) return FALSE;

	uint8_t local_func[] = { MESSAGEBOXA_BODY, 0,0,0,0, 0,0,0,0 };
	if (!ReadProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to read MessageBoxA in external process address space") && FALSE;

	const uint8_t tramp_inst[] = { MESSAGEBOXA_TRAMPOLINE_INSTRUCTIONS };
	size_t tramp_inst_sz = sizeof(tramp_inst);
	if (memcmp(local_func, tramp_inst, tramp_inst_sz) != 0) {
		puts("Unexpected data in MessageBoxA in external process address space (trampoline instructions):");
		print_hex_delta(local_func, tramp_inst, tramp_inst_sz);
		return FALSE;
	}
	uint8_t ret_byte = local_func[sizeof(local_func) - 9];
	if (ret_byte != 0xC3) {
		printf("Unexpected data in MessageBoxA in external process address space (return instruction): %.2x", ret_byte);
		return FALSE;
	}

	uint8_t local_hook[tramp_inst_sz + 6+8];
	memcpy(local_hook, tramp_inst, tramp_inst_sz);
	memcpy(local_hook+tramp_inst_sz, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	void *dest = proc_func + tramp_inst_sz;
	memcpy(local_hook+tramp_inst_sz+6, &dest, 8); // Pointer to remainder of function

	void *proc_hook = copy_to_proc_executable(proc, local_hook, sizeof(local_hook));
	if (proc_hook == NULL) return FALSE;

	memcpy(local_func, (uint8_t[2]){ 0XFF,0x25 }, 2); // JMP QWORD PTR [RIP + ...
	int32_t offset = sizeof((uint8_t[]){ MESSAGEBOXA_BODY }) - 6;
	memcpy(local_func+2, &offset, 4); // ... offset to address of hook]
	memcpy(local_func+sizeof((uint8_t[]){ MESSAGEBOXA_BODY }), &proc_hook, 8); // Address of hook

	if (!WriteProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to inject code into MessageBoxA in external process address space") && FALSE;
	return TRUE;
}

// FIXME: This just redirects to VirtualAllocEx in
// "api-ms-win-core-memory-11-1-0.dll". Ideally we would hook that function
// instead of this one, but I'm too lazy for that for now.
#define VIRTUALALLOCEX_BODY \
	0x48, 0xFF, 0x25, 0xB9, 0x82, 0x04, 0x00 // JMP QWORD PTR [RIP + 0x482B9]

// TODO: DRY.
BOOL apply_VirtualAllocEx_hook(HANDLE proc, HMODULE proc_mod, HMODULE local_mod) {
	uint8_t *proc_func = get_func_addr_in_proc(proc_mod, local_mod, "VirtualAllocEx");
	if (!proc_func) return FALSE;

	uint8_t local_func[] = {
		0,0,0,0,0,0, // Space for JMP
		0,0,0,0,0,0,0,0, // Space for address for JMP
		VIRTUALALLOCEX_BODY // Where the (modified) body will be moved
	};
	if (!ReadProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to read VirtualAllocEx in external process address space") && FALSE;

	const uint8_t body[] = { VIRTUALALLOCEX_BODY };
	size_t body_sz = sizeof(body);
	if (memcmp(local_func, body, body_sz) != 0) {
		puts("Unexpected data in VirtualAllocEx in external process address space:");
		print_hex_delta(local_func, body, body_sz);
		return FALSE;
	}

	uint8_t local_hook[6+8];
    /* CMP [RSP + 40], 0x40 */
    /* JNZ  */
	memcpy(local_hook, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	void *dest = proc_func + 6+8;
	memcpy(local_hook+6, &dest, 8); // Pointer to the (modified) body of the function
	
	void *proc_hook = copy_to_proc_executable(proc, local_hook, sizeof(local_hook));
	if (proc_hook == NULL) return FALSE;

	memcpy(local_func, (uint8_t[6]){ 0xFF,0x25,0x00,0x00,0x00,0x00 }, 6); // JMP QWORD PTR [RIP]
	memcpy(local_func+6, &proc_hook, 8); // Address of hook
	memcpy(local_func+6+8, (uint8_t[7]){ 0x48, 0xFF, 0x25, 0xB9 - 6 - 8, 0x82, 0x04, 0x00 }, 7); // JMP QWORD PTR [RIP + 0x482B9 - 6 - 8]
	
	if (!WriteProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to inject code into VirtualAllocEx in external process address space") && FALSE;
	return TRUE;
}

#define CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS \
    0x4C, 0x8B, 0xDC, \
    0x48, 0x83, 0xEC, 0x48, \
    0x44, 0x8B, 0x54, 0x24, 0x78, \
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00

// TODO: DRY.
BOOL apply_CreateRemoteThread_hook(HANDLE proc, HMODULE proc_mod, HMODULE local_mod) {
	uint8_t *proc_func = get_func_addr_in_proc(proc_mod, local_mod, "CreateRemoteThread");
	if (!proc_func) return FALSE;

	uint8_t local_func[] = { CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS };
	if (!ReadProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to read CreateRemoteThread in external process address space") && FALSE;

	const uint8_t trampoline[] = { CREATEREMOTETHREAD_TRAMPOLINE_INSTRUCTIONS };
	size_t trampoline_sz = sizeof(trampoline);
	if (memcmp(local_func, trampoline, trampoline_sz) != 0) {
		puts("Unexpected data in CreateRemoteThread in external process address space:");
		print_hex_delta(local_func, trampoline, trampoline_sz);
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
	
	if (!WriteProcessMemory(proc, proc_func, local_func, sizeof(local_func), NULL))
		return print_win_err(GetLastError(), "Failed to inject code into CreateRemoteThread in external process address space") && FALSE;
	return TRUE;
}

/// Returns TRUE if the executable file associated with `proc` is sussed.
/// Else, or if the function fails, returns FALSE.
/// `proc` must have been opened with `PROCESS_QUERY_INFORMATION` and
/// `PROCESS_VM_READ`.
BOOL proc_file_is_sussed(HANDLE proc) {
	char name[MAX_PATH];
	if (!GetModuleFileNameExA(proc, NULL, name, sizeof(name)))
		return print_win_err(GetLastError(), "Failed to get module file name") && FALSE;

	size_t name_len = strlen(name);
	size_t cmp_len = sizeof("messageboxer.exe") - 1;
	return name_len >= cmp_len && stricmp(name + name_len - cmp_len, "messageboxer.exe") == 0;
}

BOOL testfunc() {
	unsigned long pids_cb_alloc = 1028;
	unsigned long pids_cb;
	unsigned long *pids = malloc(pids_cb_alloc);
	do {
		if (!EnumProcesses(pids, pids_cb_alloc, &pids_cb)) {
			print_win_err(GetLastError(), "Failed to enumerate processes");
			return FALSE;
		}
	} while (pids_cb == pids_cb_alloc && (pids_cb_alloc *= 2) && (pids = realloc(pids, pids_cb_alloc)));

	for (unsigned long i = 0; i < pids_cb / sizeof(unsigned long); i++) {
		if (pids[i] == 0) continue; // System idle process can't be opened, and we don't care about it.

		HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pids[i]);
		if (proc == NULL) {
			print_win_err(GetLastError(), "Failed to open process (PID: %x)", pids[i]);
			continue;
		}

		// NOTE: hedda-defender is supposed to do api-injections on
		// every running process. This filter is just for testing so I
		// don't crash every process and fuck up my entire system if
		// the hook is bad.
		if (!proc_file_is_sussed(proc)) {
			CloseHandle(proc);
			continue;
		}
		////puts("\n\n");

		unsigned long mods_cb_alloc = 1028;
		unsigned long mods_cb;
		HMODULE *mods = malloc(mods_cb_alloc);
		do {
			if (!EnumProcessModules(proc, mods, mods_cb_alloc, &mods_cb)) {
				print_win_err(GetLastError(), "Failed to enumerate modules for process (PID: %x)", pids[i]);
				goto next_pid;
			}
		} while (mods_cb > mods_cb_alloc && (mods_cb_alloc = mods_cb) && (mods = realloc(mods, mods_cb_alloc)));

		for (unsigned long j = 0; j < mods_cb / sizeof(HMODULE); j++) {
			char name[MAX_PATH];
			if (!GetModuleFileNameEx(proc, mods[j], name, sizeof(name))) {
				////
				continue;
			}
			////size_t name_len = strlen(name);
			////size_t cmp_len = sizeof("user32.dll") - 1;
			////if (name_len >= cmp_len && stricmp(name + name_len - cmp_len, "user32.dll") == 0) {
			////	HMODULE local_mod = LoadLibrary("user32.dll");
			////	if (local_mod == NULL) {
			////		////
			////		continue;
			////	}
			////	puts("Applying MessageBoxA hook.");
			////	printf("result: %d\n", apply_MessageBoxA_hook(proc, mods[j], local_mod));
			////	FreeLibrary(local_mod);
			////}
			size_t name_len = strlen(name);
			size_t cmp_len = sizeof("kernel32.dll") - 1;
			if (name_len >= cmp_len && stricmp(name + name_len - cmp_len, "kernel32.dll") == 0) {
				HMODULE local_mod = LoadLibrary("kernel32.dll");
				if (local_mod == NULL) {
					////
					continue;
				}
				puts("Applying VirtualAllocEx hook.");
				printf("result: %d\n", apply_VirtualAllocEx_hook(proc, mods[j], local_mod));
				FreeLibrary(local_mod);
			}
			////puts(name);
		}

	next_pid:
		free(mods);
		CloseHandle(proc);
	}
	free(pids);
	return TRUE;
}

int main() {
	return !testfunc();
}
