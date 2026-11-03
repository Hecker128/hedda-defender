#include "util.h"
#include "scanner.h"
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <msi.h>
#include <winnt.h>
#include <wincrypt.h>

#ifdef USE_YARA
# include "yara-integration.h"

// YARA rules for scan thread.
// Set by `init_scanner`.
static YR_RULES *yara_rules;
#endif

// Logging enabled for scan thread.
// Set by `init_scanner`.
static BOOL logging_enabled;

/// Creates a read-only mapping for the file specified by `path` to `*data`.
/// `*file` receives the file handle created from opening `path`.
/// `*mapping` receives the file mapping object created for this mapping.
/// `*len` receives the length of the mapping, which is the size of the file.
/// Returns `FALSE` on failure.
static BOOL map_file(const uint8_t **data, int64_t *len, HANDLE *mapping, HANDLE *file, const char *path) {
	*file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (*file == INVALID_HANDLE_VALUE) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to open file \"%s\" for mapping", path);
		return FALSE;
	}

	*mapping = CreateFileMapping(*file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (*mapping == NULL) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to create file mapping for \"%s\"", path);
		CloseHandle(file);
		return FALSE;
	}

	*data = MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
	if (*data == NULL) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get view of file mapping for \"%s\"", path);
		CloseHandle(mapping);
		CloseHandle(file);
		return FALSE;
	}

	if (!GetFileSizeEx(*file, (PLARGE_INTEGER)len)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get size of file \"%s\" for file mapping", path);
		UnmapViewOfFile(data);
		CloseHandle(mapping);
		CloseHandle(file);
		return FALSE;
	}
	return TRUE;
}

/// Cleanup for resources received from `map_file`.
static void unmap_file(const uint8_t *data, HANDLE mapping, HANDLE file) {
	UnmapViewOfFile(data);
	CloseHandle(mapping);
	CloseHandle(file);
}

/// Hashes `data` of length `len` to a (32-byte) SHA-256 hash returned in
/// `*hash` using `prov`.
/// Returns FALSE on failure.
static BOOL sha256_hash(uint8_t *hash, const uint8_t *data, DWORD len, HCRYPTPROV prov) {
	HCRYPTHASH crypthash;
	if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &crypthash)) return FALSE;

	if (!CryptHashData(crypthash, data, len, 0)) {
		CryptDestroyHash(crypthash);
		return FALSE;
	}

	DWORD hash_len = 32;
	BOOL ret = CryptGetHashParam(crypthash, HP_HASHVAL, hash, &hash_len, 0);

	CryptDestroyHash(crypthash);
	return ret;
}

static BOOL sha256_hash_file(uint8_t *hash, const char *path, HCRYPTPROV prov) {
	const uint8_t *data;
	int64_t len;
	HANDLE mapping;
	HANDLE file;
	if (!map_file(&data, &len, &mapping, &file, path)) return FALSE;

	BOOL success = sha256_hash(hash, data, len, prov);
	unmap_file(data, mapping, file);

	return success;
}

/// Looks for byte sequence `seq` with length `seq_len` in `data` with length `len`.
/// Returns `TRUE` if found.
static BOOL data_has_seq(const uint8_t *data, size_t len, const uint8_t *seq, size_t seq_len) {
	if (seq_len > len) return FALSE;
	const uint8_t *end = data + len - seq_len;
	do {
		int cmp = memcmp(data, seq, seq_len);
		if (cmp == 0) return TRUE;
		data += abs(cmp);
	} while (data < end);
	return FALSE;
}

static double data_get_entropy(const uint8_t *data, size_t len) {
	size_t cnt[256];
	memset(cnt, 0, 256 * sizeof(size_t));
	for (size_t i = 0; i < len; cnt[data[i++]] += 1);

	double sum = 0;
	for (int i = 0; i < 256; i++) {
		double p = (double)cnt[i] / (double)len;
		sum += p * (p == 0 ? 0 : log2(p));
	}

	return -sum;
}

/// rva:           The RVA to get the file offset of.
/// section_heads: Array of headers of sections to search in.
/// n_sections:    Number of sections in section_heads.
/// Returns the file offset of rva if it's within one of the sections' bounds.
/// Returns 0 on failure.
static uint64_t rva_get_file_offset(uint32_t rva, const PIMAGE_SECTION_HEADER section_heads, uint16_t n_sections) {
	for (uint16_t i = 0; i < n_sections; i++) {
		const uint32_t start = section_heads[i].VirtualAddress;
		const uint32_t end = start + section_heads[i].SizeOfRawData;
		if (rva >= start && rva < end)
			return rva - start + section_heads[i].PointerToRawData;
	}
	return 0;
}

/// Returns TRUE if the file specified by `path` has a valid certificate and
/// Microsoft is the root signer. (It's supposed to anyway, I'm not good with
/// certificates and stuff.)
/// TODO: Confirm that this fails when a file with an invalid signature (e.g.
/// with a hash mismatch) is passed.
static BOOL valid_microsoft_root_cert(const char *path) {
	PCCERT_CONTEXT cert;
	if (MsiGetFileSignatureInformation(path, 0, &cert, NULL, NULL) != S_OK) return FALSE;

	PCCERT_CHAIN_CONTEXT chain;
	CERT_CHAIN_POLICY_STATUS status;
	if (!CertGetCertificateChain(
		NULL,
		cert,
		NULL,
		cert->hCertStore,
		&(CERT_CHAIN_PARA) {
			.cbSize = sizeof(CERT_CHAIN_PARA)
		},
		0,
		NULL,
		&chain
	)) {
		CertFreeCertificateContext(cert);
		return FALSE;
	}

	BOOL call_success = CertVerifyCertificateChainPolicy(
		CERT_CHAIN_POLICY_MICROSOFT_ROOT,
		chain,
		&(CERT_CHAIN_POLICY_PARA) {
			.cbSize = sizeof(CERT_CHAIN_POLICY_PARA)
		},
		&status
	);

	CertFreeCertificateChain(chain);
	CertFreeCertificateContext(cert);
	return call_success && status.dwError == S_OK;
}

// TODO: VirtualAllocEx (and maybe others) stems from a different DLL. Detect it as an import from that DLL instead of kernel32.
enum {
	KERNEL32_SUSSYBAKAS_IDX_CreateRemoteThread = 0,
	KERNEL32_SUSSYBAKAS_IDX_CreateRemoteThreadEx,
	KERNEL32_SUSSYBAKAS_IDX_VirtualAllocEx,
	KERNEL32_SUSSYBAKAS_MAX
};
static const char *kernel32_sus_names[] = {
	"CreateRemoteThread",
	"CreateRemoteThreadEx",
	"VirtualAllocEx",
};

/// Helper function for `get_kernel32_ordinals`.
static BOOL get_kernel32_ordinals_inner(uint16_t *ordinals, const uint8_t *data) {
	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;

	// NOTE: At this point we don't know if it's 32-bit or 64-bit yet.
	const PIMAGE_NT_HEADERS32 nt_heads32 = (PIMAGE_NT_HEADERS32)(data + dos_header->e_lfanew);
	uint16_t n_sections = nt_heads32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER section_heads;
	PIMAGE_DATA_DIRECTORY data_dirs;
	if (nt_heads32->OptionalHeader.Magic == 0x10B) { // PE32
		section_heads = (PIMAGE_SECTION_HEADER)(nt_heads32 + 1);
		data_dirs = nt_heads32->OptionalHeader.DataDirectory;
	} else { // PE32+
		const PIMAGE_NT_HEADERS64 nt_heads64 = (PIMAGE_NT_HEADERS64)nt_heads32;
		section_heads = (PIMAGE_SECTION_HEADER)(nt_heads64 + 1);
		data_dirs = nt_heads64->OptionalHeader.DataDirectory;
	}

	const PIMAGE_DATA_DIRECTORY export_dir = &data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
	const PIMAGE_EXPORT_DIRECTORY exports =
		(PIMAGE_EXPORT_DIRECTORY)(data + rva_get_file_offset(export_dir->VirtualAddress, section_heads, n_sections));
	uint32_t n_names = exports->NumberOfNames;
	const uint32_t *names = (uint32_t *)(data + rva_get_file_offset(exports->AddressOfNames, section_heads, n_sections));
	const uint16_t *pe_ordinals = (uint16_t *)(data + rva_get_file_offset(exports->AddressOfNameOrdinals, section_heads, n_sections));

	uint8_t ordinal_found_tab[KERNEL32_SUSSYBAKAS_MAX];
	for (uint32_t i = 0; i < n_names; i++) {
		const char *name = (char *)(data + rva_get_file_offset(names[i], section_heads, n_sections));
		for (int j = 0; j < KERNEL32_SUSSYBAKAS_MAX; j++)
			if (!ordinal_found_tab[j] && strcmp(name, kernel32_sus_names[j]) == 0) {
				ordinals[j] = pe_ordinals[i];
				ordinal_found_tab[j] = 1;
				break;
			}
	}
	for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; i++)
		if (ordinal_found_tab[i] == 0) return FALSE;
	return TRUE;
}

/// Get numbers that programs use for by-ordinal imports from KERNEL32.DLL (to
/// be able to check executables for suspicious imports).
/// ordinals: Pointer (of length `KERNEL32_SUSSYBAKAS_MAX`) to where to put the ordinal numbers.
/// Returns `TRUE` if successful.
static BOOL get_kernel32_ordinals(uint16_t *ordinals) {
	const char path[] = "C:\\Windows\\System32\\KERNEL32.DLL";	
	if (!valid_microsoft_root_cert(path)) return FALSE;

	const uint8_t *data;
	int64_t len;
	HANDLE mapping;
	HANDLE file;
	if (!map_file(&data, &len, &mapping, &file, path)) return FALSE;

	BOOL ret = get_kernel32_ordinals_inner(ordinals, data);

	unmap_file(data, mapping, file);
	return ret;
}

/// Helper function for `pe_is_sus`.
/// TODO: Also check imports from imported DLLs.
static BOOL imports_are_sus(
	const uint8_t *data,
	uint64_t len,
	const PIMAGE_NT_HEADERS32 nt_heads32,
	const PIMAGE_DATA_DIRECTORY import_dir,
	const PIMAGE_SECTION_HEADER section_heads,
	uint16_t n_sections,
	const uint16_t *kernel32_ordinals
) {
	uint64_t import_off = rva_get_file_offset(import_dir->VirtualAddress, section_heads, n_sections);
	if (len - import_off < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return FALSE;
	if (import_off == 0) return FALSE;
	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(data + import_off);
	do {
		uint64_t lib_name_off = rva_get_file_offset(import->Name, section_heads, n_sections);
		if (len < lib_name_off) continue;
		const char *lib_name = (char *)(data + lib_name_off);

		if (_strnicmp(lib_name, "KERNEL32.DLL", len - lib_name_off) != 0) continue;

		uint64_t ilt_off = rva_get_file_offset(import->OriginalFirstThunk, section_heads, n_sections);
		if (len < ilt_off) continue;
		if (ilt_off == 0) continue;
		const uint32_t *p_ilt_entry32 = (uint32_t *)(data + ilt_off);
		for (;;) {
			if ((uint8_t *)p_ilt_entry32 - data < 4) break;
			uint32_t ilt_entry32 = *p_ilt_entry32;
			BOOL is_ordinal;
			if (nt_heads32->OptionalHeader.Magic == 0x10B) { // PE32
				if (ilt_entry32 == 0) break;
				is_ordinal = (ilt_entry32 & 1 << 31) != 0;
				p_ilt_entry32 += 1;
			} else { // PE32+
				if ((uint8_t *)p_ilt_entry32 - data < 8) break;
				uint64_t ilt_entry64 = *(uint64_t *)p_ilt_entry32;
				if (ilt_entry64 == 0) break;
				is_ordinal = (ilt_entry64 & 1ULL << 63) != 0;
				p_ilt_entry32 += 2;
			}

			if (is_ordinal) {
				uint16_t ordinal = ilt_entry32 & 0xffff;
				LOG_PRINTF("Import by ordinal: 0x%hx.\n", ordinal);

				for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; i++)
					if (ordinal == kernel32_ordinals[i]) {
						LOG_PUTS("Suspicious by-ordinal import found!");
						return TRUE;
					}
			} else {
				uint64_t by_name_off = rva_get_file_offset(ilt_entry32, section_heads, n_sections);
				uint64_t by_name_name_off = by_name_off + sizeof(IMAGE_IMPORT_BY_NAME) - 1;
				if (len - by_name_off < sizeof(IMAGE_IMPORT_BY_NAME)) continue;
				if (by_name_off == 0) continue;
				const PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(data + by_name_off);
				LOG_PRINTF("Import by name: Hint: 0x%hx, Name: %.*s\n", by_name->Hint, (int)(len - by_name_name_off), by_name->Name);

				for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; i++)
					if (strncmp(by_name->Name, kernel32_sus_names[i], len - by_name_name_off) == 0) {
						LOG_PUTS("Suspicious by-name import found!");
						return TRUE;
					}
			}
		}
		import_off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		if (len - import_off < sizeof(IMAGE_IMPORT_DESCRIPTOR)) break;
	} while ((++import)->Name);

	return FALSE;
}

/// Statically determines whether a PE file is suspicious.
/// It's valid to pass data that isn't a (valid) PE file. Bounds checking is
/// done with respect to `len` (i.e. no addresses in the file are blindly
/// trusted to be in bounds).
/// If the PE file is invalid such that the PE loader should fail to load it
/// (e.g. if it's not actually a PE file), it isn't seen dangerous (i.e. isn't
/// flagged as suspicious).
static BOOL pe_is_sus(const uint8_t *data, uint64_t len, const uint16_t *kernel32_ordinals) {
	if (len < sizeof(IMAGE_DOS_HEADER)) {
		LOG_PUTS("Not an MZ file (with PE Extension): Not big enough for IMAGE_DOS_HEADER.");
		return FALSE;
	}
	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != 0x5A4D) {
		LOG_PUTS("Not an MZ file: Wrong e_magic.");
		return FALSE;
	}

	// NOTE: At this point we don't know if it's 32-bit or 64-bit yet.
	// Before we do, we'll only use the common fields.
	if (len - dos_header->e_lfanew < sizeof(IMAGE_NT_HEADERS32)) {
		LOG_PUTS("Not a PE file: IMAGE_NT_HEADERS32 doesn't fit.");
		return FALSE;
	}
	const PIMAGE_NT_HEADERS32 nt_heads32 = (PIMAGE_NT_HEADERS32)(data + dos_header->e_lfanew);
	if (nt_heads32->Signature != 0x4550) {
		LOG_PRINTF("Not a PE file: Wrong NT headers signature (0x%lx).\n", nt_heads32->Signature);
		return FALSE;
	}
	uint16_t n_sections = nt_heads32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER section_heads;
	PIMAGE_DATA_DIRECTORY data_dirs;
	switch (nt_heads32->OptionalHeader.Magic) {
	case 0x10B: { // PE32
		section_heads = (PIMAGE_SECTION_HEADER)(nt_heads32 + 1);
		data_dirs = nt_heads32->OptionalHeader.DataDirectory;
		break;
	} case 0x20B: { // PE32+
		const PIMAGE_NT_HEADERS64 nt_heads64 = (PIMAGE_NT_HEADERS64)nt_heads32;
		section_heads = (PIMAGE_SECTION_HEADER)(nt_heads64 + 1);
		data_dirs = nt_heads64->OptionalHeader.DataDirectory;
		break;
	} default: {
		LOG_PUTS("Not a PE file for Windows.");
		return FALSE;
	}}

	const PIMAGE_DATA_DIRECTORY import_dir = &data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_dir->Size != 0 && imports_are_sus(data, len, nt_heads32, import_dir, section_heads, n_sections, kernel32_ordinals))
		return TRUE;

	for (uint16_t i = 0; i < n_sections; i++) {
		if (len - section_heads[i].PointerToRawData < section_heads[i].SizeOfRawData) continue;
		if (data_get_entropy(data + section_heads[i].PointerToRawData, section_heads[i].SizeOfRawData) > 7) {
			LOG_PUTS("Section has suspiciously high entropy!");
			return TRUE;
		}
	}

	return FALSE;
}

typedef struct {
	char *path;
	HANDLE find;
	WIN32_FIND_DATA data;
} FindInfo;

HANDLE scan_result_mutex = NULL;
ScanResult scan_result = {0};

/// Acquires `scan_result_mutex`, letting the calling thread use `scan_result`
/// with other threads running. Always (unless this function fails) call
/// `release_scan_result` soon after because sharing is caring <3
/// Returns `NULL` on failure.
ScanResult *acquire_scan_result() {
	BOOL result = WaitForSingleObject(scan_result_mutex, INFINITE);
	if (result == WAIT_ABANDONED) {
		LOG_PUTS("Scan result mutex was abandoned (this should NOT happen).");
	} else if (result != WAIT_OBJECT_0) {
		LOG_PRINTF("Wait for scan result mutex failed. Result: 0x%X.", result);
		return NULL;
	}
	return &scan_result;
}

/// Releases `scan_result_mutex`.
/// Returns `FALSE` on failure.
BOOL release_scan_result() {
	if (!ReleaseMutex(scan_result_mutex)) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to release scan result");
		return FALSE;
	}
	return TRUE;
}

/// To be called by the main thread once, before creating the scan thread or
/// using `scan_result`.
BOOL init_scanner(
	BOOL logging_enabled_
#ifdef USE_YARA
	, YR_RULES *yara_rules_
#endif
) {
	logging_enabled = logging_enabled_;
#ifdef USE_YARA
	yara_rules = yara_rules_;
#endif
	scan_result_mutex = CreateMutex(NULL, FALSE, NULL);
	if (scan_result_mutex == NULL) {
		print_win_err(GetLastError(), "Failed to create mutex for scan result");
		return FALSE;
	}
	scan_result.malicious_infos = malloc(sizeof(FileInfo));
	return TRUE;
}

/// Helper for `scan_find_info_or_count_file`.
/// `scan_result_mutex` must be aquired by caller when calling this.
static void scan_file(const char *path, const uint16_t *kernel32_ordinals, HCRYPTPROV prov) {
	scan_result.n_scanned += 1;
#ifdef USE_YARA
	BOOL yara_matched;
	if (yara_scan_file(yara_rules, path, &yara_matched, logging_enabled) && yara_matched) {
		LOG_PRINTF("\"%s\" is a malicious file (YARA matched).\n", path);
		FileInfo info;

		size_t path_sz = strlen(path) + 1;
		info.path = malloc(path_sz);
		memcpy(info.path, path, path_sz);

		if (!sha256_hash_file(info.hash, path, prov)) {
			// This error handling behaviour is kinda dumb but I
			// don't see any reason why it would suddenly fail to
			// hash anyway.
			// In the worst case scenario though, at least flagging
			// it as suspicious is better than nothing.
			LOG_PUTS("Failed to hash malicious file. Flagging as suspicious.");
			free(info.path);
			scan_result.n_sus += 1;
			return;
		}

		scan_result.n_malicious += 1;
		scan_result.malicious_infos = realloc(scan_result.malicious_infos, sizeof(FileInfo) * scan_result.n_malicious);
		scan_result.malicious_infos[scan_result.n_malicious - 1] = info;
		return;
	}
#endif
	const uint8_t *data;
	int64_t len;
	HANDLE mapping;
	HANDLE file;
	if (!map_file(&data, &len, &mapping, &file, path)) {
		scan_result.n_sus += 1;
		return;
	}
	if (pe_is_sus(data, len, kernel32_ordinals))
		scan_result.n_sus += 1;
	unmap_file(data, mapping, file);

	return;
}

/// Helper for `scan_thread_routine`.
/// Returns `FALSE` on failure.
static BOOL scan_find_info_or_count_file(FindInfo *find, const uint16_t *kernel32_ordinals, HCRYPTPROV prov) {
	size_t path_len = strlen(find->path);

	// "path/*" => "path/file"
	// "path"   => "path" (= "file")
	BOOL path_has_wild;
	if (find->path[path_len - 1] == '*') {
		path_has_wild = TRUE;
		size_t file_name_len = strlen(find->data.cFileName);
		find->path = realloc(find->path, path_len + file_name_len);
		memcpy(find->path + path_len - 1, find->data.cFileName, file_name_len);
		find->path[path_len + file_name_len - 1] = 0;
	} else
		path_has_wild = FALSE;

	if (acquire_scan_result() == NULL) return FALSE;

	if (scan_result.is_counting_files)
		scan_result.n_total += 1;
	else
		scan_file(find->path, kernel32_ordinals, prov);

	if (!release_scan_result()) return FALSE;

	// "path" => "path/*"
	// "file" => "file"
	if (path_has_wild) {
		find->path[path_len - 1] = '*';
		find->path[path_len] = 0;
	}

	return TRUE;
}

/// Helper for `scan_thread_routine`.
/// Returns `FALSE` on failure.
static BOOL find_first_file_to_find_stack(FindInfo *find_stack, const char *path) {
	size_t path_len = strlen(path);
	if (path_len == 0) {
		LOG_PUTS("Length of file path shouldn't be 0.");
		return FALSE;
	}

	if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
		// "."  => "./*".
		// ".." => "../*".
		find_stack[0].path = malloc(path_len + sizeof("/*"));
		memcpy(find_stack[0].path, path, path_len);
		memcpy(find_stack[0].path + path_len, "/*", 3);
	} else {
		find_stack[0].path = malloc(path_len + 1);
		memcpy(find_stack[0].path, path, path_len + 1);
	}

	find_stack[0].find = FindFirstFile(find_stack[0].path, &find_stack[0].data);
	if (find_stack[0].find == INVALID_HANDLE_VALUE) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to find file (in %s)", find_stack[0].path);
		free(find_stack[0].path);
		return FALSE;
	}

	return TRUE;
}

/// Helper for `scan_thread_routine`.
/// `dir_name` is the name of the directory to enter (final part of its path).
/// The path is derived from it and the current index in `find_stack`.
static void find_stack_push_dir(FindInfo **find_stack, int *ext_depth, const char *dir_name) {
	const char *prev_path = (*find_stack)[*ext_depth].path;
	size_t prev_path_len = strlen(prev_path);
	char *new_path;

	// prev_path == "path/*" => new_path == "path/dir/*".
	// prev_path == "path"   => new_path == "path/*" (== "dir/*").
	if (prev_path[prev_path_len - 1] == '*') {
		size_t dir_name_len = strlen(dir_name);
		new_path = malloc(prev_path_len + dir_name_len + sizeof("/"));
		memcpy(new_path, prev_path, prev_path_len);
		memcpy(new_path + prev_path_len - 1, dir_name, dir_name_len);
		memcpy(new_path + prev_path_len - 1 + dir_name_len, "/*", 3);
	} else {
		new_path = malloc(prev_path_len + 3);
		memcpy(new_path, prev_path, prev_path_len);
		memcpy(new_path + prev_path_len, "/*", 3);
	}

	*ext_depth += 1;
	*find_stack = realloc(*find_stack, sizeof(FindInfo) * (1 + *ext_depth));
	(*find_stack)[*ext_depth].path = new_path;
}

static DWORD WINAPI scan_thread_routine(LPVOID lpParam) {
	HCRYPTPROV prov;
	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 1;

	uint16_t kernel32_ordinals[KERNEL32_SUSSYBAKAS_MAX];
	if (!get_kernel32_ordinals(kernel32_ordinals)) {
		CryptReleaseContext(prov, 0);
		return 1;
	}

	FindInfo *find_stack = malloc(sizeof(FindInfo));

	find_files:
	if (!find_first_file_to_find_stack(find_stack, lpParam)) {
		free(find_stack);
		CryptReleaseContext(prov, 0);
		return 1;
	}
	int ext_depth = 0;
	for (;;) {
		check_first_find:
		do {
			if (find_stack[ext_depth].data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				const char *dir_name = find_stack[ext_depth].data.cFileName;
				if (strcmp(dir_name, ".") == 0 || strcmp(dir_name, "..") == 0) continue;
				if (find_stack[ext_depth].data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
						&& find_stack[ext_depth].data.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT) continue;

				find_stack_push_dir(&find_stack, &ext_depth, dir_name);

				find_stack[ext_depth].find = FindFirstFile(find_stack[ext_depth].path, &find_stack[ext_depth].data);
				if (find_stack[ext_depth].find == INVALID_HANDLE_VALUE) {
					uint32_t err = GetLastError();
					if (err == ERROR_ACCESS_DENIED) {
						LOG_PRINTF("Skipping file(s) \"%s\" because access was denied.\n", find_stack[ext_depth].path);
						break;
					} else {
						LOG_PRINT_WIN_ERR(err, "Failed to find file (in %s)", find_stack[ext_depth].path);
						break;
					}
				}
				// Using continue here would call FindNextFile,
				// ignoring the file found with FindFirstFile.
				goto check_first_find;
			} else {
				scan_find_info_or_count_file(&find_stack[ext_depth], kernel32_ordinals, prov);
			}
		} while (FindNextFile(find_stack[ext_depth].find, &find_stack[ext_depth].data));
		
		dec_depth:
		free(find_stack[ext_depth].path);
		if (ext_depth-- <= 0) break;
		if (!FindNextFile(find_stack[ext_depth].find, &find_stack[ext_depth].data)) goto dec_depth;
	}

	if (acquire_scan_result() == NULL) {
		free(find_stack);
		CryptReleaseContext(prov, 0);
		return 1;
	}

	BOOL was_counting_files = scan_result.is_counting_files;
	if (was_counting_files)
		scan_result.is_counting_files = FALSE;
	else
		scan_result.is_scanning = FALSE;

	if (!release_scan_result()) {
		free(find_stack);
		CryptReleaseContext(prov, 0);
		return 1;
	}

	if (was_counting_files) goto find_files;

	LOG_PUTS("Scanned successfully");
	free(find_stack);
	CryptReleaseContext(prov, 0);
	return 0;
}

/// Returns the handle to the created thread, which should be passed to
/// `CloseHandle` after `scan_result.is_scanning` goes from `TRUE` to `FALSE`.
/// Returns `NULL` on failure.
/// Do NOT call this from threads other than the main thread, and never run
/// multiple scan threads at once.
HANDLE create_scan_thread(char *path) {
	scan_result.n_total = 0;
	scan_result.n_scanned = 0;
	scan_result.n_sus = 0;
	scan_result.is_scanning = TRUE;
	scan_result.is_counting_files = TRUE;

	DWORD _tid;
	return CreateThread(NULL, 0, scan_thread_routine, path, 0, &_tid);
}
