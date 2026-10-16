#include <math.h>
#include <stdint.h>
#include <stdio.h>

#include <windows.h>
#include <msi.h>
#include <winnt.h>
#include <wincrypt.h>


/// data:    Pointer to where to put the data pointer.
/// len:     Pointer to where to put the data length.
/// mapping: Pointer to where to put the mapping handle.
/// file:    Pointer to where to put the file handle.
/// path:    File path.
BOOL map_file(const uint8_t **data, int64_t *len, HANDLE *mapping, HANDLE *file, const char *path) {
	*file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (*file == INVALID_HANDLE_VALUE) return FALSE;

	*mapping = CreateFileMapping(*file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (*mapping == NULL) return FALSE;

	*data = MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
	if (*data == NULL) return FALSE;

	if (!GetFileSizeEx(*file, (PLARGE_INTEGER)len)) return FALSE;
	return TRUE;
}

/// Cleanup for stuff from map_file.
void unmap_file(const uint8_t *data, HANDLE mapping, HANDLE file) {
	UnmapViewOfFile(data);
	CloseHandle(mapping);
	CloseHandle(file);
}

/// hash: Pointer to where to put the (32-byte) SHA-256 hash.
/// data: Data to hash.
/// len:  Length of data.
/// Returns TRUE if successful.
/// NOTE: Leaks memory on failure.
BOOL sha256_hash(uint8_t *hash, const uint8_t *data, DWORD len) {
	HCRYPTPROV hp;
	HCRYPTHASH hh;
	if (!CryptAcquireContext(&hp, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
	if (!CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) return FALSE;

	if (!CryptHashData(hh, data, len, 0)) return FALSE;

	DWORD hash_len = 32;
	if (!CryptGetHashParam(hh, HP_HASHVAL, hash, &hash_len, 0)) return FALSE;

	CryptDestroyHash(hh);
	CryptReleaseContext(hp, 0);
	return TRUE;
}

/// Compares (32-byte) SHA-256 hashes a and b.
/// Returns TRUE if equal.
BOOL sha256_compare(const uint8_t *a, const uint8_t *b) {
	const uint64_t *a64 = (uint64_t *)a;
	const uint64_t *b64 = (uint64_t *)b;
	return a64[0]==b64[0] && a64[1]==b64[1] && a64[2]==b64[2] && a64[3]==b64[3];
}

/// Looks for byte sequence `seq` with length `seq_len` in `data` with length `len`.
/// Returns TRUE if found.
BOOL data_has_seq(const uint8_t *data, size_t len, const uint8_t *seq, size_t seq_len) {
	if (seq_len > len) return FALSE;
	const uint8_t *end = data + len - seq_len;
	do {
		int cmp = memcmp(data, seq, seq_len);
		if (cmp == 0) return TRUE;
		data += abs(cmp);
	} while (data < end);
	return FALSE;
}

double data_get_entropy(const uint8_t *data, size_t len) {
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
uint64_t rva_get_file_offset(uint32_t rva, const PIMAGE_SECTION_HEADER section_heads, uint16_t n_sections) {
	for (uint16_t i = 0; i < n_sections; i++) {
		const uint32_t start = section_heads[i].VirtualAddress;
		const uint32_t end = start + section_heads[i].SizeOfRawData;
		if (rva >= start && rva < end)
			return rva - start + section_heads[i].PointerToRawData;
	}
	return 0;
}

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

// Helper function for get_kernel32_ordinals.
BOOL get_kernel32_ordinals_inner(uint16_t *ordinals, const uint8_t *data) {
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
/// ordinals: Pointer (of length KERNEL32_SUSSYBAKAS_MAX) to where to put the ordinal numbers.
/// Returns TRUE if successful.
BOOL get_kernel32_ordinals(uint16_t *ordinals) {
	const char path[] = "C:\\Windows\\System32\\KERNEL32.DLL";
	const uint8_t *data;
	int64_t len;
	HANDLE mapping;
	HANDLE file;
	if (!map_file(&data, &len, &mapping, &file, path)) return FALSE;

	BOOL ret = get_kernel32_ordinals_inner(ordinals, data);

	unmap_file(data, mapping, file);
	return ret;
}

/// Helper function for pe_is_sus.
BOOL imports_are_sus(
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

		if (strnicmp(lib_name, "KERNEL32.DLL", len - lib_name_off) != 0) continue;

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
				printf("Import by ordinal: 0x%hx.\n", ordinal);

				for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; i++)
					if (ordinal == kernel32_ordinals[i]) {
						puts("Suspicious by-ordinal import found!");
						return TRUE;
					}
			} else {
				uint64_t by_name_off = rva_get_file_offset(ilt_entry32, section_heads, n_sections);
				uint64_t by_name_name_off = by_name_off + sizeof(IMAGE_IMPORT_BY_NAME) - 1;
				if (len - by_name_off < sizeof(IMAGE_IMPORT_BY_NAME)) continue;
				if (by_name_off == 0) continue;
				const PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(data + by_name_off);
				printf("Import by name: Hint: 0x%hx, Name: %.*s\n", by_name->Hint, (int)(len - by_name_name_off), by_name->Name);

				for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; i++)
					if (strncmp(by_name->Name, kernel32_sus_names[i], len - by_name_name_off) == 0) {
						puts("Suspicious by-name import found!");
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
BOOL pe_is_sus(const uint8_t *data, uint64_t len, const uint16_t *kernel32_ordinals) {
	if (len < sizeof(IMAGE_DOS_HEADER)) {
		puts("Not an MZ file (with PE Extension): Not big enough for IMAGE_DOS_HEADER.");
		return FALSE;
	}
	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != 0x5A4D) {
		puts("Not an MZ file: Wrong e_magic.");
		return FALSE;
	}

	// NOTE: At this point we don't know if it's 32-bit or 64-bit yet.
	// Before we do, we'll only use the common fields.
	if (len - dos_header->e_lfanew < sizeof(IMAGE_NT_HEADERS32)) {
		puts("Not a PE file: IMAGE_NT_HEADERS32 doesn't fit.");
		return FALSE;
	}
	const PIMAGE_NT_HEADERS32 nt_heads32 = (PIMAGE_NT_HEADERS32)(data + dos_header->e_lfanew);
	if (nt_heads32->Signature != 0x4550) {
		printf("Not a PE file: Wrong NT headers signature (0x%lx).\n", nt_heads32->Signature);
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
		puts("Not a PE file for Windows.");
		return FALSE;
	}}

	const PIMAGE_DATA_DIRECTORY import_dir = &data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_dir->Size != 0 && imports_are_sus(data, len, nt_heads32, import_dir, section_heads, n_sections, kernel32_ordinals))
		return TRUE;

	for (uint16_t i = 0; i < n_sections; i++) {
		if (len - section_heads[i].PointerToRawData < section_heads[i].SizeOfRawData) continue;
		if (data_get_entropy(data + section_heads[i].PointerToRawData, section_heads[i].SizeOfRawData) > 7) {
			puts("Section has suspiciously high entropy!");
			return TRUE;
		}
	}

	return FALSE;
}

BOOL file_is_sus(const char *path, const uint16_t *kernel32_ordinals) {
	const uint8_t *data;
	int64_t len;
	HANDLE mapping;
	HANDLE file;
	if (!map_file(&data, &len, &mapping, &file, path)) {
		puts("Failed to map file (suspicious)!");
		return TRUE;
	}

	uint8_t hash[32];
	if (!sha256_hash(hash, data, len)) {
		puts("Failed to hash file (suspicious)!");
		unmap_file(data, mapping, file);
		return TRUE;
	}
	printf("SHA-256 hash: ");
	for (int i = 0; i < 32; printf("%.2x", hash[i++]));
	putchar('\n');

	if (pe_is_sus(data, len, kernel32_ordinals)) {
		puts("File is suspicious.");
		unmap_file(data, mapping, file);
		return TRUE;
	}

	unmap_file(data, mapping, file);
	return FALSE;
}

uint32_t print_win_err(uint32_t err, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	const char *msg;
	uint32_t flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
	if (FormatMessage(flags, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char *)&msg, 0, NULL))
		printf(". Error code: 0x%x, %s", err, msg);	
	else
		printf(". Error code: 0x%x.\n", err);
	return err;
}

typedef struct {
	char *path;
	HANDLE find;
	WIN32_FIND_DATA data;
} FindInfo;

int main(int argc, char **argv) {
	uint16_t kernel32_ordinals[KERNEL32_SUSSYBAKAS_MAX];
	if (!get_kernel32_ordinals(kernel32_ordinals)) return 2;

	uint64_t n_scanned = 0;
	uint64_t n_sus = 0;

	if (argc != 2) return 1;
	FindInfo *find_stack = malloc(sizeof(FindInfo));
	size_t path_len = strlen(argv[1]);
	if (path_len == 0) return 1;
	if (strcmp(argv[1], ".") == 0 || strcmp(argv[1], "..") == 0) {
		// "."  => "./*".
		// ".." => "../*".
		find_stack[0].path = malloc(path_len + sizeof("/*"));
		memcpy(find_stack[0].path, argv[1], path_len);
		memcpy(find_stack[0].path + path_len, "/*", 3);
	} else {
		find_stack[0].path = malloc(path_len + 1);
		memcpy(find_stack[0].path, argv[1], path_len + 1);
	}
	find_stack[0].find = FindFirstFile(find_stack[0].path, &find_stack[0].data);
	if (find_stack[0].find == INVALID_HANDLE_VALUE) {
		uint32_t err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) {
			puts("Not scanning any files because access was denied.");
			goto skip_scan;
		} else
			return print_win_err(err, "Failed to find file (in %s)", find_stack[0].path);
	}
	int ext_depth = 0;
	for (;;) {
		check_first_find:
		do {
			if (find_stack[ext_depth].data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				const char *dir_name = find_stack[ext_depth].data.cFileName;
				////printf("DIR (level %d): %s\n", ext_depth, dir_name);
				if (strcmp(dir_name, ".") == 0 || strcmp(dir_name, "..") == 0) continue;
				if (find_stack[ext_depth].data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
						&& find_stack[ext_depth].data.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT) continue;
				size_t dir_name_len = strlen(dir_name);

				const char *prev_path = find_stack[ext_depth].path;
				size_t prev_path_len = strlen(prev_path);
				ext_depth += 1;
				find_stack = realloc(find_stack, sizeof(FindInfo) * (1 + ext_depth));

				// prev_path == "path/*" => new_path == "path/dir/*".
				// prev_path == "path"   => new_path == "path/*" (== "dir/*").
				if (prev_path[prev_path_len - 1] == '*') {
					// NOTE: `+sizeof("/*")` could probably be replaced with `+2`,
					// but since it's just 1 extra byte anyway we might aswell
					// to avoid OOB access in some edgecase I didn't think of or something.
					find_stack[ext_depth].path = malloc(prev_path_len + dir_name_len + sizeof("/*"));
					memcpy(find_stack[ext_depth].path, prev_path, prev_path_len);
					memcpy(find_stack[ext_depth].path + prev_path_len - 1, dir_name, dir_name_len);
					memcpy(find_stack[ext_depth].path + prev_path_len - 1 + dir_name_len, "/*", 3);
				} else {
					find_stack[ext_depth].path = malloc(prev_path_len + 3);
					memcpy(find_stack[ext_depth].path, prev_path, prev_path_len);
					memcpy(find_stack[ext_depth].path + prev_path_len, "/*", 3);
				}

				find_stack[ext_depth].find = FindFirstFile(find_stack[ext_depth].path, &find_stack[ext_depth].data);
				if (find_stack[ext_depth].find == INVALID_HANDLE_VALUE) {
					uint32_t err = GetLastError();
					if (err == ERROR_ACCESS_DENIED) {
						printf("Skipping file(s) \"%s\" because access was denied.\n", find_stack[ext_depth].path);
						break;
					} else
						return print_win_err(err, "Failed to find file (in %s)", find_stack[ext_depth].path);
				}

				goto check_first_find;
			} else {
				FindInfo *find = &find_stack[ext_depth];
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

				if (file_is_sus(find->path, kernel32_ordinals)) n_sus += 1;
				n_scanned += 1;

				// "path" => "path/*"
				// "file" => "file"
				if (path_has_wild) {
					find->path[path_len - 1] = '*';
					find->path[path_len] = 0;
				}
			}
		} while (FindNextFile(find_stack[ext_depth].find, &find_stack[ext_depth].data));
		
		dec_depth:
		free(find_stack[ext_depth].path);
		if (ext_depth-- <= 0) break;
		if (!FindNextFile(find_stack[ext_depth].find, &find_stack[ext_depth].data)) goto dec_depth;
	}
	skip_scan:

	printf("%llu files scanned.\n", n_scanned);
	printf("Found %llu suspicious files.\n", n_sus);
}
