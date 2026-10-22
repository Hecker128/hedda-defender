#include "util.c"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <msi.h>
#include <winnt.h>
#include <wincrypt.h>

/// Maps a file read-only. On failure, releases any resources it acquired.
BOOL map_file(
    const uint8_t **data,
    int64_t *len,
    HANDLE *mapping,
    HANDLE *file,
    const char *path
) {
    if (!data || !len || !mapping || !file || !path)
        return FALSE;

    *data = NULL;
    *len = 0;
    *mapping = NULL;
    *file = INVALID_HANDLE_VALUE;

    *file = CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (*file == INVALID_HANDLE_VALUE)
        return FALSE;

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(*file, &file_size) || file_size.QuadPart < 0) {
        CloseHandle(*file);
        *file = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    *len = file_size.QuadPart;

    // Empty files cannot be mapped as a normal file view.
    if (*len == 0) {
        CloseHandle(*file);
        *file = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    *mapping = CreateFileMappingA(*file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (*mapping == NULL) {
        CloseHandle(*file);
        *file = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    *data = (const uint8_t *)MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
    if (*data == NULL) {
        CloseHandle(*mapping);
        *mapping = NULL;
        CloseHandle(*file);
        *file = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

/// Releases resources returned by map_file().
void unmap_file(const uint8_t *data, HANDLE mapping, HANDLE file) {
    if (data)
        UnmapViewOfFile(data);
    if (mapping && mapping != INVALID_HANDLE_VALUE)
        CloseHandle(mapping);
    if (file && file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
}

/// Calculates the SHA-256 hash of data.
BOOL sha256_hash(uint8_t *hash, const uint8_t *data, DWORD len) {
    if (!hash || (!data && len != 0))
        return FALSE;

    HCRYPTPROV hp = 0;
    HCRYPTHASH hh = 0;
    BOOL ok = FALSE;

    if (!CryptAcquireContextA(&hp, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        goto cleanup;

    if (!CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh))
        goto cleanup;

    if (!CryptHashData(hh, data, len, 0))
        goto cleanup;

    DWORD hash_len = 32;
    if (!CryptGetHashParam(hh, HP_HASHVAL, hash, &hash_len, 0) || hash_len != 32)
        goto cleanup;

    ok = TRUE;

cleanup:
    if (hh)
        CryptDestroyHash(hh);
    if (hp)
        CryptReleaseContext(hp, 0);
    return ok;
}

/// Compares two 32-byte SHA-256 hashes.
BOOL sha256_compare(const uint8_t *a, const uint8_t *b) {
    return a && b && memcmp(a, b, 32) == 0;
}

/// Looks for a byte sequence in a buffer.
BOOL data_has_seq(const uint8_t *data, size_t len, const uint8_t *seq, size_t seq_len) {
    if (seq_len == 0)
        return TRUE;
    if (!data || !seq || seq_len > len)
        return FALSE;

    for (size_t i = 0; i <= len - seq_len; ++i) {
        if (memcmp(data + i, seq, seq_len) == 0)
            return TRUE;
    }
    return FALSE;
}

double data_get_entropy(const uint8_t *data, size_t len) {
    if (!data || len == 0)
        return 0.0;

    uint64_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i)
        counts[data[i]]++;

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0)
            continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

/// Converts an RVA to a file offset. Returns 0 if it cannot be mapped.
uint64_t rva_get_file_offset(
    uint32_t rva,
    const IMAGE_SECTION_HEADER *section_heads,
    uint16_t n_sections
) {
    if (!section_heads)
        return 0;

    for (uint16_t i = 0; i < n_sections; ++i) {
        uint64_t start = section_heads[i].VirtualAddress;
        uint64_t size = section_heads[i].SizeOfRawData;
        uint64_t end = start + size;

        if ((uint64_t)rva >= start && (uint64_t)rva < end)
            return (uint64_t)section_heads[i].PointerToRawData + ((uint64_t)rva - start);
    }
    return 0;
}

/// Checks whether a file has a certificate chain accepted by Microsoft's root policy.
BOOL valid_microsoft_root_cert(const char *path) {
    if (!path)
        return FALSE;

    // Windows Installer exposes this API as a wide-character function.
    int wide_count = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
    if (wide_count <= 0)
        return FALSE;

    wchar_t *wide_path = (wchar_t *)malloc((size_t)wide_count * sizeof(wchar_t));
    if (!wide_path)
        return FALSE;

    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, wide_path, wide_count)) {
        free(wide_path);
        return FALSE;
    }

    PCCERT_CONTEXT cert = NULL;
    UINT msi_result = MsiGetFileSignatureInformationW(
        wide_path, 0, &cert, NULL, NULL
    );
    free(wide_path);
    if (msi_result != ERROR_SUCCESS || !cert)
        return FALSE;

    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_para;
    memset(&chain_para, 0, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);

    if (!CertGetCertificateChain(
            NULL, cert, NULL, cert->hCertStore, &chain_para, 0, NULL, &chain)) {
        CertFreeCertificateContext(cert);
        return FALSE;
    }

    CERT_CHAIN_POLICY_PARA policy_para;
    memset(&policy_para, 0, sizeof(policy_para));
    policy_para.cbSize = sizeof(policy_para);

    CERT_CHAIN_POLICY_STATUS status;
    memset(&status, 0, sizeof(status));
    status.cbSize = sizeof(status);

    BOOL verified = CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, &policy_para, &status
    );

    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(cert);
    return verified && status.dwError == 0;
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
    "VirtualAllocEx"
};

static BOOL range_fits(uint64_t offset, uint64_t amount, uint64_t len) {
    return offset <= len && amount <= len - offset;
}

BOOL get_kernel32_ordinals_inner(uint16_t *ordinals, const uint8_t *data) {
    if (!ordinals || !data)
        return FALSE;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        return FALSE;

    uint64_t nt_offset = (uint32_t)dos->e_lfanew;
    // This function's caller maps kernel32.dll; validate the minimum headers.
    const IMAGE_NT_HEADERS32 *nt32 =
        (const IMAGE_NT_HEADERS32 *)(data + nt_offset);

    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    uint16_t n_sections = nt32->FileHeader.NumberOfSections;
    const IMAGE_DATA_DIRECTORY *data_dirs = NULL;
    const IMAGE_SECTION_HEADER *sections = NULL;

    if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        sections = (const IMAGE_SECTION_HEADER *)(nt32 + 1);
        data_dirs = nt32->OptionalHeader.DataDirectory;
    } else if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt32;
        sections = (const IMAGE_SECTION_HEADER *)(nt64 + 1);
        data_dirs = nt64->OptionalHeader.DataDirectory;
    } else {
        return FALSE;
    }

    const IMAGE_DATA_DIRECTORY *export_dir = &data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir->VirtualAddress == 0 || export_dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        return FALSE;

    uint64_t export_offset = rva_get_file_offset(
        export_dir->VirtualAddress, sections, n_sections
    );
    // The mapped file length is not passed to this helper, so callers should
    // only use it on a trusted, OS-provided system DLL.
    if (export_offset == 0)
        return FALSE;

    const IMAGE_EXPORT_DIRECTORY *exports =
        (const IMAGE_EXPORT_DIRECTORY *)(data + export_offset);
    uint32_t n_names = exports->NumberOfNames;
    uint64_t names_offset = rva_get_file_offset(exports->AddressOfNames, sections, n_sections);
    uint64_t ords_offset = rva_get_file_offset(
        exports->AddressOfNameOrdinals, sections, n_sections
    );
    if (!names_offset || !ords_offset)
        return FALSE;

    const uint32_t *names = (const uint32_t *)(data + names_offset);
    const uint16_t *pe_ordinals = (const uint16_t *)(data + ords_offset);
    BOOL found[KERNEL32_SUSSYBAKAS_MAX] = { FALSE };

    for (uint32_t i = 0; i < n_names; ++i) {
        uint64_t name_offset = rva_get_file_offset(names[i], sections, n_sections);
        if (!name_offset)
            continue;

        const char *name = (const char *)(data + name_offset);
        for (int j = 0; j < KERNEL32_SUSSYBAKAS_MAX; ++j) {
            if (!found[j] && strcmp(name, kernel32_sus_names[j]) == 0) {
                ordinals[j] = pe_ordinals[i];
                found[j] = TRUE;
                break;
            }
        }
    }

    for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; ++i) {
        if (!found[i])
            return FALSE;
    }
    return TRUE;
}

/// Retrieves export ordinals from the local Windows kernel32.dll.
BOOL get_kernel32_ordinals(uint16_t *ordinals) {
    const char path[] = "C:\\Windows\\System32\\KERNEL32.DLL";
    if (!ordinals || !valid_microsoft_root_cert(path))
        return FALSE;

    const uint8_t *data = NULL;
    int64_t len = 0;
    HANDLE mapping = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;

    if (!map_file(&data, &len, &mapping, &file, path))
        return FALSE;

    // The inner parser uses PE offsets but currently has no length argument.
    // It is only called on the local Windows system DLL.
    BOOL result = get_kernel32_ordinals_inner(ordinals, data);
    unmap_file(data, mapping, file);
    return result;
}

/// Checks import tables for imports of selected API names or ordinals.
BOOL imports_are_sus(
    const uint8_t *data,
    uint64_t len,
    const IMAGE_NT_HEADERS32 *nt_heads32,
    const IMAGE_DATA_DIRECTORY *import_dir,
    const IMAGE_SECTION_HEADER *section_heads,
    uint16_t n_sections,
    const uint16_t *kernel32_ordinals
) {
    if (!data || !nt_heads32 || !import_dir || !section_heads || !kernel32_ordinals)
        return FALSE;
    if (import_dir->VirtualAddress == 0 || import_dir->Size == 0)
        return FALSE;

    uint64_t import_off = rva_get_file_offset(
        import_dir->VirtualAddress, section_heads, n_sections
    );
    if (!import_off || !range_fits(import_off, sizeof(IMAGE_IMPORT_DESCRIPTOR), len))
        return FALSE;

    uint64_t descriptor_limit = import_dir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const IMAGE_IMPORT_DESCRIPTOR *imports =
        (const IMAGE_IMPORT_DESCRIPTOR *)(data + import_off);

    for (uint64_t d = 0; d < descriptor_limit; ++d) {
        uint64_t desc_off = import_off + d * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!range_fits(desc_off, sizeof(IMAGE_IMPORT_DESCRIPTOR), len))
            break;

        const IMAGE_IMPORT_DESCRIPTOR *imp = &imports[d];
        if (imp->Name == 0 && imp->FirstThunk == 0 && imp->OriginalFirstThunk == 0)
            break;

        uint64_t lib_off = rva_get_file_offset(imp->Name, section_heads, n_sections);
        if (!lib_off || lib_off >= len)
            continue;

        const char *lib_name = (const char *)(data + lib_off);
        size_t remaining = (size_t)(len - lib_off);
        if (!memchr(lib_name, '\0', remaining))
            continue;
        if (_stricmp(lib_name, "KERNEL32.DLL") != 0)
            continue;

        uint32_t thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        uint64_t thunk_off = rva_get_file_offset(thunk_rva, section_heads, n_sections);
        if (!thunk_off || thunk_off >= len)
            continue;

        BOOL is_pe32plus = nt_heads32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        uint64_t entry_size = is_pe32plus ? sizeof(uint64_t) : sizeof(uint32_t);

        for (uint64_t pos = thunk_off; range_fits(pos, entry_size, len); pos += entry_size) {
            uint64_t entry = 0;
            if (is_pe32plus)
                entry = *(const uint64_t *)(data + pos);
            else
                entry = *(const uint32_t *)(data + pos);

            if (entry == 0)
                break;

            BOOL by_ordinal = is_pe32plus
                ? ((entry & IMAGE_ORDINAL_FLAG64) != 0)
                : ((entry & IMAGE_ORDINAL_FLAG32) != 0);

            if (by_ordinal) {
                uint16_t ordinal = (uint16_t)(entry & 0xffff);
                for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; ++i) {
                    if (ordinal == kernel32_ordinals[i])
                        return TRUE;
                }
            } else {
                uint64_t name_off = rva_get_file_offset(
                    (uint32_t)(entry & 0x7fffffff), section_heads, n_sections
                );
                if (!name_off || !range_fits(name_off, sizeof(IMAGE_IMPORT_BY_NAME), len))
                    continue;

                const IMAGE_IMPORT_BY_NAME *by_name =
                    (const IMAGE_IMPORT_BY_NAME *)(data + name_off);
                uint64_t string_off = name_off + offsetof(IMAGE_IMPORT_BY_NAME, Name);
                if (string_off >= len)
                    continue;

                size_t string_len = (size_t)(len - string_off);
                if (!memchr(by_name->Name, '\0', string_len))
                    continue;

                for (int i = 0; i < KERNEL32_SUSSYBAKAS_MAX; ++i) {
                    if (strcmp((const char *)by_name->Name, kernel32_sus_names[i]) == 0)
                        return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/// Statically checks whether a PE file appears suspicious.
BOOL pe_is_sus(const uint8_t *data, uint64_t len, const uint16_t *kernel32_ordinals) {
    if (!data || len < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        return FALSE;

    uint64_t nt_off = (uint32_t)dos->e_lfanew;
    if (!range_fits(nt_off, sizeof(IMAGE_NT_HEADERS32), len))
        return FALSE;

    const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)(data + nt_off);
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    uint16_t n_sections = nt32->FileHeader.NumberOfSections;
    uint64_t optional_size = nt32->FileHeader.SizeOfOptionalHeader;
    uint64_t optional_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!range_fits(optional_off, optional_size, len))
        return FALSE;

    const IMAGE_DATA_DIRECTORY *data_dirs = NULL;
    uint64_t section_off = optional_off + optional_size;

    if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optional_size < sizeof(IMAGE_OPTIONAL_HEADER32))
            return FALSE;
        data_dirs = nt32->OptionalHeader.DataDirectory;
    } else if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt32;
        if (optional_size < sizeof(IMAGE_OPTIONAL_HEADER64))
            return FALSE;
        data_dirs = nt64->OptionalHeader.DataDirectory;
    } else {
        return FALSE;
    }

    uint64_t sections_bytes = (uint64_t)n_sections * sizeof(IMAGE_SECTION_HEADER);
    if (!range_fits(section_off, sections_bytes, len))
        return FALSE;

    const IMAGE_SECTION_HEADER *sections =
        (const IMAGE_SECTION_HEADER *)(data + section_off);

    if (data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
        data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size &&
        imports_are_sus(
            data, len, nt32, &data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT],
            sections, n_sections, kernel32_ordinals
        )) {
        return TRUE;
    }

    for (uint16_t i = 0; i < n_sections; ++i) {
        uint64_t raw_off = sections[i].PointerToRawData;
        uint64_t raw_size = sections[i].SizeOfRawData;

        if (raw_size == 0 || !range_fits(raw_off, raw_size, len))
            continue;

        if (data_get_entropy(data + raw_off, (size_t)raw_size) > 7.0)
            return TRUE;
    }

    return FALSE;
}

/// Returns TRUE if a file appears suspicious. Failure to read a file is not
/// itself treated as proof of maliciousness.
BOOL file_is_sus(const char *path, const uint16_t *kernel32_ordinals) {
    const uint8_t *data = NULL;
    int64_t len = 0;
    HANDLE mapping = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;

    if (!map_file(&data, &len, &mapping, &file, path))
        return FALSE;

    BOOL suspicious = FALSE;
    if (len > 0)
        suspicious = pe_is_sus(data, (uint64_t)len, kernel32_ordinals);

    unmap_file(data, mapping, file);
    return suspicious;
}

typedef struct {
    char *path;
    HANDLE find;
    WIN32_FIND_DATAA data;
} FindInfo;

typedef struct {
    uint64_t n_scanned;
    uint64_t n_sus;
    uint64_t n_total;
    BOOL is_counting;
    BOOL is_scanning;
} ScanResult;

HANDLE scan_result_mutex = NULL;

ScanResult scan_result = {
    .n_scanned = 0,
    .n_sus = 0,
    .n_total = 0,
    .is_counting = FALSE,
    .is_scanning = FALSE
};

BOOL init_scanner(void) {
    if (scan_result_mutex)
        return TRUE;

    scan_result_mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!scan_result_mutex) {
        print_win_err(GetLastError(), "Failed to create mutex for scan result");
        return FALSE;
    }
    return TRUE;
}

static BOOL lock_scan_result(void) {
    if (!scan_result_mutex)
        return FALSE;

    DWORD result = WaitForSingleObject(scan_result_mutex, INFINITE);
    return result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
}

static void unlock_scan_result(void) {
    if (scan_result_mutex)
        ReleaseMutex(scan_result_mutex);
}

static void finish_scan(void) {
    if (lock_scan_result()) {
        scan_result.is_counting = FALSE;
        scan_result.is_scanning = FALSE;
        unlock_scan_result();
    }
}

static BOOL build_child_path(
    char *out,
    size_t out_size,
    const char *directory,
    const char *name
) {
    size_t dlen = strlen(directory);
    BOOL has_slash = dlen > 0 &&
        (directory[dlen - 1] == '\\' || directory[dlen - 1] == '/');

    int n = snprintf(out, out_size, "%s%s%s", directory, has_slash ? "" : "\\", name);
    return n >= 0 && (size_t)n < out_size;
}

/// Counts accessible regular files recursively. Reparse-point directories are
/// not followed. Long paths beyond MAX_PATH are skipped.
static uint64_t count_files_recursive(const char *directory) {
    char search_path[MAX_PATH];
    if (!build_child_path(search_path, sizeof(search_path), directory, "*"))
        return 0;

    WIN32_FIND_DATAA data;
    HANDLE find = FindFirstFileA(search_path, &data);
    if (find == INVALID_HANDLE_VALUE)
        return 0;

    uint64_t total = 0;
    do {
        if (strcmp(data.cFileName, ".") == 0 ||
            strcmp(data.cFileName, "..") == 0)
            continue;

        char full_path[MAX_PATH];
        if (!build_child_path(full_path, sizeof(full_path), directory, data.cFileName))
            continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                total += count_files_recursive(full_path);
        } else {
            ++total;
        }
    } while (FindNextFileA(find, &data));

    FindClose(find);
    return total;
}

static void close_find_stack(FindInfo *stack, size_t count) {
    if (!stack)
        return;

    for (size_t i = 0; i < count; ++i) {
        if (stack[i].find && stack[i].find != INVALID_HANDLE_VALUE)
            FindClose(stack[i].find);
        free(stack[i].path);
    }
    free(stack);
}

/// Scans one directory tree. Each directory has its own FindFirstFile handle.
static BOOL scan_directory_tree(
    const char *root,
    const uint16_t *kernel32_ordinals
) {
    size_t capacity = 16;
    size_t depth = 0;
    FindInfo *stack = (FindInfo *)calloc(capacity, sizeof(*stack));
    if (!stack)
        return FALSE;

    stack[0].find = INVALID_HANDLE_VALUE;
    stack[0].path = (char *)malloc(MAX_PATH);
    if (!stack[0].path ||
        !build_child_path(stack[0].path, MAX_PATH, root, "*")) {
        close_find_stack(stack, 1);
        return FALSE;
    }

    stack[0].find = FindFirstFileA(stack[0].path, &stack[0].data);
    if (stack[0].find == INVALID_HANDLE_VALUE) {
        close_find_stack(stack, 1);
        return TRUE; // inaccessible directory: skip it
    }

    for (;;) {
        FindInfo *current = &stack[depth];
        const char *name = current->data.cFileName;

        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            if (current->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!(current->data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    char child_dir[MAX_PATH];
                    size_t parent_len = strlen(current->path);
                    size_t name_len = strlen(name);

                    // Current search path ends in '*'; replace it with
                    // "directory-name\\*" to descend into this directory.
                    if (parent_len > 0 &&
                        current->path[parent_len - 1] == '*' &&
                        parent_len - 1 + name_len + 3 <= sizeof(child_dir)) {
                        memcpy(child_dir, current->path, parent_len - 1);
                        memcpy(child_dir + parent_len - 1, name, name_len);
                        child_dir[parent_len - 1 + name_len] = '\\';
                        child_dir[parent_len + name_len] = '*';
                        child_dir[parent_len + name_len + 1] = '\0';

                        if (depth + 1 >= capacity) {
                            size_t new_capacity = capacity * 2;
                            FindInfo *new_stack = (FindInfo *)realloc(
                                stack, new_capacity * sizeof(*stack)
                            );
                            if (!new_stack) {
                                close_find_stack(stack, depth + 1);
                                return FALSE;
                            }
                            stack = new_stack;
                            memset(stack + capacity, 0,
                                (new_capacity - capacity) * sizeof(*stack));
                            capacity = new_capacity;
                            current = &stack[depth];
                        }

                        FindInfo *child = &stack[depth + 1];
                        memset(child, 0, sizeof(*child));
                        child->find = INVALID_HANDLE_VALUE;
                        child->path = (char *)malloc(strlen(child_dir) + 1);

                        if (!child->path) {
                            close_find_stack(stack, depth + 1);
                            return FALSE;
                        }
                        strcpy(child->path, child_dir);

                        child->find = FindFirstFileA(child->path, &child->data);
                        if (child->find != INVALID_HANDLE_VALUE) {
                            depth++;
                            continue; // process first entry in child directory
                        }

                        // Inaccessible/vanished directory: skip it.
                        free(child->path);
                        child->path = NULL;
                    }
                }
            } else {
                char file_path[MAX_PATH];
                size_t parent_len = strlen(current->path);
                size_t name_len = strlen(name);

                if (parent_len > 0 &&
                    current->path[parent_len - 1] == '*' &&
                    parent_len - 1 + name_len + 1 <= sizeof(file_path)) {
                    memcpy(file_path, current->path, parent_len - 1);
                    memcpy(file_path + parent_len - 1, name, name_len);
                    file_path[parent_len - 1 + name_len] = '\0';

                    BOOL suspicious = file_is_sus(file_path, kernel32_ordinals);
                    if (!lock_scan_result()) {
                        close_find_stack(stack, depth + 1);
                        return FALSE;
                    }

                    scan_result.n_scanned++;
                    if (suspicious)
                        scan_result.n_sus++;

                    unlock_scan_result();
                }
            }
        }

        // Advance this directory. If exhausted, pop it and advance its parent.
        if (FindNextFileA(stack[depth].find, &stack[depth].data))
            continue;

        FindClose(stack[depth].find);
        stack[depth].find = INVALID_HANDLE_VALUE;
        free(stack[depth].path);
        stack[depth].path = NULL;

        if (depth == 0) {
            free(stack);
            return TRUE;
        }

        depth--;
        while (!FindNextFileA(stack[depth].find, &stack[depth].data)) {
            FindClose(stack[depth].find);
            stack[depth].find = INVALID_HANDLE_VALUE;
            free(stack[depth].path);
            stack[depth].path = NULL;

            if (depth == 0) {
                free(stack);
                return TRUE;
            }
            depth--;
        }
    }
}

// Do not call this directly. Use create_scan_thread().
DWORD WINAPI scan_thread_routine(LPVOID lpParam) {
    const char *path = (const char *)lpParam;
    if (!path || !*path) {
        finish_scan();
        return 1;
    }

    uint16_t kernel32_ordinals[KERNEL32_SUSSYBAKAS_MAX] = {0};
    if (!get_kernel32_ordinals(kernel32_ordinals)) {
        finish_scan();
        return 1;
    }

    if (!lock_scan_result()) {
        finish_scan();
        return 1;
    }
    scan_result.is_counting = TRUE;
    scan_result.is_scanning = TRUE;
    unlock_scan_result();

    uint64_t total = count_files_recursive(path);

    if (!lock_scan_result()) {
        finish_scan();
        return 1;
    }
    scan_result.n_total = total;
    scan_result.is_counting = FALSE;
    unlock_scan_result();

    BOOL success = scan_directory_tree(path, kernel32_ordinals);
    finish_scan();

    if (!success) {
        puts("Scan stopped because of an internal error.");
        return 1;
    }

    puts("Scan completed.");
    return 0;
}

/// Starts a scan thread. Keep `path` valid until the worker has finished.
/// Example: create_scan_thread("C:\\");
HANDLE create_scan_thread(char *path) {
    if (!path || !*path || !init_scanner())
        return NULL;

    if (!lock_scan_result())
        return NULL;

    if (scan_result.is_scanning || scan_result.is_counting) {
        unlock_scan_result();
        return NULL;
    }

    scan_result.n_scanned = 0;
    scan_result.n_sus = 0;
    scan_result.n_total = 0;
    scan_result.is_counting = TRUE;
    scan_result.is_scanning = TRUE;
    unlock_scan_result();

    DWORD tid = 0;
    HANDLE thread = CreateThread(NULL, 0, scan_thread_routine, path, 0, &tid);
    if (!thread)
        finish_scan();

    return thread;
}
