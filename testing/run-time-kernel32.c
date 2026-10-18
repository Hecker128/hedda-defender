#include <windows.h>

int main() {
	HINSTANCE kernel32 = LoadLibrary("\\Windows\\System32\\KERNEL32.dll");
	if (kernel32 == NULL) return GetLastError();

	LPVOID (__cdecl *VirtualAllocEx_proc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = (void *)GetProcAddress(kernel32, "VirtualAllocEx");
	if (VirtualAllocEx_proc == NULL) return GetLastError();

	// This VirtualAllocEx call should "safely" fail I think, but since we're still calling it that should be detected.
	(VirtualAllocEx_proc)(0, NULL, 0, 0, 0);

	FreeLibrary(kernel32);
}
