set USE_MSVCRT=1
set USE_MINGW=1
set USE_YARA=1
set USE_APPNOTIFICATIONS=1
:: set USE_API_HOOKS=1
:: set USE_HEDDAFLT=1
set USE_ASAN=1

@set CFLAGS=src\gui.c src\util.c -o bin\hedda-defender.exe -Wall -Wextra -Werror=return-type -Wno-unused-parameter -Wno-unused-function -luser32 -lgdi32 -lcomctl32 -lmsi -ladvapi32 -lcrypt32 -g

@setlocal EnableDelayedExpansion

@if "%USE_YARA%" NEQ "" (
	if "%USE_MINGW%" NEQ "" (
		set VCPKG_DIR=%USERPROFILE%\vcpkg\installed\x64-mingw-dynamic
	) else (
		set VCPKG_DIR=%USERPROFILE%\vcpkg\installed\x64-windows
	)

	copy "!VCPKG_DIR!\bin\libcrypto-3-x64.dll" bin
	if !ERRORLEVEL! NEQ 0 (
		echo Failed to copy "!VCPKG_DIR!\bin\libcrypto-3-x64.dll" to bin.
		EXIT /B !ERRORLEVEL!
	)

	set CFLAGS=%CFLAGS% -DUSE_YARA src\yara-integration.c -I"!VCPKG_DIR!\include" -L"!VCPKG_DIR!\lib" -llibyara -llibcrypto -D_CRT_SECURE_NO_DEPRECATE
)

@if "%USE_APPNOTIFICATIONS%" NEQ "" (
	set PACKAGES_DIR=%USERPROFILE%\.nuget\packages
	set FOUNDATION_DIR=%USERPROFILE%\.nuget\packages\microsoft.windowsappsdk.foundation\2.6.4
	set RUNTIME_DIR=%USERPROFILE%\.nuget\packages\microsoft.windowsappsdk.runtime\2.6.4
	set CFLAGS=%CFLAGS% -DUSE_APPNOTIFICATIONS -I"!FOUNDATION_DIR!\include" -I"!RUNTIME_DIR!\include" -L"!FOUNDATION_DIR!\lib\native\x64" -lRuntimeObject -lMicrosoft.WindowsAppRuntime.Bootstrap

	copy "!FOUNDATION_DIR!\runtimes\win-x64\native\Microsoft.WindowsAppRuntime.Bootstrap.dll" bin
	if !ERRORLEVEL! NEQ 0 (
		echo Failed to copy "!FOUNDATION_DIR!\runtimes\win-x64\native\Microsoft.WindowsAppRuntime.Bootstrap.dll" to bin.
		EXIT /B !ERRORLEVEL!
	)
)

@if "%USE_API_HOOKS%" NEQ "" set CFLAGS=%CFLAGS% -DUSE_API_HOOKS

@if "%USE_HEDDAFLT%" NEQ "" set CFLAGS=%CFLAGS% -DUSE_HEDDAFLT -lFltLib

@if "%USE_ASAN%" NEQ "" (
	if "%USE_MSVCRT%" NEQ "" echo AddressSanitizer used with the MSVCRT runtime. If this produces linker errors, consider switching to the UCRT runtime.
	set CFLAGS=%CFLAGS% -fsanitize=address
)

clang %CFLAGS%
