set USE_YARA=1
set USE_APPNOTIFICATIONS=1
:: set USE_API_HOOKS=1

set CFLAGS=src\gui.c -o bin\hedda-defender.exe -Wall -Wextra -Werror=return-type -Wno-unused-parameter -Wno-unused-function -luser32 -lgdi32 -lcomctl32 -lmsi -ladvapi32 -lcrypt32 -g

setlocal EnableDelayedExpansion

if "%USE_YARA%" NEQ "" (
	set VCPKG_DIR=%USERPROFILE%\vcpkg\installed\x64-mingw-dynamic
	copy "!VCPKG_DIR!\bin\libcrypto-3-x64.dll" bin
	set CFLAGS=%CFLAGS% -DUSE_YARA -I"!VCPKG_DIR!\include" -L"!VCPKG_DIR!\lib" -llibyara -llibcrypto
)

if "%USE_APPNOTIFICATIONS%" NEQ "" (
	set PACKAGES_DIR=%USERPROFILE%\.nuget\packages
	set FOUNDATION_DIR=%USERPROFILE%\.nuget\packages\microsoft.windowsappsdk.foundation\2.6.4
	set RUNTIME_DIR=%USERPROFILE%\.nuget\packages\microsoft.windowsappsdk.runtime\2.6.4
	copy "!FOUNDATION_DIR!\runtimes\win-x64\native\Microsoft.WindowsAppRuntime.Bootstrap.dll" bin
	set CFLAGS=%CFLAGS% -DUSE_APPNOTIFICATIONS -I"!FOUNDATION_DIR!\include" -I"!RUNTIME_DIR!\include" -L"!FOUNDATION_DIR!\lib\native\x64" -lRuntimeObject -lMicrosoft.WindowsAppRuntime.Bootstrap
)

if "%USE_API_HOOKS%" NEQ "" (
	set CFLAGS=%CFLAGS% -DUSE_API_HOOKS
)

clang %CFLAGS%
