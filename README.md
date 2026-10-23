To compile use this:
& $clang /MD /O2 /Fe:HeddaDefender.exe `  /I"$env:USERPROFILE\vcpkg\installed\x64-windows\include" `
gui.c scanner.c util.c ` "$env:USERPROFILE\vcpkg\installed\x64-windows\lib\libyara.lib" ` "$env:USERPROFILE\vcpkg\installed\x64-windows\lib\libcrypto.lib" ` user32.lib gdi32.lib comctl32.lib ` advapi32.lib crypt32.lib msi.lib ws2_32.lib
