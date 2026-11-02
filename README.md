# WARNING
Hedda Defender is NOT a suitable replacement for more developed antiviruses such as Windows Defender. Do NOT use it as your main antivirus.

# System requirements
Hedda Defender is only "officially supported" on x86-64 Windows 11 24H2 and later. Earlier Windows releases or other CPU ISAs might be able to run it (at least partially), but don't take that for granted.
Hardware requirements depend on what features within Hedda Defender you want to use. For example, to use Windows notification center notifications you need enough storage to install the Windows APP SDK.

# Compiling
1. Install LLVM/Clang. This can be done by running `winget install MartinStorsjo.LLVM-MinGW.UCRT` (recommended if you want to use AddressSanitizer), or `winget install MartinStorsjo.LLVM-MinGW.UCRT` to use the MSVCRT runtime, or `winget install LLVM.LLVM` to not use MinGW and use the MSVCRT runtime.
2. If you don't want to use YARA then skip this step. Otherwise: Uncomment `set USE_YARA=1` in `build.bat`. Clone the GitHub repository for vcpkg (https://github.com/microsoft/vcpkg.git) to your USERPROFILE directory. From the vcpkg directory run `./bootstrap-vcpkg.bat`, then `./vcpkg install yara:x64-mingw-dynamic` (or `./vcpkg install yara:x64-windows` if you're using Clang with the MSVCRT runtime).
3. If you don't want to use Windows notification center notifications, skip this step. Otherwise: Uncomment `set USE_APPNOTIFICATIONS=1` in `build.bat`. Install Windows App SDK 2.6.4.
4. If you don't want to use HeddaFlt (a minifilter driver that helps Hedda Defender catch threats by intercepting system I/O), skip this step. Otherwise (NOT recommended on your main windows installation!): Uncomment `set USE_HEDDAFLT` in `build.bat`, install Visual Studio with the "Desktop development with C++" workload and the "Windows Driver kit" component. Then separately install the Windows SDK and a matching version of the WDK. After that, open `HeddaFlt.sln` in `src/HeddaFlt` with Visual studio and build the solution. To install and load HeddaFlt, you need to disable driver signature enforcement. In the "Power" options in Windows start, hold shift and click "Restart". In Windows recovery environment, select Troubleshoot\>Advanced options\>Startup settings and restart. After the restart, select "Disable driver signature enforcement" (F7). After Windows has booted, open powershell as administrator and cd to `src/HeddaFlt/x64/Debug`, then run `pnputil /add-driver HeddaFlt.inf /install` and install the driver.
5. If you want to use AddressSanitizer for debugging memory management stuff, uncomment `set_USE_ASAN` in `build.bat`.
6. If you're using Clang with the MSVCRT runtime, uncomment `set USE_MSVCRT` in `build.bat`.
7. If you're using Clang with MinGW, uncomment `set USE_MINGW` in `build.bat`.
8. Run `./build.bat`. This will build Hedda Defender to `bin`.

# Running
The executable for running Hedda Defender is `bin/hedda-defender.exe`.
Hedda Defender is primarily meant to run with Administrator privileges. It will run without them, but with limited functionality.
If you run into problems while running, you can use the `-v` flag to enable logging to the console. The `-r _directory_` flag is also useful if you want to test the static scanner functionality without having to wait ages for your entire system to be scanned.
