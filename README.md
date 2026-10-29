# Compiling

1. Install LLVM/Clang. `winget install LLVM.LLVM` should work (I think).
2. If you don't want to use YARA, comment out `set USE_YARA=1` in `build.bat`. Otherwise, install/compile vcpkg (git clone https://github.com/microsoft/vcpkg.git to your home direcrory/USERPROFILE) and then install (lib)yara through vcpkg. For now `build.bat` assumes the files are installed to `%USERPROFILE%\vcpkg\installed\x64-mingw-dynamic`, so Make sure that's the case for you (or modify that line in `build.bat`, but that might require doing some other stuff too).
3. If you don't want to use Windows notification center notifications, comment out `set USE_APPNOTIFICATIONS=1` in `build.bat`. Otherwise, install Windows App SDK 2.6.4.
4. Run `./build.bat`. This will build Hedda Defender to `bin`.
