@echo off
for /f "usebackq tokens=* delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
    set "VS_PATH=%%i"
)
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

set