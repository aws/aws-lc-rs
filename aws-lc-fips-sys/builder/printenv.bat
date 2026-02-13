@echo off
setlocal EnableDelayedExpansion

set "TOP_DIR=%ProgramFiles(x86)%\Microsoft Visual Studio"
for /f "usebackq tokens=* delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
    set "TOP_DIR=%%i"
    echo VS Installation: "!TOP_DIR!"
    if exist "!TOP_DIR!\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VS_PATH=!TOP_DIR!\VC\Auxiliary\Build\"
        echo FOUND in Installation: "!VS_PATH!"
        goto FoundVS
    )
    goto SearchVS
)

echo Visual Studio installation not found using vswhere. Searching in default directories...

:SearchVS
for /R "%TOP_DIR%" %%a in (vcvarsall.bat) do (
    if exist "%%~fa" (
        set "VS_PATH=%%~dpa"
        echo FOUND: "!VS_PATH!"
        goto FoundVS
    )
)
echo vcvarsall.bat not found.
goto End

:FoundVS
REM Determine the vcvarsall architecture argument based on target
REM CARGO_CFG_TARGET_ARCH is set by Cargo during build script execution
REM Default to x64 if not set
set "VCVARS_ARCH=x64"

if defined CARGO_CFG_TARGET_ARCH (
    echo Target architecture: !CARGO_CFG_TARGET_ARCH!
    if "!CARGO_CFG_TARGET_ARCH!"=="aarch64" (
        set "VCVARS_ARCH=x64_arm64"
    ) else if "!CARGO_CFG_TARGET_ARCH!"=="x86" (
        set "VCVARS_ARCH=x64_x86"
    ) else if "!CARGO_CFG_TARGET_ARCH!"=="i686" (
        set "VCVARS_ARCH=x64_x86"
    ) else (
        set "VCVARS_ARCH=x64"
    )
) else (
    echo CARGO_CFG_TARGET_ARCH not set, defaulting to x64
)

echo Using vcvarsall architecture: !VCVARS_ARCH!

call "!VS_PATH!vcvarsall.bat" !VCVARS_ARCH!
if !ERRORLEVEL! neq 0 (
    echo Failed to set Visual Studio environment variables.
    echo PATH: "!VS_PATH!vcvarsall.bat"
    echo ARCH: !VCVARS_ARCH!
    goto End
)
echo Visual Studio environment variables set for !VCVARS_ARCH!.

set
endlocal
exit /b 0

:End
endlocal
exit /b 1
