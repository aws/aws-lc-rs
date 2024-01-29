@echo off
setlocal EnableDelayedExpansion
for /f "usebackq tokens=* delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
    set "VS_PATH=%%i\VC\Auxiliary\Build\"
    echo FOUND: "!VS_PATH!"
    goto FoundVS
)

echo Visual Studio installation not found using vswhere. Searching in default directories...
for /R "%ProgramFiles(x86)%\Microsoft Visual Studio" %%a in (vcvarsall.bat) do (
    if exist "%%~fa" (
        set "VS_PATH=%%~dpa"
        echo FOUND: "!VS_PATH!"
        goto FoundVS
    )
)
echo vcvarsall.bat not found.
goto End

:FoundVS
call "!VS_PATH!vcvarsall.bat" x64
if !ERRORLEVEL! neq 0 (
    echo Failed to set Visual Studio environment variables.
    echo PATH: "!VS_PATH!vcvarsall.bat"
    goto End
)
echo Visual Studio environment variables set for x64.

set
endlocal
exit /b 0

:End
endlocal
exit /b 1
