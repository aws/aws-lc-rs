@echo off
setlocal DisableDelayedExpansion

set "VCVARS_ARCH=%~1"
if "%VCVARS_ARCH%"=="" set "VCVARS_ARCH=x64"
set "VC_TOOLS_COMPONENT=%~2"
if "%VC_TOOLS_COMPONENT%"=="" set "VC_TOOLS_COMPONENT=Microsoft.VisualStudio.Component.VC.Tools.x86.x64"

rem Prefer the newest installation, of any product, that has the C++ tools for
rem the target. Failing that, try installations from newest to oldest, since
rem the toolset may be installed under another component ID (e.g. a version-pinned
rem toolset). Skip installations that cannot initialize the target environment.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto SearchVS
call :FindWithVswhere -latest -products * -requires %VC_TOOLS_COMPONENT% && goto FoundVS
call :FindWithVswhere -products * -sort && goto FoundVS
rem Retry a rejected query, not an exhausted list of installations. Older
rem versions support -products * but not -sort; keep Build Tools in scope.
if not errorlevel 2 goto SearchVS
call :FindWithVswhere -products * && goto FoundVS
if not errorlevel 2 goto SearchVS
call :FindWithVswhere -latest && goto FoundVS

:SearchVS
>&2 echo No usable Visual Studio installation found using vswhere. Searching in default directories...

for /R "%ProgramFiles(x86)%\Microsoft Visual Studio" %%a in (vcvarsall.bat) do (
    if exist "%%~fa" (
        >&2 echo FOUND: "%%~dpa"
        call :TryVcvarsall "%%~fa" && goto FoundVS
    )
)
>&2 echo No usable vcvarsall.bat found.
goto End

:FoundVS
endlocal
exit /b 0

:End
endlocal
exit /b 1

rem FOR /F does not propagate the command's exit code. The sentinel is not an installation path.
:FindWithVswhere
for /f "usebackq tokens=* delims=" %%i in (`"%VSWHERE%" %* -property installationPath ^|^| echo :QueryFailed`) do (
    if "%%i"==":QueryFailed" exit /b 2
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" (
        >&2 echo FOUND in Installation: "%%i\VC\Auxiliary\Build\"
        call :TryVcvarsall "%%i\VC\Auxiliary\Build\vcvarsall.bat" && exit /b 0
    )
)
exit /b 1

rem Only print an initialized environment. Failed attempts must not affect
rem later candidates, and the caller only needs the printed environment.
:TryVcvarsall
setlocal
call "%~1" %VCVARS_ARCH% 1>&2
if not "%errorlevel%"=="0" (
    >&2 echo Failed to set Visual Studio environment variables.
    >&2 echo PATH: "%~1" %VCVARS_ARCH%
    endlocal
    exit /b 1
)
rem vcvarsall can succeed without target tools and preserve another target's
rem libraries on LIB. Check that the selected toolset actually has this target.
if not defined VCToolsInstallDir goto NoTargetLibs
if not defined VSCMD_ARG_TGT_ARCH goto NoTargetLibs
if not exist "%VCToolsInstallDir%\lib\%VSCMD_ARG_TGT_ARCH%\msvcrt.lib" goto NoTargetLibs
for %%f in (msvcrt.lib) do if "%%~$LIB:f"=="" goto NoTargetLibs
>&2 echo Visual Studio environment variables set for %VCVARS_ARCH%.
rem stdout is only the selected environment, in UTF-16LE regardless of the active code page.
"%ComSpec%" /d /u /c set
exit /b %errorlevel%

:NoTargetLibs
>&2 echo No MSVC libraries for %VCVARS_ARCH% in the Visual Studio environment.
endlocal
exit /b 1
