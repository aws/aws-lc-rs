REM -- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
REM -- SPDX-License-Identifier: Apache-2.0 OR ISC
@echo off
set "ScriptDir=%~dp0"
set "ScriptDir=%ScriptDir:~0,-1%"
:loop
set "arg1=%~1"
if "%arg1%"=="-o" goto end
if "%arg1%"=="" goto failure
shift
goto loop
:end
shift
set "path=%~1"
for %%f in ("%path%") do set "filename=%%~nxf"
copy "%ScriptDir%\prebuilt-nasm\%filename%" "%path%"
exit 0

:failure
echo PATH: %path% 1>&2
echo FILENAME: %filename% 1>&2
echo ScriptDir: %ScriptDir% 1>&2
exit 1
