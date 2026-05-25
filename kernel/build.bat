@echo off
setlocal enabledelayedexpansion

set PROJ_DIR=%~dp0
set WDK_DIR=%PROJ_DIR%wdk
set SRC=%PROJ_DIR%IntegrityMonitor.c
set HDR=%PROJ_DIR%IntegrityMonitor.h

REM --- Find VS 2022 ---
set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
    set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
if not exist %VCVARS% (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

call %VCVARS%
echo Visual Studio environment set up

REM --- Include paths ---
set INCLUDE_FLAGS=/I"%WDK_DIR%\include\km" /I"%WDK_DIR%\include\shared" /I"%WDK_DIR%\include\um"

REM --- Compile ---
echo Compiling IntegrityMonitor.c ...
cl.exe /nologo /c /O1 /W4 /WX /Gz /kernel /Zp8 /GS- ^
    /DDRIVER /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 ^
    %INCLUDE_FLAGS% ^
    "%SRC%"
if %ERRORLEVEL% neq 0 (
    echo Compilation failed
    exit /b %ERRORLEVEL%
)

REM --- Link ---
echo Linking IntegrityMonitor.sys ...
link.exe /nologo /driver /kernel /subsystem:native ^
    /entry:DriverEntry@8 ^
    /out:"%PROJ_DIR%IntegrityMonitor.sys" ^
    IntegrityMonitor.obj ^
    "%WDK_DIR%\lib\ntoskrnl.lib" ^
    "%WDK_DIR%\lib\hal.lib"
if %ERRORLEVEL% neq 0 (
    echo Linking failed
    exit /b %ERRORLEVEL%
)

echo.
echo Success! IntegrityMonitor.sys built.
echo.
dir "%PROJ_DIR%IntegrityMonitor.sys"
