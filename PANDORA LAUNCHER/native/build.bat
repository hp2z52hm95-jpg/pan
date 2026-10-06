@echo off
REM ====================================================================
REM  build.bat - build PandoraLauncher.exe on Windows
REM
REM  Needs ONE of these free toolchains:
REM    * Visual Studio Build Tools (cl.exe)  - recommended
REM    * MinGW-w64 (gcc.exe)                 - e.g. from winlibs.com
REM    * LLVM/clang (clang.exe + llvm-rc)
REM
REM  Usage:  build.bat            (release build, 32-bit - runs everywhere)
REM          build.bat 64         (64-bit build)
REM          build.bat debug
REM
REM  Output: PandoraLauncher.exe in this folder, ready to copy next to
REM          PandoraTool.exe together with a launcher.ini.
REM ====================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set ARCH=32
set CONFIG=release
if /I "%~1"=="64" set ARCH=64
if /I "%~1"=="x64" set ARCH=64
if /I "%~1"=="debug" set CONFIG=debug

echo === Pandora Launcher build (%ARCH%-bit, %CONFIG%) ===

REM ---- 1. resources (icon + manifest + version info) -------------------
if exist launcher.res del launcher.res
where rc.exe >nul 2>nul
if not errorlevel 1 (
    rc.exe /nologo /fo launcher.res launcher.rc || goto :fail
) else (
    where windres.exe >nul 2>nul
    if not errorlevel 1 (
        windres.exe launcher.rc -O coff -o launcher_res.o || goto :fail
    ) else (
        echo WARNING: no resource compiler ^(rc.exe / windres.exe^) found.
        echo          The exe will be built without icon/manifest.
    )
)

set RES=
if exist launcher.res set RES=launcher.res
if exist launcher_res.o set RES=launcher_res.o

REM ---- 2. compile ------------------------------------------------------
where cl.exe >nul 2>nul
if not errorlevel 1 goto :msvc

where gcc.exe >nul 2>nul
if not errorlevel 1 goto :gcc

where clang.exe >nul 2>nul
if not errorlevel 1 goto :clang

echo ERROR: no C compiler found ^(cl.exe, gcc.exe or clang.exe^).
echo        Install "Visual Studio Build Tools" or MinGW-w64 and retry.
goto :fail

:msvc
echo Using MSVC...
if "%ARCH%"=="64" (set PLAT=x64) else (set PLAT=x86)
set CFLAGS=/nologo /TC /W3 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601
if "%CONFIG%"=="debug" (set CFLAGS=%CFLAGS% /Od /Zi) else (set CFLAGS=%CFLAGS% /O2 /GL)
REM Console app? No - this is a GUI app (WinMain via /SUBSYSTEM:WINDOWS).
cl %CFLAGS% launcher.c util.c %RES% /Fe:PandoraLauncher.exe /link ^
   /SUBSYSTEM:WINDOWS /MACHINE:%PLAT% user32.lib gdi32.lib shell32.lib ^
   winhttp.lib comctl32.lib version.lib advapi32.lib || goto :fail
del *.obj >nul 2>nul
goto :done

:gcc
echo Using MinGW-w64...
set CFLAGS=-std=c99 -O2 -Wall -Wextra -DUNICODE -D_UNICODE
if "%CONFIG%"=="debug" set CFLAGS=-std=c99 -O0 -g -Wall -DUNICODE -D_UNICODE
gcc %CFLAGS% -o PandoraLauncher.exe launcher.c util.c %RES% ^
    -lwinhttp -lcomctl32 -lversion -lshell32 -luser32 -lgdi32 -ladvapi32 ^
    -Wl,--subsystem,windows || goto :fail
goto :done

:clang
echo Using clang...
clang -std=c99 -O2 -Wall -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 ^
    -o PandoraLauncher.exe launcher.c util.c %RES% ^
    -lwinhttp -lcomctl32 -lversion -lshell32 -luser32 -lgdi32 -ladvapi32 ^
    -Wl,--subsystem,windows || goto :fail
goto :done

:done
echo.
echo BUILD OK: %CD%\PandoraLauncher.exe
echo Copy PandoraLauncher.exe + launcher.ini ^(from launcher.ini.example^)
echo next to PandoraTool.exe and point the shortcut at it.
exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
