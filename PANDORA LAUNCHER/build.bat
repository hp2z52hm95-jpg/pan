@echo off
REM Build PandoraLauncher with Delphi's command-line compiler.
REM 1. Open PandoraLauncher.dpr once in the Delphi IDE and press Save All
REM    (this generates PandoraLauncher.dproj + .res).
REM 2. Run this script.
REM 3. Copy Release\Win32\PandoraLauncher.exe next to PandoraTool.exe.

setlocal

REM --- adjust this path to your Delphi version ---
if exist "C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\rsvars.bat" (
  call "C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\rsvars.bat"
) else if exist "C:\Program Files (x86)\Embarcadero\Studio\22.0\bin\rsvars.bat" (
  call "C:\Program Files (x86)\Embarcadero\Studio\22.0\bin\rsvars.bat"
) else (
  echo ERROR: rsvars.bat not found. Edit build.bat with your Delphi path.
  exit /b 1
)

msbuild PandoraLauncher.dproj /p:Config=Release /p:Platform=Win32 /v:minimal
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

echo.
echo BUILD OK: Bin\PandoraLauncher.exe (or Release\Win32\)
echo Copy it + launcher.ini next to PandoraTool.exe
