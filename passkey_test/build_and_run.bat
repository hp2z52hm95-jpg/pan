@echo off
echo === Passkey Authentication Smoke Test - Build Script ===
echo.

REM Check if Delphi compiler is available
where dcc32 >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Delphi compiler (dcc32) not found in PATH
    echo.
    echo Please ensure Delphi is installed and dcc32.exe is in your PATH.
    echo Alternatively, open PasskeyTest.dpr in the Delphi IDE and build from there.
    echo.
    pause
    exit /b 1
)

echo [INFO] Compiling PasskeyTest...
echo.

dcc32 PasskeyTest.dpr -B -$O+ -$W- -$H+ -$X+ -NSSystem;System.Win;Vcl;Vcl.Imaging;Winapi

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Compilation failed
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Compilation successful!
echo.
echo Running PasskeyTest.exe...
echo.

PasskeyTest.exe

pause
