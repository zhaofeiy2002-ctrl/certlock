@echo off
chcp 65001 >nul
echo ============================================
echo   CertLock Build Script
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH
    pause
    exit /b 1
)

:: Check PyInstaller
python -c "import PyInstaller" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

echo [1/2] Cleaning old builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/2] Building single executable...
python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name CertLock ^
    --clean ^
    --noconfirm ^
    --add-data "cert_360_b64.txt;." ^
    certlock.py

if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Build Complete!
echo   Output: dist\CertLock.exe
echo ============================================
dir dist\CertLock.exe 2>nul

:: UPX compression (optional)
where upx >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo [OPTIONAL] Compressing with UPX...
    upx --best --lzma dist\CertLock.exe
    echo After UPX:
    dir dist\CertLock.exe 2>nul
)

echo.
echo Done! Portable executable is ready.
pause
