@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PIP_DISABLE_PIP_VERSION_CHECK=1
python --version >nul 2>&1
if errorlevel 1 exit /b 1
python -m pip install -r requirements-dev.txt
if errorlevel 1 exit /b 1
for /f %%v in ('python -c "import certlock; print(certlock.APP_VERSION)"') do set VERSION=%%v
for /f %%i in ('python -c "import uuid; print(uuid.uuid4().hex)"') do set RUN_ID=%%i
if not defined VERSION exit /b 1
if not defined RUN_ID exit /b 1
set OUTPUT=dist\local-%RUN_ID%\CertLock_v%VERSION%-portable
if exist "%OUTPUT%" exit /b 1
python -m unittest discover -s tests -v
if errorlevel 1 exit /b 1
python tests/smoke_preset_gui.py
if errorlevel 1 exit /b 1
python -m PyInstaller certlock.spec --distpath "%OUTPUT%" --workpath "build\local-%RUN_ID%" --noconfirm
if errorlevel 1 exit /b 1
python tests/verify_packaged.py --release-dir "%OUTPUT%"
if errorlevel 1 exit /b 1
copy /-Y "LICENSE" "%OUTPUT%\LICENSE" >nul
if errorlevel 1 exit /b 1
copy /-Y "THIRD_PARTY_NOTICES.md" "%OUTPUT%\THIRD_PARTY_NOTICES.md" >nul
if errorlevel 1 exit /b 1
copy /-Y "docs\常用预设使用说明.md" "%OUTPUT%\使用说明.md" >nul
if errorlevel 1 exit /b 1
echo Build verified: %OUTPUT%
echo No previous build or release was removed.
