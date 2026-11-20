@echo off
chcp 65001 >nul
echo ============================================================================
echo  Smart Office Lightweight ECC P-256 Authentication - Windows EXE Builder
echo ============================================================================
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.8+ is not installed or not in PATH.
    pause
    exit /b 1
)

echo [1/3] Checking/Installing PyInstaller...
python -m pip install --upgrade pyinstaller
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install PyInstaller. Check internet connection.
    pause
    exit /b 1
)

echo.
echo [2/3] Building SmartOffice_Server.exe (Bob)...
python -m PyInstaller --noconfirm --onefile --windowed --name "SmartOffice_Server" --add-data "crypto_ecc.py;." --add-data "i18n.py;." server_app.py

echo.
echo [3/3] Building SmartOffice_Client.exe (Alice)...
python -m PyInstaller --noconfirm --onefile --windowed --name "SmartOffice_Client" --add-data "crypto_ecc.py;." --add-data "i18n.py;." client_app.py

echo.
echo ============================================================================
echo  DONE! Executables are located in the "dist\" folder:
echo    - dist\SmartOffice_Server.exe
echo    - dist\SmartOffice_Client.exe
echo ============================================================================
pause
