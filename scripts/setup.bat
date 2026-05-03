@echo off
:: ╔══════════════════════════════════════════════════════╗
:: ║        NetScan Pro — Windows Setup Script           ║
:: ╚══════════════════════════════════════════════════════╝

title NetScan Pro Setup
color 0B

echo.
echo  ╔══════════════════════════════════════╗
echo  ║       NetScan Pro — Setup            ║
echo  ╚══════════════════════════════════════╝
echo.

:: ── Check Python ──
echo [i] Checking Python 3...
where python >nul 2>&1
if %errorlevel% neq 0 (
  echo [!] Python not found.
  echo [i] Download from: https://www.python.org/downloads/
  echo [i] Make sure to check "Add Python to PATH" during installation.
  pause
  exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [OK] Python %PYVER% found

:: ── Install Python packages ──
echo.
echo [i] Installing Python packages...
python -m pip install --user psutil netifaces --quiet
if %errorlevel% equ 0 (
  echo [OK] Python packages installed
) else (
  echo [!] Failed to install packages. Try: pip install psutil netifaces
)

:: ── Check Node.js ──
echo.
echo [i] Checking Node.js...
where node >nul 2>&1
if %errorlevel% neq 0 (
  echo [!] Node.js not found.
  echo [i] Download from: https://nodejs.org/
  echo [i] The desktop GUI requires Node.js. The web UI works without it.
) else (
  for /f "tokens=1" %%i in ('node --version') do set NODEVER=%%i
  echo [OK] Node.js %NODEVER% found
  
  echo.
  echo [i] Installing Electron dependencies...
  cd frontend
  call npm install --silent
  if %errorlevel% equ 0 (
    echo [OK] Electron dependencies installed
  ) else (
    echo [!] npm install failed
  )
  cd ..
)

:: ── Firewall note ──
echo.
echo [!] Windows Firewall: When prompted, allow NetScan Pro through the firewall
echo [!] For full scanning, run as Administrator (right-click cmd → Run as Administrator)

:: ── Desktop shortcut ──
echo.
echo [i] Creating desktop shortcut...
set SCRIPT_DIR=%~dp0
powershell -Command ^
  "$ws = New-Object -ComObject WScript.Shell; " ^
  "$s = $ws.CreateShortcut('%USERPROFILE%\Desktop\NetScan Pro.lnk'); " ^
  "$s.TargetPath = 'cmd.exe'; " ^
  "$s.Arguments = '/k cd /d ""%SCRIPT_DIR%.."" && python backend\scanner.py'; " ^
  "$s.WorkingDirectory = '%SCRIPT_DIR%..'; " ^
  "$s.Description = 'NetScan Pro Network Scanner'; " ^
  "$s.Save()" 2>nul
if %errorlevel% equ 0 echo [OK] Desktop shortcut created

:: ── Done ──
echo.
echo  ╔══════════════════════════════════════╗
echo  ║        Setup complete! ✓             ║
echo  ╚══════════════════════════════════════╝
echo.
echo   Web UI mode (no Node.js required):
echo     python backend\scanner.py
echo     Then open: http://127.0.0.1:7832
echo.
echo   Desktop GUI mode (requires Node.js):
echo     cd frontend
echo     npm start
echo.
echo   Build Windows installer:
echo     cd frontend
echo     npm run build:win
echo.
pause
