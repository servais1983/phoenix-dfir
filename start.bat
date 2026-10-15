@echo off
REM ============================================================
REM  Phoenix DFIR - Windows launcher
REM  Double-click this file to start the platform.
REM  Requirements: Python 3.10+ and Node.js 20+ in the PATH.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo  ============================================
echo   Phoenix DFIR - Startup
echo  ============================================
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo  [ERROR] Node.js not found.
    echo  Install Node.js 20+: https://nodejs.org
    pause
    exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo  Install Python 3.10+: https://python.org
    echo  ^(check "Add Python to PATH" during installation^)
    pause
    exit /b 1
)

if not exist node_modules (
    echo  [SETUP] Installing frontend dependencies...
    call npm install --no-audit --no-fund
    if errorlevel 1 (
        echo  [ERROR] npm install failed.
        pause
        exit /b 1
    )
)

if not exist backend\venv (
    echo  [SETUP] Setting up the Python environment...
    node scripts\setup-backend.js
)

echo.
echo  Frontend : http://localhost:5173
echo  Backend  : http://localhost:5000
if defined GITHUB_TOKEN (
    echo  AI investigator: GitHub Copilot configured
) else if defined PHOENIX_GITHUB_TOKEN (
    echo  AI investigator: GitHub Copilot configured
) else (
    echo  AI investigator: set GITHUB_TOKEN to enable it
    echo                   ^(GitHub token, "Models: read" permission^)
)
echo  Auto drop folder: backend\evidence_inbox ^(drop evidence files, processing is automatic^)
echo  ^(Ctrl+C to stop^)
echo.

call npm start

pause
endlocal
