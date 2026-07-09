@echo off
REM ============================================================
REM  Phoenix DFIR - Lanceur Windows
REM  Double-cliquez sur ce fichier pour demarrer la plateforme.
REM  Prerequis : Python 3.10+ et Node.js 20+ dans le PATH.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo  ============================================
echo   Phoenix DFIR - Demarrage
echo  ============================================
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo  [ERREUR] Node.js est introuvable.
    echo  Installez Node.js 20+ : https://nodejs.org
    pause
    exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
    echo  [ERREUR] Python est introuvable.
    echo  Installez Python 3.10+ : https://python.org
    echo  ^(cochez "Add Python to PATH" durant l'installation^)
    pause
    exit /b 1
)

if not exist node_modules (
    echo  [SETUP] Installation des dependances frontend...
    call npm install --no-audit --no-fund
    if errorlevel 1 (
        echo  [ERREUR] npm install a echoue.
        pause
        exit /b 1
    )
)

if not exist backend\venv (
    echo  [SETUP] Configuration de l'environnement Python...
    node scripts\setup-backend.js
)

echo.
echo  Frontend : http://localhost:5173
echo  Backend  : http://localhost:5000
if defined GITHUB_TOKEN (
    echo  Enqueteur IA : GitHub Copilot configure
) else if defined PHOENIX_GITHUB_TOKEN (
    echo  Enqueteur IA : GitHub Copilot configure
) else (
    echo  Enqueteur IA : definissez GITHUB_TOKEN pour l'activer
    echo                 ^(jeton GitHub, permission "Models: read"^)
)
echo  Depot auto : backend\evidence_inbox ^(deposez vos evidences, tout se fait seul^)
echo  (Ctrl+C pour arreter)
echo.

call npm start

pause
endlocal
