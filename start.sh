#!/usr/bin/env bash
# ============================================================
#  Phoenix DFIR - Lanceur Linux / macOS
#  Usage : ./start.sh
#  Prerequis : Python 3.10+ et Node.js 20+
# ============================================================
set -e
cd "$(dirname "$0")"

echo ""
echo " ============================================"
echo "  Phoenix DFIR - Demarrage"
echo " ============================================"
echo ""

if ! command -v node >/dev/null 2>&1; then
    echo " [ERREUR] Node.js est introuvable."
    echo " Installez Node.js 20+ : https://nodejs.org"
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
    else
        echo " [ERREUR] Python est introuvable."
        echo " Installez Python 3.10+ : https://python.org"
        exit 1
    fi
fi
echo " Python : $($PYTHON_CMD --version) | Node : $(node --version)"

if [ ! -d node_modules ]; then
    echo " [SETUP] Installation des dependances frontend..."
    npm install --no-audit --no-fund
fi

if [ ! -d backend/venv ]; then
    echo " [SETUP] Configuration de l'environnement Python..."
    node scripts/setup-backend.js
fi

echo ""
echo " Frontend : http://localhost:5173"
echo " Backend  : http://localhost:5000"
echo " (Ctrl+C pour arreter)"
echo ""

npm start
