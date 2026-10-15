#!/usr/bin/env bash
# ============================================================
#  Phoenix DFIR - Linux / macOS launcher
#  Usage: ./start.sh
#  Requirements: Python 3.10+ and Node.js 20+
# ============================================================
set -e
cd "$(dirname "$0")"

echo ""
echo " ============================================"
echo "  Phoenix DFIR - Startup"
echo " ============================================"
echo ""

if ! command -v node >/dev/null 2>&1; then
    echo " [ERROR] Node.js not found."
    echo " Install Node.js 20+: https://nodejs.org"
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
    else
        echo " [ERROR] Python not found."
        echo " Install Python 3.10+: https://python.org"
        exit 1
    fi
fi
echo " Python: $($PYTHON_CMD --version) | Node: $(node --version)"

if [ ! -d node_modules ]; then
    echo " [SETUP] Installing frontend dependencies..."
    npm install --no-audit --no-fund
fi

if [ ! -d backend/venv ]; then
    echo " [SETUP] Setting up the Python environment..."
    node scripts/setup-backend.js
fi

echo ""
echo " Frontend : http://localhost:5173"
echo " Backend  : http://localhost:5000"
if [ -n "${GITHUB_TOKEN:-}" ] || [ -n "${PHOENIX_GITHUB_TOKEN:-}" ]; then
    echo " AI investigator: GitHub Copilot configured"
else
    echo " AI investigator: set GITHUB_TOKEN to enable it"
    echo "                  (GitHub token, \"Models: read\" permission)"
fi
echo " Auto drop folder: backend/evidence_inbox (drop evidence files, processing is automatic)"
echo " (Ctrl+C to stop)"
echo ""

npm start
