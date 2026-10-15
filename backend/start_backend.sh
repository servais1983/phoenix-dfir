#!/bin/bash

# Phoenix DFIR backend startup script

echo "Phoenix DFIR - Backend startup"
echo "====================================="

# Check that Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    exit 1
fi

# Create a virtual environment if missing
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
pip install -r requirements-optional.txt || echo "WARNING: optional dependencies skipped (python-evtx/hexdump)"

# Create required folders
echo "Creating folders..."
mkdir -p uploads sessions reports logs

# Start the application
echo "Starting Flask server..."
echo "Backend available at: http://localhost:5000"
echo "API Health Check: http://localhost:5000/api/health"
echo "====================================="

python app.py
