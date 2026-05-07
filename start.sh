#!/bin/bash
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies..."
pip install -q -r requirements.txt

echo "Starting BMC Log Analyzer..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
