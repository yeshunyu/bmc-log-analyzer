#!/bin/sh
# Load env vars from /app/.env if it exists
if [ -f /app/.env ]; then
    set -a
    . /app/.env
    set +a
fi
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
