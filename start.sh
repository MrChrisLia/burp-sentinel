#!/usr/bin/env bash
# Sentinel backend launcher. No venv activation needed — uses the venv's
# uvicorn directly. Press Ctrl+C to stop.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "No .env found — run ./install.sh first."
  exit 1
fi
if [ ! -x .venv/bin/uvicorn ]; then
  echo "Virtual environment not installed — run ./install.sh first."
  exit 1
fi

echo "Starting Sentinel backend on http://localhost:8000  (Ctrl+C to stop)"
exec .venv/bin/uvicorn sentinel_api.main:app --host 0.0.0.0 --port 8000
