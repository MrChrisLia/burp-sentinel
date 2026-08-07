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

PROVIDER=$(grep -E '^SENTINEL_PROVIDER=' .env | tail -1 | cut -d= -f2)
APIKEY=$(grep -E '^SENTINEL_API_KEY=' .env | tail -1 | cut -d= -f2)
if [ "$PROVIDER" = "mock" ]; then
  echo ">> Note: running in MOCK mode (SENTINEL_PROVIDER=mock)."
  echo "   Chat returns fake answers. For real AI responses, set"
  echo "   SENTINEL_PROVIDER=openai_compatible + SENTINEL_API_KEY in .env and restart."
elif [ -z "$APIKEY" ]; then
  echo ">> Warning: SENTINEL_API_KEY is empty in .env — chat will fail until you set it."
  echo "   (Or set SENTINEL_PROVIDER=mock to test offline.)"
fi

echo "Starting Sentinel backend on http://localhost:8000  (Ctrl+C to stop)"
exec .venv/bin/uvicorn sentinel_api.main:app --host 0.0.0.0 --port 8000
