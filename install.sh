#!/usr/bin/env bash
# Sentinel one-shot installer: creates the venv, installs dependencies,
# prepares .env. Idempotent — safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"

echo "== Burp Sentinel installer =="

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install it first, e.g.:"
  echo "  sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi

if [ ! -d .venv ]; then
  echo ">> Creating virtual environment (.venv)..."
  python3 -m venv .venv
else
  echo ">> Virtual environment already exists, reusing it."
fi

echo ">> Installing Python dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo ">> Created .env from .env.example"
  echo "   IMPORTANT: open .env and set SENTINEL_API_KEY to your LLM provider key"
  echo "   (or keep SENTINEL_PROVIDER=mock to test without a key)."
else
  echo ">> .env already exists, leaving it untouched."
fi

JAR=$(ls releases/*.jar 2>/dev/null | head -1 || true)
echo
echo "Installation complete!"
echo
echo "Next steps:"
echo "  1. Start the backend:        ./start.sh"
echo "  2. Load the extension in Burp:"
echo "     Burp -> Extensions -> Installed -> Add -> Type: Java"
if [ -n "$JAR" ]; then
  echo "     Select: $(pwd)/$JAR"
else
  echo "     Select: releases/burp-sentinel-*.jar"
fi
echo "  3. Open the 'Sentinel Insights' tab and set 'Sentinel Backend' to"
echo "     http://localhost:8000"
