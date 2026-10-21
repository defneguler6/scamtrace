#!/bin/bash
# One-time setup on macOS. Run from the scamtrace folder:  bash setup_mac.sh
set -e
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
python -m playwright install chromium
[ -f .env ] || cp .env.example .env
echo ""
echo "Done. Add your ANTHROPIC_API_KEY to .env, then try:  python demo/run_demo.py"
