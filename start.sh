#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements.txt
fi

echo "[*] Demo lab: http://127.0.0.1:9999"
./.venv/bin/python demo_lab.py &
LAB_PID=$!
trap 'kill $LAB_PID 2>/dev/null || true' EXIT
sleep 1

echo "[*] Console: http://127.0.0.1:8848"
./.venv/bin/python app.py
