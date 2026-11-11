@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [*] Creating virtual environment...
  python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)

echo [*] Starting demo lab on http://127.0.0.1:9999
start "SecLab Demo Lab" ".venv\Scripts\python.exe" demo_lab.py

echo [*] Starting console on http://127.0.0.1:8848
start "" http://127.0.0.1:8848
".venv\Scripts\python.exe" app.py
