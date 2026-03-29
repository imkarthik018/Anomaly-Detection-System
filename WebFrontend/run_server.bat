@echo off
title Anomaly Detection - Flask (login + CSV)
cd /d "%~dp0"

if not exist "..\.venv\Scripts\python.exe" (
  echo No venv found at ..\.venv\ — create it in the project root: python -m venv .venv
  pause
  exit /b 1
)

echo Starting server. Keep this window OPEN, then open your browser:
echo   http://127.0.0.1:5000/login
echo.
echo Press Ctrl+C here to stop the server.
echo.

"..\.venv\Scripts\python.exe" app.py
pause
