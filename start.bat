@echo off
setlocal EnableDelayedExpansion
title Aegix Share — Local Server

echo ============================================================
echo   Aegix Share — End-to-End Encrypted File Sharing
echo ============================================================
echo.

REM ─── Detect the machine's best LAN IP ────────────────────────────────────────
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /r /c:"IPv4 Address"') do (
    set "_IP=%%a"
    set "_IP=!_IP: =!"
    REM Skip loopback
    if not "!_IP!"=="127.0.0.1" (
        if not defined LAN_IP set "LAN_IP=!_IP!"
    )
)
if not defined LAN_IP set "LAN_IP=127.0.0.1"

REM ─── Run Django migrations ────────────────────────────────────────────────────
echo [1/3] Applying database migrations...
python manage.py migrate --noinput
if errorlevel 1 (
    echo ERROR: Migration failed. Make sure Python and Django are installed.
    pause
    exit /b 1
)

REM ─── Collect static files ────────────────────────────────────────────────────
echo [2/3] Collecting static files...
python manage.py collectstatic --noinput --clear >nul 2>&1

REM ─── Start the server on all interfaces ──────────────────────────────────────
echo [3/3] Starting server...
echo.
echo ============================================================
echo   Access URLs:
echo     Local:  http://localhost:8000
echo     LAN:    http://%LAN_IP%:8000
echo.
echo   Scan the QR code from any device on the same WiFi.
echo   Press Ctrl+C to stop the server.
echo ============================================================
echo.

python manage.py runserver 0.0.0.0:8000
