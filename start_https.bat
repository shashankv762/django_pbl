@echo off
setlocal EnableDelayedExpansion
title Aegix Share — HTTPS Server

echo ============================================================
echo   Aegix Share — HTTPS Mode (Secure File Sharing)
echo ============================================================
echo.

REM ─── Detect the machine's best LAN IP ────────────────────────────────────────
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /r /c:"IPv4 Address"') do (
    set "_IP=%%a"
    set "_IP=!_IP: =!"
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

REM ─── Collect static files ─────────────────────────────────────────────────────
echo [2/3] Collecting static files...
python manage.py collectstatic --noinput --clear >nul 2>&1

REM ─── Start HTTPS server ───────────────────────────────────────────────────────
echo [3/3] Starting HTTPS server...
echo.
echo ============================================================
echo   HTTPS Access URLs:
echo     Local:  https://localhost:8443
echo     LAN:    https://%LAN_IP%:8443
echo.
echo   FIRST TIME ON MOBILE:
echo     1. Open https://%LAN_IP%:8443 in your mobile browser
echo     2. Tap "Advanced" then "Proceed to site" (Chrome)
echo        OR "Show Details" then "visit this website" (Safari)
echo     3. File downloads and camera scanner will now work!
echo.
echo   Press Ctrl+C to stop the server.
echo ============================================================
echo.

python manage.py runssl 0.0.0.0:8443
