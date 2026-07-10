@echo off
:: Aegix Share — One-time Firewall Setup
:: Run this once as Administrator to allow mobile devices on your WiFi to connect.
echo.
echo ======================================================
echo   Aegix Share — Windows Firewall Setup (Admin needed)
echo ======================================================
echo.

:: Remove old rule if it exists
netsh advfirewall firewall delete rule name="Aegix Port 8000" >nul 2>&1

:: Add inbound TCP rule for port 8000
netsh advfirewall firewall add rule ^
  name="Aegix Port 8000" ^
  protocol=TCP ^
  dir=in ^
  localport=8000 ^
  action=allow ^
  description="Allows mobile devices on the same WiFi to reach the Aegix Share server"

if %errorlevel% == 0 (
  echo [OK] Firewall rule added. Mobile devices on your WiFi can now connect!
) else (
  echo [FAIL] Could not add firewall rule. Make sure you ran this as Administrator.
)
echo.
pause
