@echo off
REM Local Chrome Extension Auditor - Installer launcher (131)
REM Registers the native messaging host for the current user (no elevation).
setlocal
cd /d "%~dp0"
echo.
echo === Local Chrome Extension Auditor - Install ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "installer\install.ps1" -PackageDir "%cd%"
echo.
pause
