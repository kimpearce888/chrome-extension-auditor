@echo off
REM Local Chrome Extension Auditor - Uninstaller launcher (134)
setlocal
cd /d "%~dp0"
echo.
echo === Local Chrome Extension Auditor - Uninstall ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "installer\uninstall.ps1" -PackageDir "%cd%"
echo.
pause
