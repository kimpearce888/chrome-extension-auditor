@echo off
REM Local Chrome Extension Auditor - Diagnostics (135)
setlocal
cd /d "%~dp0"
echo.
echo === Local Chrome Extension Auditor - Diagnostics ===
echo.
native\scanner.exe --diagnose
echo.
pause
