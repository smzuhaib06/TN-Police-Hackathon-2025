@echo off
REM TOR Unveil - Start Backend with Administrator Privileges
REM This is required for packet capture to work like Wireshark

echo ================================================
echo TOR Unveil - Starting Backend with Admin Rights
echo ================================================
echo.
echo IMPORTANT: Packet capture requires Administrator privileges
echo This will open a UAC prompt - click "Yes" to continue
echo.
pause

REM Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Already running as Administrator
    goto :runbackend
)

REM Request admin privileges
echo Requesting Administrator privileges...
powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:runbackend
echo.
echo Starting backend server on port 5000...
echo.

REM Activate virtual environment and run backend
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python backend\working_backend.py

pause
