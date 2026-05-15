@echo off
REM HoneyPot Setup and Run Script for Windows

setlocal enabledelayedexpansion

echo.
echo ================================
echo  HoneyPot System Management
echo ================================
echo.
echo Available commands:
echo   1. Setup (install dependencies)
echo   2. Start HoneyPot Server
echo   3. Start Dashboard (separate window)
echo   4. Show Status
echo   5. Show Recent Alerts
echo   6. Exit
echo.

:menu
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto setup
if "%choice%"=="2" goto honeypot
if "%choice%"=="3" goto dashboard
if "%choice%"=="4" goto status
if "%choice%"=="5" goto alerts
if "%choice%"=="6" goto exit
if "%choice%"=="" goto menu

echo Invalid choice. Please try again.
goto menu

:setup
echo.
echo Installing dependencies...
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt
echo.
echo Setup complete! You can now run the HoneyPot.
goto menu

:honeypot
echo.
echo Starting HoneyPot Server...
echo Listening on ports 22 (SSH) and 23 (Telnet)
echo Press Ctrl+C to stop
echo.
call venv\Scripts\activate.bat
python honeyPot.py
goto menu

:dashboard
echo.
echo Starting Dashboard in new window...
echo Access at: http://localhost:5000
echo.
start cmd /k "call venv\Scripts\activate.bat && python dashboard.py"
goto menu

:status
echo.
call venv\Scripts\activate.bat
python manage.py status
goto menu

:alerts
echo.
call venv\Scripts\activate.bat
python manage.py alerts --limit 15
goto menu

:exit
echo.
echo Goodbye!
echo.
exit /b 0
