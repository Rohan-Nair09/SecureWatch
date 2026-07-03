@echo off
setlocal

echo ===================================================
echo     SecureWatch - Production Server Startup
echo ===================================================
echo.

:: Check if virtual environment exists
if not exist "venv\Scripts\activate.bat" (
    echo [!] Virtual environment not found. Creating one...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment. Ensure python is in your PATH.
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

:: Install requirements
echo [*] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

:: Check for .env file, if not present copy from .env.example
if not exist ".env" (
    if exist ".env.example" (
        echo [*] .env file not found. Creating default from .env.example...
        copy .env.example .env
        echo [!] Please update the SECRET_KEY in the .env file later for better security!
    )
)

:: Start the application with waitress
echo [*] Starting the server using Waitress WSGI...
python wsgi.py

endlocal
