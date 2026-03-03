@echo off
echo ========================================
echo    AI Cybersecurity Suite Setup
echo ========================================
echo.

:: Check Python
python --version
if errorlevel 1 (
    echo Error: Python not found!
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

:: Create virtual environment
echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo Error creating virtual environment!
    pause
    exit /b 1
)

:: Activate venv
echo Activating virtual environment...
call venv\Scripts\activate

:: Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

:: Install requirements
echo Installing dependencies...
pip install -r requirements_minimal.txt
if errorlevel 1 (
    echo Error installing dependencies!
    echo Trying alternative method...
    pip install Flask==2.3.3
    pip install requests==2.31.0
)

:: Create directories
echo Creating directories...
mkdir static 2>nul
mkdir templates 2>nul

echo.
echo ========================================
echo    SETUP COMPLETE!
echo ========================================
echo.
echo To run the application:
echo 1. Activate virtual environment: venv\Scripts\activate
echo 2. Run: python app.py
echo 3. Open browser: http://localhost:5000
echo.
echo Press any key to continue...
pause >nul