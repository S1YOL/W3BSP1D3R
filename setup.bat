@echo off
REM ──────────────────────────────────────────────
REM W3BSP1D3R — Setup Script (Windows)
REM ──────────────────────────────────────────────

echo.
echo   W3BSP1D3R Setup - by S1YOL
echo   ===========================
echo.

cd /d "%~dp0"

REM Check for Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    where python3 >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [!] Python 3 not found.
        echo     Download from: https://www.python.org/downloads/
        echo     IMPORTANT: Check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

REM Verify Python version
%PYTHON% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Python 3.10 or higher is required.
    %PYTHON% --version
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('%PYTHON% --version') do echo [*] Using %%i

REM Create virtual environment
if not exist "venv" (
    echo [*] Creating virtual environment...
    %PYTHON% -m venv venv
) else (
    echo [*] Virtual environment already exists
)

REM Activate and install
echo [*] Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo.
echo [+] Setup complete!
echo.
echo   Usage:
echo     venv\Scripts\activate.bat
echo     python main.py --url ^<TARGET^> [options]
echo.
echo   Example:
echo     python main.py --url http://localhost/dvwa --login-user admin --login-pass password
echo.
echo   For GUI mode:
echo     pip install streamlit
echo     streamlit run gui.py
echo.
pause
