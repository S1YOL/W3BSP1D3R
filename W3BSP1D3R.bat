@echo off
REM ================================================================
REM  W3BSP1D3R v3.0.0-beta — One-Click Launcher (Windows)
REM  by S1YOL
REM
REM  Double-click this file to run W3BSP1D3R.
REM  It will auto-install Python dependencies on first run.
REM ================================================================
title W3BSP1D3R v3.0.0-beta — Web Vulnerability Scanner
color 0C
cd /d "%~dp0"

REM ---- Check for Python ----
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    where python3 >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo.
        echo  [ERROR] Python 3 is not installed or not in PATH.
        echo.
        echo  Download Python from: https://www.python.org/downloads/
        echo  IMPORTANT: Check "Add Python to PATH" during installation.
        echo.
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

REM ---- Verify Python version ----
%PYTHON% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Python 3.10 or higher is required.
    %PYTHON% --version
    echo.
    pause
    exit /b 1
)

REM ---- Auto-setup on first run ----
if not exist "venv" (
    echo.
    echo  ============================================
    echo   W3BSP1D3R — First-Time Setup
    echo  ============================================
    echo.
    echo  Setting up virtual environment...
    %PYTHON% -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  Installing dependencies (this may take a minute)...
    call venv\Scripts\activate.bat
    pip install --upgrade pip -q 2>nul
    pip install -r requirements.txt -q
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    echo.
    echo  [OK] Setup complete!
    echo.
) else (
    call venv\Scripts\activate.bat
)

:MENU
cls
echo.
echo.
echo   =========================================================
echo.
echo     W   W  333  BBB   SSS  PPP  1  DDD  333  RRR
echo     W   W    3  B  B S     P  P 1  D  D   3  R  R
echo     W W W  33   BBB   SS   PPP  1  D  D  33  RRR
echo     WW WW    3  B  B    S  P    1  D  D    3  R R
echo     W   W  333  BBB  SSS   P    1  DDD  333  R  R
echo.
echo   =========================================================
echo.
echo     App       W3BSP1D3R - Web Vulnerability Scanner
echo     Version   v3.0.0-beta
echo     Build     S1YOL
echo.
echo   =========================================================
echo.
echo   ---------------------------------------------------------
echo.
echo   [1] Quick Scan          (enter a URL, run full scan)
echo   [2] SQLi-Only Scan      (SQL injection testing only)
echo   [3] XSS-Only Scan       (cross-site scripting only)
echo   [4] Passive Scan        (no attack payloads sent)
echo   [5] Authenticated Scan  (login first, then scan)
echo   [6] Custom Command      (type your own arguments)
echo   [7] Start GUI           (opens Streamlit web UI)
echo   [8] Build Standalone EXE (create portable .exe)
echo   [0] Exit
echo.
echo   ---------------------------------------------------------
echo.
set /p CHOICE="  Select an option: "

if "%CHOICE%"=="1" goto QUICK
if "%CHOICE%"=="2" goto SQLI
if "%CHOICE%"=="3" goto XSS
if "%CHOICE%"=="4" goto PASSIVE
if "%CHOICE%"=="5" goto AUTH
if "%CHOICE%"=="6" goto CUSTOM
if "%CHOICE%"=="7" goto GUI
if "%CHOICE%"=="8" goto BUILD_EXE
if "%CHOICE%"=="0" goto EXIT
echo  Invalid choice. Try again.
timeout /t 2 >nul
goto MENU

:QUICK
echo.
set /p TARGET_URL="  Enter target URL (e.g. http://localhost/dvwa): "
if "%TARGET_URL%"=="" (
    echo  [!] URL cannot be empty.
    pause
    goto MENU
)
echo.
echo  Starting full scan against %TARGET_URL%...
echo  ================================================
echo.
python main.py --url "%TARGET_URL%" --scan-type full --output reports\scan_report
echo.
echo  ================================================
echo  Scan complete! Check the "reports" folder for results.
echo.
pause
goto MENU

:SQLI
echo.
set /p TARGET_URL="  Enter target URL: "
if "%TARGET_URL%"=="" (
    echo  [!] URL cannot be empty.
    pause
    goto MENU
)
echo.
python main.py --url "%TARGET_URL%" --scan-type sqli --output reports\sqli_report
echo.
echo  Scan complete! Check the "reports" folder.
pause
goto MENU

:XSS
echo.
set /p TARGET_URL="  Enter target URL: "
if "%TARGET_URL%"=="" (
    echo  [!] URL cannot be empty.
    pause
    goto MENU
)
echo.
python main.py --url "%TARGET_URL%" --scan-type xss --output reports\xss_report
echo.
echo  Scan complete! Check the "reports" folder.
pause
goto MENU

:PASSIVE
echo.
set /p TARGET_URL="  Enter target URL: "
if "%TARGET_URL%"=="" (
    echo  [!] URL cannot be empty.
    pause
    goto MENU
)
echo.
python main.py --url "%TARGET_URL%" --scan-type passive --output reports\passive_report
echo.
echo  Scan complete! Check the "reports" folder.
pause
goto MENU

:AUTH
echo.
set /p TARGET_URL="  Enter target URL: "
set /p LOGIN_USER="  Enter username: "
set /p LOGIN_PASS="  Enter password: "
if "%TARGET_URL%"=="" (
    echo  [!] URL cannot be empty.
    pause
    goto MENU
)
echo.
python main.py --url "%TARGET_URL%" --login-user "%LOGIN_USER%" --login-pass "%LOGIN_PASS%" --scan-type full --output reports\auth_scan_report
echo.
echo  Scan complete! Check the "reports" folder.
pause
goto MENU

:CUSTOM
echo.
echo  Type your arguments after "python main.py":
echo  Example: --url http://target.com --scan-type xss --threads 8
echo.
set /p CUSTOM_ARGS="  python main.py "
echo.
python main.py %CUSTOM_ARGS%
echo.
pause
goto MENU

:GUI
echo.
echo  Checking for Streamlit...
pip show streamlit >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  Installing Streamlit (first time only)...
    pip install streamlit -q
)
echo  Launching GUI in your browser...
echo  (Press Ctrl+C in this window to stop the GUI)
echo.
streamlit run gui.py
pause
goto MENU

:BUILD_EXE
echo.
echo  Installing PyInstaller...
pip install pyinstaller -q
echo  Building standalone executable...
echo  (This may take a few minutes)
echo.
pyinstaller --noconfirm --onefile --console --name W3BSP1D3R ^
    --add-data "scanner;scanner" ^
    --add-data "requirements.txt;." ^
    --hidden-import scanner.testers.sqli ^
    --hidden-import scanner.testers.xss ^
    --hidden-import scanner.testers.csrf ^
    --hidden-import scanner.testers.cmdi ^
    --hidden-import scanner.testers.ssti ^
    --hidden-import scanner.testers.nosql_injection ^
    --hidden-import scanner.testers.path_traversal ^
    --hidden-import scanner.testers.open_redirect ^
    --hidden-import scanner.testers.idor ^
    --hidden-import scanner.testers.headers ^
    --hidden-import scanner.testers.cookie_security ^
    --hidden-import scanner.testers.cors ^
    --hidden-import scanner.testers.ssl_tls ^
    --hidden-import scanner.testers.waf ^
    --hidden-import scanner.testers.subdomain ^
    --hidden-import scanner.testers.cve ^
    --hidden-import scanner.testers.sensitive_files ^
    --hidden-import scanner.reporting.html_report ^
    --hidden-import scanner.reporting.json_report ^
    --hidden-import scanner.reporting.markdown_report ^
    --hidden-import scanner.reporting.sarif_report ^
    --hidden-import scanner.reporting.pdf_report ^
    --hidden-import scanner.reporting.diff_report ^
    --hidden-import scanner.utils.display ^
    --hidden-import scanner.utils.http ^
    --hidden-import scanner.utils.http_async ^
    --hidden-import scanner.utils.logging_config ^
    --hidden-import scanner.config ^
    --hidden-import scanner.auth ^
    --hidden-import scanner.auth_enterprise ^
    --hidden-import scanner.crawler ^
    --hidden-import scanner.checkpoint ^
    --hidden-import scanner.db ^
    --hidden-import scanner.plugins ^
    --hidden-import scanner.payloads ^
    --hidden-import scanner.scheduler ^
    --hidden-import scanner.webhooks ^
    --hidden-import scanner.virustotal ^
    --hidden-import scanner.audit ^
    --hidden-import scanner.api ^
    main.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Build failed. Check the output above for details.
    pause
    goto MENU
)
echo.
echo  ================================================
echo  [OK] Build complete!
echo.
echo  Your standalone executable is at:
echo    dist\W3BSP1D3R.exe
echo.
echo  You can copy W3BSP1D3R.exe anywhere and run it
echo  without needing Python installed!
echo.
echo  Usage: W3BSP1D3R.exe --url http://target.com
echo  ================================================
echo.
pause
goto MENU

:EXIT
echo.
echo  Goodbye!
echo.
exit /b 0
