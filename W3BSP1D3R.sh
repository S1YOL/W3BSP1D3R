#!/usr/bin/env bash
# ================================================================
#  W3BSP1D3R v3.0.0-beta — One-Click Launcher (Linux / macOS)
#  by S1YOL
#
#  Make executable and run:
#    chmod +x W3BSP1D3R.sh
#    ./W3BSP1D3R.sh
#
#  It will auto-install Python dependencies on first run.
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Colours ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Check for Python ----
PYTHON=""
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo ""
    echo -e "${RED}  [ERROR] Python 3 is not installed.${NC}"
    echo ""
    echo "  Install Python 3.10+:"
    echo "    Arch:           sudo pacman -S python"
    echo "    Debian/Ubuntu:  sudo apt install python3 python3-venv python3-pip"
    echo "    Fedora:         sudo dnf install python3"
    echo "    macOS:          brew install python"
    echo "    Or download:    https://www.python.org/downloads/"
    echo ""
    read -rp "  Press Enter to exit..." _
    exit 1
fi

# ---- Verify Python version ----
PY_OK=$($PYTHON -c "import sys; print(1 if sys.version_info >= (3, 10) else 0)" 2>/dev/null || echo 0)
if [ "$PY_OK" != "1" ]; then
    echo ""
    echo -e "${RED}  [ERROR] Python 3.10 or higher is required.${NC}"
    echo -n "  Found: "
    $PYTHON --version 2>&1
    echo ""
    read -rp "  Press Enter to exit..." _
    exit 1
fi

echo ""
echo -e "  ${GREEN}[OK]${NC} Found $($PYTHON --version 2>&1)"

# ---- Auto-setup on first run ----
if [ ! -d "venv" ]; then
    echo ""
    echo -e "${BOLD}  ============================================${NC}"
    echo -e "${BOLD}   W3BSP1D3R — First-Time Setup${NC}"
    echo -e "${BOLD}  ============================================${NC}"
    echo ""
    echo "  Creating virtual environment..."
    if ! $PYTHON -m venv venv; then
        echo ""
        echo -e "${RED}  [ERROR] Failed to create virtual environment.${NC}"
        echo "  On Arch, you may need: sudo pacman -S python"
        echo "  On Debian/Ubuntu: sudo apt install python3-venv"
        echo ""
        read -rp "  Press Enter to exit..." _
        exit 1
    fi
    echo "  Installing dependencies (this may take a minute)..."
    source venv/bin/activate
    pip install --upgrade pip -q 2>/dev/null || true
    if ! pip install -r requirements.txt -q; then
        echo ""
        echo -e "${RED}  [ERROR] Failed to install dependencies.${NC}"
        echo ""
        read -rp "  Press Enter to exit..." _
        exit 1
    fi
    echo ""
    echo -e "  ${GREEN}[OK] Setup complete!${NC}"
    echo ""
    sleep 1
else
    source venv/bin/activate 2>/dev/null || {
        echo -e "${RED}  [ERROR] Failed to activate virtual environment.${NC}"
        echo "  Try deleting the 'venv' folder and running again."
        echo ""
        read -rp "  Press Enter to exit..." _
        exit 1
    }
fi

# ---- Menu loop ----
show_menu() {
    clear 2>/dev/null || true
    echo ""
    echo -e "   ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "        ${BOLD}${RED}W 3 B S P 1 D 3 R${NC}"
    echo ""
    echo -e "   ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "   ${BOLD}App${NC} ····· ${CYAN}W3BSP1D3R${NC}"
    echo -e "   ${BOLD}Type${NC} ···· ${CYAN}Web Vulnerability Scanner${NC}"
    echo -e "   ${BOLD}Version${NC} · ${RED}v3.0.0-beta${NC}"
    echo -e "   ${BOLD}Build${NC} ··· ${CYAN}S1YOL${NC}"
    echo ""
    echo -e "   ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "   ${CYAN}[1]${NC} Quick Scan          ${BOLD}(full scan)${NC}"
    echo -e "   ${CYAN}[2]${NC} SQLi-Only Scan      ${BOLD}(SQL injection)${NC}"
    echo -e "   ${CYAN}[3]${NC} XSS-Only Scan       ${BOLD}(cross-site scripting)${NC}"
    echo -e "   ${CYAN}[4]${NC} Passive Scan        ${BOLD}(no attack payloads)${NC}"
    echo -e "   ${CYAN}[5]${NC} Authenticated Scan  ${BOLD}(login + full scan)${NC}"
    echo -e "   ${CYAN}[6]${NC} Custom Command      ${BOLD}(your own args)${NC}"
    echo -e "   ${CYAN}[7]${NC} Start GUI           ${BOLD}(web interface)${NC}"
    echo -e "   ${CYAN}[0]${NC} Exit"
    echo ""
    echo -e "   ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

pause_prompt() {
    echo ""
    read -rp "  Press Enter to return to menu..." _
}

while true; do
    show_menu
    read -rp "  Select an option: " CHOICE

    case "$CHOICE" in
        1)
            echo ""
            read -rp "  Enter target URL (e.g. http://localhost/dvwa): " TARGET_URL
            if [ -z "$TARGET_URL" ]; then
                echo -e "  ${RED}[!] URL cannot be empty.${NC}"
                pause_prompt
                continue
            fi
            echo ""
            echo "  Starting full scan against $TARGET_URL..."
            echo "  ================================================"
            echo ""
            python main.py --url "$TARGET_URL" --scan-type full --output reports/scan_report || true
            echo ""
            echo "  ================================================"
            echo -e "  ${GREEN}Scan complete! Check the \"reports\" folder for results.${NC}"
            pause_prompt
            ;;
        2)
            echo ""
            read -rp "  Enter target URL: " TARGET_URL
            if [ -z "$TARGET_URL" ]; then
                echo -e "  ${RED}[!] URL cannot be empty.${NC}"
                pause_prompt
                continue
            fi
            echo ""
            python main.py --url "$TARGET_URL" --scan-type sqli --output reports/sqli_report || true
            echo ""
            echo -e "  ${GREEN}Scan complete! Check the \"reports\" folder.${NC}"
            pause_prompt
            ;;
        3)
            echo ""
            read -rp "  Enter target URL: " TARGET_URL
            if [ -z "$TARGET_URL" ]; then
                echo -e "  ${RED}[!] URL cannot be empty.${NC}"
                pause_prompt
                continue
            fi
            echo ""
            python main.py --url "$TARGET_URL" --scan-type xss --output reports/xss_report || true
            echo ""
            echo -e "  ${GREEN}Scan complete! Check the \"reports\" folder.${NC}"
            pause_prompt
            ;;
        4)
            echo ""
            read -rp "  Enter target URL: " TARGET_URL
            if [ -z "$TARGET_URL" ]; then
                echo -e "  ${RED}[!] URL cannot be empty.${NC}"
                pause_prompt
                continue
            fi
            echo ""
            python main.py --url "$TARGET_URL" --scan-type passive --output reports/passive_report || true
            echo ""
            echo -e "  ${GREEN}Scan complete! Check the \"reports\" folder.${NC}"
            pause_prompt
            ;;
        5)
            echo ""
            read -rp "  Enter target URL: " TARGET_URL
            read -rp "  Enter username: " LOGIN_USER
            read -rsp "  Enter password: " LOGIN_PASS
            echo ""
            if [ -z "$TARGET_URL" ]; then
                echo -e "  ${RED}[!] URL cannot be empty.${NC}"
                pause_prompt
                continue
            fi
            echo ""
            python main.py --url "$TARGET_URL" --login-user "$LOGIN_USER" --login-pass "$LOGIN_PASS" --scan-type full --output reports/auth_scan_report || true
            echo ""
            echo -e "  ${GREEN}Scan complete! Check the \"reports\" folder.${NC}"
            pause_prompt
            ;;
        6)
            echo ""
            echo "  Type your arguments after \"python main.py\":"
            echo "  Example: --url http://target.com --scan-type xss --threads 8"
            echo ""
            read -rp "  python main.py " CUSTOM_ARGS
            echo ""
            eval python main.py $CUSTOM_ARGS || true
            pause_prompt
            ;;
        7)
            echo ""
            echo "  Checking for Streamlit..."
            pip show streamlit &>/dev/null || {
                echo "  Installing Streamlit (first time only)..."
                pip install streamlit -q || true
            }
            echo "  Launching GUI in your browser..."
            echo "  (Press Ctrl+C to stop the GUI)"
            echo ""
            streamlit run gui.py || true
            pause_prompt
            ;;
        0)
            echo ""
            echo "  Goodbye!"
            echo ""
            exit 0
            ;;
        *)
            echo -e "  ${RED}Invalid choice. Try again.${NC}"
            sleep 1
            ;;
    esac
done
