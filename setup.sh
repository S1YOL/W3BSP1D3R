#!/usr/bin/env bash
# ──────────────────────────────────────────────
# W3BSP1D3R — Setup Script (macOS / Linux)
# ──────────────────────────────────────────────
set -e

echo ""
echo "  ╦ ╦╔═╗╔╗ ╔═╗╔═╗╦╔╦╗╔═╗╦═╗"
echo "  ║║║╠═╣╠╩╗╚═╗╠═╝║ ║║║╣ ╠╦╝"
echo "  ╚╩╝╩ ╩╚═╝╚═╝╩  ╩═╩╝╚═╝╩╚═  Setup"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python 3.8+
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "[!] Python 3 not found. Install Python 3.10+ from https://www.python.org"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "[!] Python 3.10+ required (found $PY_VERSION)"
    exit 1
fi

echo "[*] Using $PYTHON ($PY_VERSION)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    $PYTHON -m venv venv
else
    echo "[*] Virtual environment already exists"
fi

# Activate and install
echo "[*] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "[+] Setup complete!"
echo ""
echo "  Usage:"
echo "    source venv/bin/activate"
echo "    python main.py --url <TARGET> [options]"
echo ""
echo "  Example:"
echo "    python main.py --url http://localhost/dvwa --login-user admin --login-pass password"
echo ""
echo "  For GUI mode:"
echo "    pip install streamlit"
echo "    streamlit run gui.py"
echo ""
