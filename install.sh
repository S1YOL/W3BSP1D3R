#!/usr/bin/env bash
# ================================================================
#  W3BSP1D3R — Linux One-Time Installer
#
#  Run this ONCE. It will:
#    1. Add W3BSP1D3R to your app menu (search it like any app)
#    2. Set up Python dependencies
#    3. Launch the scanner immediately
#
#  After this, just click W3BSP1D3R in your app menu. Done.
#
#  One-liner:
#    chmod +x install.sh && ./install.sh
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="$SCRIPT_DIR/W3BSP1D3R.sh"
DESKTOP_DIR="$HOME/.local/share/applications"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${RED}${BOLD}  W3BSP1D3R — Installer${NC}"
echo -e "  ====================="
echo ""

# ---- Check launcher exists ----
if [ ! -f "$LAUNCHER" ]; then
    echo -e "  ${RED}[ERROR]${NC} W3BSP1D3R.sh not found."
    echo "  Make sure you run this from inside the extracted W3BSP1D3R folder."
    read -rp "  Press Enter to exit..." _
    exit 1
fi

# ---- Make scripts executable ----
chmod +x "$LAUNCHER"
chmod +x "$SCRIPT_DIR/setup.sh" 2>/dev/null || true
echo -e "  ${GREEN}[1/3]${NC} Scripts are ready"

# ---- Create desktop entry (app menu shortcut) ----
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/w3bsp1d3r.desktop" << DESKTOP_EOF
[Desktop Entry]
Name=W3BSP1D3R
Comment=Web Vulnerability Scanner v3.0.0-beta by S1YOL
Exec=bash -c 'cd "$SCRIPT_DIR" && ./W3BSP1D3R.sh'
Terminal=true
Type=Application
Categories=Security;Development;System;
StartupNotify=true
DESKTOP_EOF
chmod +x "$DESKTOP_DIR/w3bsp1d3r.desktop"

# Update desktop database if available (makes it show up faster)
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo -e "  ${GREEN}[2/3]${NC} Added to your app menu"

# ---- Done ----
echo -e "  ${GREEN}[3/3]${NC} Installation complete!"
echo ""
echo -e "  ${BOLD}From now on, just search '${RED}W3BSP1D3R${NC}${BOLD}' in your app menu.${NC}"
echo -e "  No terminal needed — it opens like any other app."
echo ""
echo -e "  ${CYAN}To uninstall:${NC} rm ~/.local/share/applications/w3bsp1d3r.desktop"
echo ""
echo -e "  ${BOLD}Launching W3BSP1D3R now...${NC}"
echo ""
sleep 2

# ---- Launch the app ----
exec "$LAUNCHER"
