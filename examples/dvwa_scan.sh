#!/usr/bin/env bash
# =============================================================================
# examples/dvwa_scan.sh
# Example scan commands for DVWA (Damn Vulnerable Web Application)
# and OWASP Juice Shop running in Docker.
#
# Prerequisites:
#   docker compose up -d   (from project root with docker-compose.yml)
#   pip install -r requirements.txt
# =============================================================================

set -euo pipefail

SCANNER="python main.py"
REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"

echo "================================================================"
echo "  W3BSP1D3R — Example Scan Commands  |  by S1YOL"
echo "  ⚠️  AUTHORISED TESTING ONLY — DVWA / Juice Shop in Docker"
echo "================================================================"
echo ""

# -----------------------------------------------------------------------------
# 1. Full authenticated scan against DVWA
# -----------------------------------------------------------------------------
echo "[1/4] Full authenticated scan against DVWA..."
$SCANNER \
  --url http://localhost:80/dvwa \
  --login-user admin \
  --login-pass password \
  --scan-type full \
  --max-pages 30 \
  --delay 0.3 \
  --output "$REPORTS_DIR/dvwa_full_scan"

echo ""

# -----------------------------------------------------------------------------
# 2. SQLi-only scan against DVWA
# -----------------------------------------------------------------------------
echo "[2/4] SQLi-only scan against DVWA..."
$SCANNER \
  --url http://localhost:80/dvwa \
  --login-user admin \
  --login-pass password \
  --scan-type sqli \
  --output "$REPORTS_DIR/dvwa_sqli"

echo ""

# -----------------------------------------------------------------------------
# 3. XSS scan against DVWA
# -----------------------------------------------------------------------------
echo "[3/4] XSS scan against DVWA..."
$SCANNER \
  --url http://localhost:80/dvwa \
  --login-user admin \
  --login-pass password \
  --scan-type xss \
  --output "$REPORTS_DIR/dvwa_xss"

echo ""

# -----------------------------------------------------------------------------
# 4. Unauthenticated scan against OWASP Juice Shop
# -----------------------------------------------------------------------------
echo "[4/4] Unauthenticated scan against Juice Shop..."
$SCANNER \
  --url http://localhost:3000 \
  --scan-type full \
  --max-pages 20 \
  --output "$REPORTS_DIR/juiceshop_scan"

echo ""
echo "================================================================"
echo "  W3BSP1D3R — All scans complete! Reports saved to: $REPORTS_DIR/"
echo "  Open the .html files in your browser for full reports."
echo "================================================================"
