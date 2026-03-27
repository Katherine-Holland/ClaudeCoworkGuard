#!/bin/bash
# CoworkGuard — Start
# © 2026 Katherine Holland. MIT + Commons Clause.

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🛡️  Starting CoworkGuard...${NC}"
echo ""

# ── Check if already running ──────────────────────────────────────────
if lsof -i :8080 &>/dev/null; then
  echo -e "${YELLOW}⚠ Something is already running on port 8080.${NC}"
  echo "  Stop it first or CoworkGuard may not work correctly."
  echo ""
fi

# ── Start mitmproxy ───────────────────────────────────────────────────
echo -e "${CYAN}→ Starting proxy scanner...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$INSTALL_DIR' && mitmproxy -s proxy.py --listen-port 8080\"" &>/dev/null
sleep 2
echo -e "${GREEN}✓ Proxy scanner running on port 8080${NC}"

# ── Start dashboard server ────────────────────────────────────────────
echo -e "${CYAN}→ Starting dashboard server...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$INSTALL_DIR' && python3 server.py\"" &>/dev/null
sleep 2
echo -e "${GREEN}✓ Dashboard server running at http://localhost:7070${NC}"

# ── Trust certificate if needed ───────────────────────────────────────
CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ -f "$CERT" ]; then
  # Check if already trusted
  if ! security verify-cert -c "$CERT" &>/dev/null; then
    echo ""
    echo -e "${YELLOW}⚠ One-time certificate setup required:${NC}"
    open "$CERT"
    echo ""
    echo "  Keychain Access has opened. Please:"
    echo "  1. Double-click the mitmproxy certificate"
    echo "  2. Expand Trust"
    echo "  3. Set 'When using this certificate' to Always Trust"
    echo "  4. Close and enter your Mac password"
    echo ""
    read -p "  Press Enter once you have trusted the certificate..."
  fi
fi

# ── Set system proxy ──────────────────────────────────────────────────
echo ""
echo -e "${CYAN}→ Enabling system proxy...${NC}"

# Get active network service
NETWORK_SERVICE=$(networksetup -listallnetworkservices | grep -v "^\*" | grep -E "Wi-Fi|Ethernet|USB" | head -1)

if [ -z "$NETWORK_SERVICE" ]; then
  NETWORK_SERVICE="Wi-Fi"
fi

networksetup -setwebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setsecurewebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setwebproxystate "$NETWORK_SERVICE" on
networksetup -setsecurewebproxystate "$NETWORK_SERVICE" on

echo -e "${GREEN}✓ System proxy enabled on $NETWORK_SERVICE${NC}"

# ── Open dashboard ────────────────────────────────────────────────────
sleep 1
echo -e "${CYAN}→ Opening dashboard...${NC}"
open "http://localhost:7070"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard is running${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:7070${NC}"
echo -e "  Proxy:      ${CYAN}localhost:8080${NC}"
echo ""
echo -e "  ${YELLOW}${BOLD}Important:${NC} Run ${CYAN}./stop.sh${NC} when you are done."
echo "  This turns off the proxy and restores your normal internet."
echo ""
