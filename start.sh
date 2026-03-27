#!/bin/bash
# CoworkGuard — Start
# © 2026 Katherine Holland. MIT + Commons Clause.

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CERT_PEM="$HOME/.coworkguard/coworkguard-ca-cert.pem"

echo ""
echo -e "${BOLD}🛡️  Starting CoworkGuard...${NC}"
echo ""

# ── Check install has been run ────────────────────────────────────────
if [ ! -f "$CERT_PEM" ]; then
  echo -e "${RED}✗ CoworkGuard is not installed yet.${NC}"
  echo ""
  echo "  Please run the installer first:"
  echo -e "  ${CYAN}curl -sSL https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/install.sh | bash${NC}"
  exit 1
fi

# ── Check if already running ──────────────────────────────────────────
if lsof -i :8080 &>/dev/null; then
  echo -e "${YELLOW}⚠ Something is already running on port 8080.${NC}"
  echo "  Run stop.sh first, then try again."
  echo ""
fi

# ── Start mitmproxy with CoworkGuard certificate ──────────────────────
echo -e "${CYAN}→ Starting proxy scanner...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$INSTALL_DIR' && mitmproxy -s proxy.py --listen-port 8080\"" &>/dev/null
sleep 2
echo -e "${GREEN}✓ Proxy scanner running on port 8080${NC}"

# ── Start dashboard server ────────────────────────────────────────────
echo -e "${CYAN}→ Starting dashboard server...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$INSTALL_DIR' && python3 server.py\"" &>/dev/null
sleep 2
echo -e "${GREEN}✓ Dashboard running at http://localhost:7070${NC}"

# ── Enable system proxy ───────────────────────────────────────────────
echo -e "${CYAN}→ Enabling system proxy...${NC}"

NETWORK_SERVICE=$(networksetup -listallnetworkservices | grep -v "^\*" | grep -E "Wi-Fi|Ethernet|USB" | head -1)
if [ -z "$NETWORK_SERVICE" ]; then
  NETWORK_SERVICE="Wi-Fi"
fi

networksetup -setwebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setsecurewebproxy "$NETWORK_SERVICE" 127.0.0.1 8080
networksetup -setwebproxystate "$NETWORK_SERVICE" on
networksetup -setsecurewebproxystate "$NETWORK_SERVICE" on

echo -e "${GREEN}✓ System proxy enabled${NC}"

# ── Open dashboard ────────────────────────────────────────────────────
sleep 1
open "http://localhost:7070"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard is running${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:7070${NC}"
echo -e "  Protecting: Claude · ChatGPT · Cursor · Copilot · Gemini + more"
echo ""
echo -e "  ${YELLOW}${BOLD}Remember:${NC} Run ${CYAN}~/CoworkGuard/stop.sh${NC} when you are done."
echo ""
