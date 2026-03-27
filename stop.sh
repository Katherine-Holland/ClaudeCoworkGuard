#!/bin/bash
# CoworkGuard — Stop
# © 2026 Katherine Holland. MIT + Commons Clause.

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🛡️  Stopping CoworkGuard...${NC}"
echo ""

# ── Turn off system proxy first ───────────────────────────────────────
echo -e "${CYAN}→ Restoring normal internet connection...${NC}"

NETWORK_SERVICE=$(networksetup -listallnetworkservices | grep -v "^\*" | grep -E "Wi-Fi|Ethernet|USB" | head -1)
if [ -z "$NETWORK_SERVICE" ]; then
  NETWORK_SERVICE="Wi-Fi"
fi

networksetup -setwebproxystate "$NETWORK_SERVICE" off
networksetup -setsecurewebproxystate "$NETWORK_SERVICE" off

# Write clean stop flag so startup checker knows this was intentional
touch "$HOME/.coworkguard/.clean_stop"

echo -e "${GREEN}✓ Normal internet restored${NC}"

# ── Stop mitmproxy ────────────────────────────────────────────────────
echo -e "${CYAN}→ Stopping proxy scanner...${NC}"
pkill -f "mitmproxy" 2>/dev/null || true
pkill -f "mitmdump" 2>/dev/null || true
echo -e "${GREEN}✓ Proxy scanner stopped${NC}"

# ── Stop dashboard server ─────────────────────────────────────────────
echo -e "${CYAN}→ Stopping dashboard server...${NC}"
pkill -f "server.py" 2>/dev/null || true
echo -e "${GREEN}✓ Dashboard stopped${NC}"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard stopped${NC}"
echo ""
echo "  Your internet is fully restored."
echo -e "  Run ${CYAN}~/CoworkGuard/start.sh${NC} next time you want protection."
echo ""
