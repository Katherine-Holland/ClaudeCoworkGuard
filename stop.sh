#!/bin/bash
# CoworkGuard — Stop
# © 2026 Katherine Weston. MIT + Commons Clause.

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

# ── Stop proxy scanner ────────────────────────────────────────────────
echo -e "${CYAN}→ Stopping proxy scanner...${NC}"
if [ -f "$HOME/.coworkguard/proxy.pid" ]; then
  kill "$(cat "$HOME/.coworkguard/proxy.pid")" 2>/dev/null || true
  rm "$HOME/.coworkguard/proxy.pid"
fi
pkill -f "mitmdump" 2>/dev/null || true
pkill -f "mitmproxy" 2>/dev/null || true
echo -e "${GREEN}✓ Proxy scanner stopped${NC}"

# ── Stop dashboard server ─────────────────────────────────────────────
echo -e "${CYAN}→ Stopping dashboard server...${NC}"
if [ -f "$HOME/.coworkguard/server.pid" ]; then
  kill "$(cat "$HOME/.coworkguard/server.pid")" 2>/dev/null || true
  rm "$HOME/.coworkguard/server.pid"
fi
pkill -f "server.py" 2>/dev/null || true
echo -e "${GREEN}✓ Dashboard stopped${NC}"

# ── Stop skill scanner ────────────────────────────────────────────────
echo -e "${CYAN}→ Stopping skill scanner...${NC}"
if [ -f "$HOME/.coworkguard/skill_scanner.pid" ]; then
  kill "$(cat "$HOME/.coworkguard/skill_scanner.pid")" 2>/dev/null || true
  rm "$HOME/.coworkguard/skill_scanner.pid"
fi
pkill -f "skill_scanner.py" 2>/dev/null || true
echo -e "${GREEN}✓ Skill scanner stopped${NC}"

# ── Stop agent guard and model monitor ───────────────────────────────
echo -e "${CYAN}→ Stopping agent guard...${NC}"
if [ -f "$HOME/.coworkguard/agent_guard.pid" ]; then
  kill "$(cat "$HOME/.coworkguard/agent_guard.pid")" 2>/dev/null || true
  rm "$HOME/.coworkguard/agent_guard.pid"
fi
if [ -f "$HOME/.coworkguard/model_monitor.pid" ]; then
  kill "$(cat "$HOME/.coworkguard/model_monitor.pid")" 2>/dev/null || true
  rm "$HOME/.coworkguard/model_monitor.pid"
fi
pkill -f "actor_monitor.agent_guard" 2>/dev/null || true
pkill -f "actor_monitor.model_monitor" 2>/dev/null || true
echo -e "${GREEN}✓ Agent guard stopped${NC}"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard stopped${NC}"
echo ""
echo "  Your internet is fully restored."
echo -e "  Run ${CYAN}~/CoworkGuard/start.sh${NC} next time you want protection."
echo ""