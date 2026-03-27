#!/bin/bash
# CoworkGuard — Startup Checker
# © 2026 Katherine Weston. MIT + Commons Clause.
# Registered as a Login Item by install.sh
# Runs automatically on Mac startup — checks if proxy was left on

# Wait for login to settle before checking
sleep 8

INSTALL_DIR="$HOME/CoworkGuard"

# ── Check if system proxy is pointing to CoworkGuard ─────────────────
NETWORK_SERVICE=$(networksetup -listallnetworkservices 2>/dev/null | grep -v "^\*" | grep -E "Wi-Fi|Ethernet|USB" | head -1)
if [ -z "$NETWORK_SERVICE" ]; then
  NETWORK_SERVICE="Wi-Fi"
fi

PROXY_STATE=$(networksetup -getwebproxy "$NETWORK_SERVICE" 2>/dev/null | grep "Enabled:" | awk '{print $2}')
PROXY_SERVER=$(networksetup -getwebproxy "$NETWORK_SERVICE" 2>/dev/null | grep "Server:" | awk '{print $2}')
PROXY_PORT=$(networksetup -getwebproxy "$NETWORK_SERVICE" 2>/dev/null | grep "Port:" | awk '{print $2}')

# Only act if our proxy is enabled and pointing to localhost:8080
if [[ "$PROXY_STATE" != "Yes" ]] || [[ "$PROXY_SERVER" != "127.0.0.1" ]] || [[ "$PROXY_PORT" != "8080" ]]; then
  exit 0
fi

# ── Proxy is on — check if mitmproxy is actually running ──────────────
if lsof -i :8080 &>/dev/null; then
  exit 0  # Everything is fine — mitmproxy is running
fi

# ── Proxy is on but mitmproxy is not running — notify user ───────────
# Use AppleScript to show a friendly dialog (better than osascript notification)
osascript << 'APPLESCRIPT'
set response to button returned of (display dialog "Your internet may not be working properly.

CoworkGuard's protection was left on when your Mac last restarted, but the scanner isn't running.

What would you like to do?" ¬
  with title "🛡️ CoworkGuard — Quick fix needed" ¬
  buttons {"Turn Off Protection", "Start CoworkGuard"} ¬
  default button "Start CoworkGuard" ¬
  with icon caution)

if response is "Start CoworkGuard" then
  tell application "Terminal"
    activate
    do script "echo '🛡️ Starting CoworkGuard...' && ~/CoworkGuard/start.sh"
  end tell
else if response is "Turn Off Protection" then
  do shell script "networksetup -setwebproxystate Wi-Fi off; networksetup -setsecurewebproxystate Wi-Fi off"
  display notification "Your internet connection has been restored. Run ~/CoworkGuard/start.sh whenever you want protection back on." with title "🛡️ CoworkGuard" subtitle "Protection turned off"
end if
APPLESCRIPT
