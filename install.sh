#!/bin/bash
# CoworkGuard — One-time installer
# © 2026 Katherine Holland. MIT + Commons Clause.
# Run once: curl -sSL https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/install.sh | bash

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🛡️  CoworkGuard Installer${NC}"
echo "─────────────────────────────────────"
echo ""

# ── Check macOS ──────────────────────────────────────────────────────
if [[ "$OSTYPE" != "darwin"* ]]; then
  echo -e "${RED}✗ CoworkGuard currently requires macOS.${NC}"
  echo "  Windows support is coming. See the roadmap on GitHub."
  exit 1
fi
echo -e "${GREEN}✓ macOS detected${NC}"

# ── Check Python ─────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}✗ Python 3 not found.${NC}"
  echo ""
  echo "  Install Python first:"
  echo "  → https://www.python.org/downloads/"
  echo "  Or via Homebrew: brew install python"
  exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}✓ Python ${PY_VERSION} found${NC}"

# ── Check pip ────────────────────────────────────────────────────────
if ! command -v pip3 &>/dev/null; then
  echo -e "${YELLOW}⚠ pip3 not found — installing...${NC}"
  python3 -m ensurepip --upgrade
fi

# ── Clone or update repo ─────────────────────────────────────────────
INSTALL_DIR="$HOME/CoworkGuard"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo -e "${CYAN}→ Updating existing installation...${NC}"
  cd "$INSTALL_DIR"
  git pull --quiet
  echo -e "${GREEN}✓ Updated to latest version${NC}"
else
  echo -e "${CYAN}→ Downloading CoworkGuard...${NC}"
  git clone --quiet https://github.com/Katherine-Holland/ClaudeCoworkGuard.git "$INSTALL_DIR"
  cd "$INSTALL_DIR"
  echo -e "${GREEN}✓ Downloaded${NC}"
fi

# ── Install Python dependencies ───────────────────────────────────────
echo -e "${CYAN}→ Installing dependencies (this may take a minute)...${NC}"
pip3 install mitmproxy flask flask-cors psutil --quiet --disable-pip-version-check
echo -e "${GREEN}✓ Dependencies installed${NC}"

# ── Trust mitmproxy certificate ───────────────────────────────────────
echo -e "${CYAN}→ Setting up security certificate...${NC}"

# Run mitmproxy briefly to generate the certificate
python3 -c "
import subprocess, time, os, signal

# Start mitmproxy briefly to generate cert
p = subprocess.Popen(['mitmdump', '--listen-port', '18765', '--quiet'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
p.terminate()
p.wait()
" 2>/dev/null || true

CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ -f "$CERT" ]; then
  # Add to macOS keychain
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT" 2>/dev/null && \
    echo -e "${GREEN}✓ Certificate trusted automatically${NC}" || \
    echo -e "${YELLOW}⚠ Could not auto-trust certificate. Run start.sh and follow the manual step.${NC}"
else
  echo -e "${YELLOW}⚠ Certificate will be generated on first run.${NC}"
fi

# ── Create logs directory ─────────────────────────────────────────────
mkdir -p "$HOME/.coworkguard/logs"
echo -e "${GREEN}✓ Log directory created at ~/.coworkguard/logs${NC}"

# ── Make scripts executable ───────────────────────────────────────────
chmod +x "$INSTALL_DIR/start.sh"
chmod +x "$INSTALL_DIR/stop.sh"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard installed successfully!${NC}"
echo ""
echo -e "  Installed to: ${CYAN}$INSTALL_DIR${NC}"
echo ""
echo -e "  ${BOLD}To start CoworkGuard:${NC}"
echo -e "  ${CYAN}$INSTALL_DIR/start.sh${NC}"
echo ""
echo -e "  ${BOLD}Next step — install the Chrome extension:${NC}"
echo -e "  https://chrome.google.com/webstore/detail/coworkguard"
echo ""
