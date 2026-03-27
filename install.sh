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

INSTALL_DIR="$HOME/CoworkGuard"
CERT_DIR="$HOME/.coworkguard"
CERT_KEY="$CERT_DIR/coworkguard-ca-key.pem"
CERT_PEM="$CERT_DIR/coworkguard-ca-cert.pem"

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
  python3 -m ensurepip --upgrade
fi

# ── Check OpenSSL ────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
  echo -e "${RED}✗ OpenSSL not found.${NC}"
  echo "  Install via: brew install openssl"
  exit 1
fi
echo -e "${GREEN}✓ OpenSSL found${NC}"

# ── Clone or update repo ─────────────────────────────────────────────
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

# ── Generate CoworkGuard certificate ─────────────────────────────────
mkdir -p "$CERT_DIR/logs"

if [ -f "$CERT_PEM" ]; then
  echo -e "${GREEN}✓ CoworkGuard certificate already exists${NC}"
else
  echo -e "${CYAN}→ Generating CoworkGuard Security Certificate...${NC}"

  # Generate private key
  openssl genrsa -out "$CERT_KEY" 2048 2>/dev/null

  # Generate CA certificate with friendly CoworkGuard name
  openssl req -new -x509 \
    -days 3650 \
    -key "$CERT_KEY" \
    -out "$CERT_PEM" \
    -subj "/CN=CoworkGuard Security Certificate/O=CoworkGuard/OU=AI Privacy Protection" \
    2>/dev/null

  echo -e "${GREEN}✓ Certificate generated${NC}"
fi

# ── Trust the certificate ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}One password prompt required:${NC}"
echo -e "  CoworkGuard needs your Mac password to trust its security"
echo -e "  certificate. This happens once only — never again."
echo ""

if sudo security add-trusted-cert \
    -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$CERT_PEM"; then
  echo -e "${GREEN}✓ CoworkGuard Security Certificate trusted${NC}"
else
  echo -e "${YELLOW}⚠ Could not trust certificate automatically.${NC}"
  echo "  Open Keychain Access, search for 'CoworkGuard Security Certificate'"
  echo "  double-click it and set Trust to 'Always Trust'."
fi

# ── Configure mitmproxy to use our certificate ────────────────────────
MITMPROXY_DIR="$HOME/.mitmproxy"
mkdir -p "$MITMPROXY_DIR"

# Write mitmproxy options file pointing to our cert
cat > "$MITMPROXY_DIR/config.yaml" << CONF
# CoworkGuard mitmproxy configuration — do not edit manually
certs:
  - "*=$CERT_PEM"
certs_key:
  - "*=$CERT_KEY"
CONF

echo -e "${GREEN}✓ Proxy configured to use CoworkGuard certificate${NC}"

# ── Make scripts executable ───────────────────────────────────────────
chmod +x "$INSTALL_DIR/start.sh"
chmod +x "$INSTALL_DIR/stop.sh"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "${GREEN}${BOLD}✓ CoworkGuard installed successfully!${NC}"
echo ""
echo -e "  ${BOLD}To start CoworkGuard:${NC}"
echo -e "  ${CYAN}~/CoworkGuard/start.sh${NC}"
echo ""
echo -e "  ${BOLD}Install the Chrome extension:${NC}"
echo -e "  https://chrome.google.com/webstore/detail/coworkguard"
echo ""
