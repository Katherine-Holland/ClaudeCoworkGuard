# CoworkGuard Menubar App

Native macOS menubar app that wraps CoworkGuard — no terminal required.

## What it does

- Shield icon in your menubar — green (off), orange (on)
- One click to start/stop protection
- Starts mitmproxy + server.py silently in the background
- Enables/disables system proxy automatically
- Detects broken proxy state on startup and alerts you
- First-run setup wizard for certificate trust

## Building on your Mac

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Tauri CLI
cargo install tauri-cli

# Install Node dependencies
cd menubar-app
npm install
```

### Build

```bash
# Development (live reload)
cargo tauri dev

# Production .dmg
cargo tauri build
```

Output: `src-tauri/target/release/bundle/dmg/CoworkGuard_1.0.0_aarch64.dmg`

### Code signing (for distribution)

```bash
# Sign with your Apple Developer certificate
export APPLE_CERTIFICATE="Developer ID Application: Your Name (TEAMID)"
export APPLE_CERTIFICATE_PASSWORD="your-keychain-password"
cargo tauri build
```

## Architecture

The menubar app is a thin wrapper — it does not modify the scanner,
proxy, or dashboard. It simply:

1. Starts/stops `mitmproxy -s proxy.py` and `python3 server.py`
2. Toggles macOS system proxy settings via `networksetup`
3. Serves the existing `dashboard.html` at localhost:7070

All detection logic lives in `scanner.py`. The Rust code only handles
process management, proxy toggling, and native macOS UI.
