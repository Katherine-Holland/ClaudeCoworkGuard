# CoworkGuard 🛡️

**A firewall for AI agents.**

AI agent tools — Claude, Cursor, GitHub Copilot, ChatGPT, Gemini — operate with full access to your environment. Every file, browser session, and credential is in scope. None of them provide a native audit trail, payload scanner, or data loss prevention layer (as of this release).

CoworkGuard adds that layer. It sits between your machine and every major AI API, scanning outbound payloads in real time, blocking sensitive data before it leaves, and keeping a local audit log of everything that passes through.

No cloud dependency. No accounts. Everything runs on your own machine.

> **Proven in the wild:** Within 48 hours of Claude Cowork's launch, researchers demonstrated a Word document with hidden white text could exfiltrate partial Social Security numbers via the Anthropic API. CoworkGuard blocks that class of attack across all 10 monitored AI endpoints.

---

## Monitored AI endpoints

| Provider | Endpoint | Tools covered |
|---|---|---|
| **Anthropic** ⭐ | api.anthropic.com | Claude Cowork, Claude Code, Claude in Chrome |
| OpenAI | api.openai.com | ChatGPT, GPT-4, Assistants API |
| Google | generativelanguage.googleapis.com | Gemini |
| Perplexity | api.perplexity.ai | Perplexity |
| Cursor | api.cursor.sh | Cursor IDE |
| GitHub | copilot-proxy.githubusercontent.com | GitHub Copilot |
| Mistral | api.mistral.ai | Mistral |
| Cohere | api.cohere.com | Cohere |
| Groq | api.groq.com | Groq |
| xAI | api.x.ai | Grok |

---

## Why this exists

Every AI agent tool operates with the same permissions you have — your browser session, your files, your credentials are all in scope. There is no native audit trail, no payload scanner, and no warning when sensitive data is about to leave your machine.

This isn't a theoretical risk. Prompt injection, data exfiltration via hidden document content, and MCP supply chain attacks are all documented vectors. CoworkGuard is the DLP layer that AI agent tools don't ship with.

---

## Features

| Feature | Description |
|---|---|
| **Payload scanner** | 48 patterns detecting PII, secrets, and internal data in every outbound request |
| **Active blocking** | Configurable by severity — CRITICAL threats blocked by default, HIGH/MEDIUM toggleable |
| **Domain guard** | In-page warning banner + Chrome notification when a Claude session is active and you navigate to a sensitive domain |
| **Live audit log** | Real-time JSONL log of every intercepted request, with filterable dashboard view |
| **Threat detail modal** | Click any log entry to see full finding breakdown — severity, type, redacted preview |
| **Payload trend chart** | 24-hour bar chart showing data volume sent per hour, colour-coded by worst action |
| **Settings panel** | Toggle block levels, add custom patterns and domains — no config file editing required |
| **Menubar app** | Native macOS menubar app — start/stop protection with one click, no terminal required |
| **Zero cloud dependency** | Everything runs locally. No accounts, no telemetry, no data leaves your machine |

---

## What it detects

### PII
| Pattern | Severity |
|---|---|
| Social Security Number | CRITICAL |
| Credit card number | CRITICAL |
| Date of birth | MEDIUM |
| Email address | MEDIUM |
| Phone number (US) | MEDIUM |
| Passport number | MEDIUM |
| IP address | MEDIUM |

### Auth / Secrets
| Pattern | Severity |
|---|---|
| Private key (RSA/EC/OpenSSH) | CRITICAL |
| AWS access key | CRITICAL |
| Anthropic API key | CRITICAL |
| OpenAI API key | CRITICAL |
| GitHub token | HIGH |
| JWT | HIGH |
| Bearer token | HIGH |
| Stripe live key | HIGH |
| Slack token | HIGH |
| Google API key | HIGH |
| HTTP Basic Auth header | HIGH |
| AWS secret (inline) | CRITICAL |

### Internal / Corporate
| Pattern | Severity |
|---|---|
| Private IP URL (10.x, 192.168.x, 172.16-31.x) | MEDIUM |
| VPN / intranet hostname (.internal, .corp, .lan) | MEDIUM |
| .env file values (DB_PASSWORD, SECRET_KEY, etc.) | HIGH |
| Database connection string (PostgreSQL, MySQL, MongoDB, Redis) | HIGH |

---

## Architecture

```
Browser / AI Agent Tools
(Claude Cowork · Cursor · ChatGPT · Copilot · Gemini · Perplexity…)
         │
         ▼
 ┌──────────────┐      ┌─────────────────────────────────┐
 │  mitmdump    │─────▶│  scanner.py  (Detection engine) │
 │  proxy.py    │      │  • 48 severity-scored patterns   │
 └──────────────┘      │  • Payload hash (never raw)      │
         │              │  • Redacted finding previews     │
         │              └─────────────────────────────────┘
         ▼
 api.anthropic.com  ╮
 api.openai.com     ╟── allowed, or 403 BLOCKED
 + 8 more AI APIs  ╯

 ┌──────────────┐
 │  server.py   │  Flask local API — serves dashboard, reads logs,
 │  :7070       │  detects processes, persists settings
 └──────────────┘
         │
         ▼
 ┌──────────────┐
 │ dashboard    │  Live audit log · Payload trend chart
 │ .html        │  Threat detail modal · Settings panel
 └──────────────┘

 ┌──────────────────────────────────────┐
 │  CoworkGuard.app (macOS menubar)     │
 │  One-click start/stop · No terminal  │
 └──────────────────────────────────────┘

 Chrome Extension (parallel layer)
 ┌────────────────────────────────────────────┐
 │ background.js  Session detection, API watch│
 │ content.js     In-page warning banners     │
 │ manifest.json  Manifest V3                 │
 └────────────────────────────────────────────┘
```

---

## File Structure

```
coworkguard/
├── install.sh              # One-time installer (terminal approach)
├── start.sh                # Start CoworkGuard + enable proxy
├── stop.sh                 # Stop CoworkGuard + restore internet
├── checker.sh              # Startup checker — detects broken proxy state
├── scanner.py              # Core PII/secret detection engine
├── proxy.py                # mitmproxy interceptor script
├── server.py               # Local Flask API server for dashboard
├── dashboard.html          # Audit dashboard UI
├── domains.json            # Shared sensitive domains list
├── README.md
├── menubar-app/            # Native macOS menubar app (Tauri)
│   ├── src-tauri/
│   │   ├── src/main.rs     # Rust backend — process management, proxy toggle
│   │   ├── Cargo.toml
│   │   └── tauri.conf.json
│   └── src/index.html      # First-run setup wizard
└── chrome-extension/
    ├── manifest.json       # Manifest V3
    ├── popup.html          # Toolbar popup — live stats + recent events
    ├── background.js       # Service worker — detection + monitoring
    ├── content.js          # In-page warning banner injection
    └── icons/
```

---

## Quick Start

### Option 1 — macOS Menubar App (recommended)

Download `CoworkGuard_1.0.0_aarch64.dmg` from the [latest release](https://github.com/Katherine-Holland/ClaudeCoworkGuard/releases).

1. Open the `.dmg` and drag CoworkGuard to Applications
2. Open CoworkGuard — a shield icon appears in your menubar
3. Complete the one-time setup wizard (generates and trusts the certificate)
4. Click the shield → **Start Protection**

That's it. No terminal required.

Then install the Chrome extension from the [Chrome Web Store](https://chrome.google.com/webstore/detail/coworkguard).

### Option 2 — Terminal installer

```bash
curl -sSL https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/install.sh | bash
```

---

## Daily Use

### Menubar app
Click the shield icon in your menubar → **Start Protection** / **Stop Protection**.

### Terminal
```bash
~/CoworkGuard/start.sh   # Start protection
~/CoworkGuard/stop.sh    # Stop protection + restore internet
```

> **Important:** Always stop CoworkGuard when done. If your Mac restarts with protection on, CoworkGuard will alert you automatically and offer to fix it.

---

## Configuration

All settings are available through the dashboard at `http://localhost:7070` — no config file editing needed.

| Setting | Default | Description |
|---|---|---|
| Block Critical | ✅ On | SSNs, credit cards, private keys, raw API keys |
| Block High | ❌ Off | JWTs, bearer tokens, GitHub tokens, Stripe keys |
| Block Medium | ❌ Off | Emails, phone numbers, IP addresses |
| Domain Alerts | ✅ On | Warn when navigating to sensitive domains while a Claude session is active |
| Proxy Port | 8080 | Port mitmdump listens on |
| Max Log Entries | 1000 | Audit log rotation limit |
| Custom Patterns | — | Your own regex patterns, applied at MEDIUM severity |
| Custom Domains | — | Additional domains to monitor |

---

## Audit Logs

Logs are written to `~/.coworkguard/logs/audit_YYYYMMDD.jsonl` — one JSON object per line, one file per day.

```json
{
  "timestamp": "2026-03-26T15:09:05Z",
  "url": "https://api.anthropic.com/v1/messages",
  "method": "POST",
  "action": "BLOCKED",
  "blocked": true,
  "payload_hash": "f6ca59cf600f565f",
  "payload_size_bytes": 1842,
  "finding_count": 2,
  "findings": [
    { "type": "SSN", "severity": "CRITICAL", "preview": "12*******89", "blocked": true },
    { "type": "EMAIL", "severity": "MEDIUM",  "preview": "jo****@****.com", "blocked": false }
  ]
}
```

**Raw payload content is never stored.**

---

## Sensitive Domains (built-in)

`console.aws.amazon.com` · `app.datadoghq.com` · `grafana.*` · `jenkins.*` · `gitlab.*` · `github.com` · `jira.*` · `confluence.*` · `notion.so` · `linear.app` · `stripe.com/dashboard` · `mail.google.com` · `outlook.*` · `workday.com` · `bamboohr.*` · `salesforce.com` · `hubspot.com`

Add your own in the Settings panel.

---

## Roadmap

- [ ] OTel exporter — pipe findings to Grafana/Datadog/SIEM
- [ ] Windows support
- [ ] Firefox extension
- [ ] Enterprise managed policy support
- [ ] Webhook alerts — POST to Slack/Teams when a request is blocked
- [ ] Mac App Store distribution (requires Network Extension entitlement)

---

## Security

CoworkGuard never sends data externally. The proxy runs on `localhost:8080`, the server on `localhost:7070`, and the Chrome extension communicates only with these local endpoints.

For security disclosures, please open a private GitHub issue.

---

## License

**MIT with Commons Clause** — © 2026 Katherine Weston. All rights reserved.

- ✅ Free for personal and internal non-commercial use
- ✅ Fork and modify for personal use
- ❌ Cannot be sold, hosted as a service, or bundled into a commercial product without a separate license

For commercial licensing or acquisition enquiries: littlerobinagency@gmail.com

See [LICENSE](./LICENSE) for full terms.

CoworkGuard is built on open source components: mitmproxy, Flask, Tauri.