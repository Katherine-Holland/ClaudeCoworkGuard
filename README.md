# CoworkGuard

**Real-time privacy protection for Claude Cowork and Claude in Chrome.**

CoworkGuard monitors and blocks sensitive data — PII, auth tokens, secrets, and internal URLs — before it leaves your machine via the Anthropic API. It fills the compliance gap that Anthropic themselves acknowledge: Cowork activity is explicitly excluded from Audit Logs, the Compliance API, and Data Exports.

> Two days after Cowork launched, researchers demonstrated that a Word document with hidden white text could trick Cowork into uploading files containing partial Social Security numbers to an attacker's account. CoworkGuard is the layer that stops that.

---

## Why this exists

Claude Cowork and Claude in Chrome are powerful — and they inherit access to your entire browser session. Every tab you navigate, every page Claude reads, every file in your working folder can be sent to `api.anthropic.com`. There is no native audit trail, no payload scanner, and no warning when you navigate to sensitive pages while Cowork is active.

CoworkGuard adds that layer, running entirely on your own machine with no cloud dependency.

---

## Features

| Feature | Description |
|---|---|
| **Payload scanner** | 25+ regex patterns detecting PII, secrets, and internal data in every outbound request |
| **Active blocking** | Configurable by severity — CRITICAL threats blocked by default, HIGH/MEDIUM toggleable |
| **Domain guard** | In-page warning banner + Chrome notification when Cowork is active and you navigate to a sensitive domain |
| **Live audit log** | Real-time JSONL log of every intercepted request, with filterable dashboard view |
| **Threat detail modal** | Click any log entry to see full finding breakdown — severity, type, redacted preview |
| **Payload trend chart** | 24-hour bar chart showing data volume sent per hour, colour-coded by worst action |
| **Settings panel** | Toggle block levels, add custom patterns and domains — no config file editing required |
| **Process detection** | Detects whether the Claude desktop app is running and reflects status in the dashboard |
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
Browser / Cowork Desktop App
         │
         ▼
 ┌──────────────┐      ┌─────────────────────────────────┐
 │  mitmproxy   │─────▶│  scanner.py  (Detection engine) │
 │  proxy.py    │      │  • 25+ severity-scored patterns  │
 └──────────────┘      │  • Payload hash (never raw)      │
         │              │  • Redacted finding previews     │
         │              └─────────────────────────────────┘
         ▼
 api.anthropic.com  ← allowed, or 403 BLOCKED
         
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

 Chrome Extension (parallel layer)
 ┌────────────────────────────────────────────┐
 │ background.js  Cowork detection, API watch │
 │ content.js     In-page warning banners     │
 │ manifest.json  Manifest V3                 │
 └────────────────────────────────────────────┘
```

---

## File Structure

```
coworkguard/
├── scanner.py          # Core PII/secret detection engine (your IP)
├── proxy.py            # mitmproxy interceptor script
├── server.py           # Local Flask API server for dashboard
├── dashboard.html      # Audit dashboard UI
├── PRIVACY.md          # Privacy policy (host on GitHub Pages for Chrome store)
├── README.md
└── chrome-extension/
    ├── manifest.json   # Manifest V3
    ├── background.js   # Service worker — detection + monitoring
    └── content.js      # In-page warning banner injection
```

---

## Quick Start

### Prerequisites

```bash
pip install mitmproxy flask flask-cors psutil
```

### Step 1 — Start the proxy

```bash
mitmproxy -s proxy.py --listen-port 8080
```

Set your macOS system proxy:
- **System Settings → Network → [Your network] → Proxies**
- HTTP Proxy: `127.0.0.1` Port: `8080`
- HTTPS Proxy: `127.0.0.1` Port: `8080`

Trust the mitmproxy certificate:
```bash
open ~/.mitmproxy/mitmproxy-ca-cert.pem
# Add to Keychain → Trust for SSL
```

### Step 2 — Start the local server

```bash
python3 server.py
# Dashboard available at http://localhost:7070
```

### Step 3 — Load the Chrome extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder

### Step 4 — Open the dashboard

Navigate to `http://localhost:7070` in Chrome.

---

## Configuration

All settings are available through the dashboard Settings panel — no config file editing needed. Settings are persisted to `~/.coworkguard/settings.json` and hot-reloaded by the proxy.

| Setting | Default | Description |
|---|---|---|
| Block Critical | ✅ On | SSNs, credit cards, private keys, raw API keys |
| Block High | ❌ Off | JWTs, bearer tokens, GitHub tokens, Stripe keys |
| Block Medium | ❌ Off | Emails, phone numbers, IP addresses |
| Domain Alerts | ✅ On | Warn when navigating to sensitive domains while Cowork is active |
| Proxy Port | 8080 | Port mitmproxy listens on |
| Max Log Entries | 1000 | Audit log rotation limit |
| Custom Patterns | — | Your own regex patterns, applied at MEDIUM severity |
| Custom Domains | — | Additional domains to monitor |

---

## Audit Logs

Logs are written to `~/.coworkguard/logs/audit_YYYYMMDD.jsonl` — one JSON object per line, one file per day.

Each entry contains:

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

**Raw payload content is never stored.** Only SHA-256 hashes, byte sizes, pattern types, severities, and redacted previews are logged.

---

## Sensitive Domains (built-in)

CoworkGuard warns when Cowork is active and you navigate to any of these:

`console.aws.amazon.com` · `app.datadoghq.com` · `grafana.*` · `jenkins.*` · `gitlab.*` · `github.com` · `jira.*` · `confluence.*` · `notion.so` · `linear.app` · `stripe.com/dashboard` · `mail.google.com` · `outlook.*` · `workday.com` · `bamboohr.*` · `salesforce.com` · `hubspot.com`

Add your own in the Settings panel or directly in `~/.coworkguard/settings.json`.

---

## Chrome Web Store

CoworkGuard is available on the Chrome Web Store. For enterprise deployment without the store, use Chrome's `ExtensionInstallForcelist` policy or load unpacked via Developer mode.

Privacy policy: see `PRIVACY.md` — host at `https://yourusername.github.io/coworkguard/PRIVACY` for store submission.

---

## Roadmap

- [ ] macOS menubar app wrapper (status indicator without opening dashboard)
- [ ] OTel exporter — pipe findings to Grafana/Datadog/SIEM
- [ ] Windows support (mitmproxy works cross-platform; Cowork Windows support is planned by Anthropic)
- [ ] Firefox extension
- [ ] Enterprise managed policy support (pre-configure block levels and custom domains via IT)
- [ ] Webhook alerts — POST to Slack/Teams when a request is blocked

---

## Security

CoworkGuard itself never sends data externally. The proxy runs on `localhost:8080`, the server on `localhost:7070`, and the Chrome extension communicates only with these local endpoints.

If you discover a security issue in CoworkGuard, please open a private GitHub issue.

---

## License

**MIT with Commons Clause** — © 2026 [Katherine Weston]. All rights reserved.

- ✅ Free for personal and internal non-commercial use
- ✅ Fork and modify for personal use
- ❌ Cannot be sold, hosted as a service, or bundled into a commercial product without a separate license

For commercial licensing or acquisition enquiries: [littlerobinagency@gmail.com]

See [LICENSE](./LICENSE) for full terms.

CoworkGuard is built on Apache 2.0 open source components: mitmproxy, Flask, OpenTelemetry.
