# CoworkGuard

**CoworkGuard shows you what your AI tools are actually doing on your machine — in plain English, in real time.**

Trusted tooling is becoming the new attack surface.

AI tools read files, access credentials, download models, and make outbound requests — often silently. CoworkGuard is the runtime observability layer that makes those behaviours visible, understandable, and controllable.

No cloud dependency. No accounts. Everything runs locally on your Mac.

[![GitHub release](https://img.shields.io/github/v/release/Katherine-Holland/ClaudeCoworkGuard)](https://github.com/Katherine-Holland/ClaudeCoworkGuard/releases)
[![macOS](https://img.shields.io/badge/macOS-12%2B-blue)](https://github.com/Katherine-Holland/ClaudeCoworkGuard/releases)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Web%20Store-blue)](https://chromewebstore.google.com/detail/coworkguard/doidechmkoeggififfckcghclbpjcmdg)

---

![CoworkGuard Dashboard — Overview](https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/docs/assets/overview.png)

---

## What it does

CoworkGuard sits between your machine and AI-powered tooling. It scans outbound requests, surfaces behavioural sequences, and presents everything in a calm local dashboard — without sending anything to a server.

```text
Claude Desktop / Cursor / ChatGPT / Ollama / VS Code…
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  CoworkGuard proxy (localhost:8080)                │
│  Scans outbound AI requests                        │
│  Detects credentials, secrets, injections          │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  Behavioural correlation engine                    │
│  "VS Code Extension → Read .env → Connected        │
│   externally 2 seconds later"                      │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  Local dashboard (localhost:7070)                  │
│  Plain English · Local-first · Human-readable      │
└─────────────────────────────────────────────────────┘
```

---

## Features

### Behavioural correlation timeline

Surfaces sequences — not isolated events.

When an AI tool accesses private data and then makes an outbound request seconds later, CoworkGuard connects the dots:

```text
VS Code Extension
↓  Accessed .env file
↓  2 seconds later
Connected externally
↓  Review recommended
```

![Behavioural correlation timeline](https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/docs/assets/correlation.png)

### Proxy scanner

Intercepts outbound AI API requests and scans for sensitive data before transmission. Detects API keys, private keys, JWTs, database connection strings, `.env` values, prompt injections, hidden instructions, and more.

### MCP Trust Gateway

Scans tool responses before they reach the model context. Blocks prompt injection attacks, credential leaks, unicode steganography, hidden instructions, and suspicious tool metadata changes.

![Blocked request detail](https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/docs/assets/blocked.png)

### Model download detection

Detects when AI apps silently download models locally. Supports Ollama, LM Studio, GPT4All, Jan.ai, AnythingLLM, Msty, Superwhisper, and browser-bundled models.

### Actor monitor

Tracks AI runtimes and behavioural sequences across processes, bundle IDs, network activity, and local model interactions.

### Browser AI session tracking

Chrome extension detects active AI web sessions across ChatGPT, Claude, Gemini, Perplexity, Copilot, Mistral, and more.

### Clipboard & file monitoring

Detects sensitive clipboard content and suspicious AI file writes outside approved locations.

### Skill supply chain scanner

Watches MCP skill files for dangerous patterns including `eval()`, subprocess execution, credential access, obfuscated payloads, and excessive permissions.

### Confirm before send

Pause outbound AI requests for review before they leave the machine.

### Local dashboard

All activity in one place at `localhost:7070`.

Calm UI. Plain English explanations. Behavioural timelines. Full audit visibility.

---

## Quick start

### macOS App (recommended)

Download the latest DMG from [Releases](https://github.com/Katherine-Holland/ClaudeCoworkGuard/releases)

1. Open the `.dmg` and drag CoworkGuard to Applications
2. Launch CoworkGuard
3. Complete the one-time certificate setup
4. Click the shield → **Start Protection**
5. Install the Chrome extension

> macOS may briefly close and reopen the app during the first launch. This is a normal Gatekeeper verification check.

### Terminal

```bash
curl -sSL https://raw.githubusercontent.com/Katherine-Holland/ClaudeCoworkGuard/main/install.sh | bash
```

```bash
~/CoworkGuard/start.sh
~/CoworkGuard/stop.sh
```

---

## What it detects

### Credentials & secrets

* Private keys
* AWS credentials
* GitHub tokens
* Anthropic/OpenAI keys
* JWTs
* Bearer tokens
* Stripe live keys
* Database connection strings
* `.env` values

### Sensitive data

* Credit cards
* SSNs
* Passport numbers
* Emails
* Phone numbers
* Dates of birth

### MCP tool responses

* Prompt injection
* Hidden instructions
* Unicode steganography
* Credential theft attempts
* Tool metadata tampering

### Skill supply chain attacks

* `eval()` execution
* Shell/subprocess execution
* Credential access
* Obfuscation
* Persistence attempts
* Suspicious outbound fetches

---

## Architecture

```text
AI Tools (Claude Desktop · Cursor · ChatGPT · Copilot · Ollama…)
         │
         ▼
 ┌──────────────┐
 │  proxy.py    │
 │  :8080       │
 └──────────────┘
         │
         ▼
 ┌──────────────────────────────────┐
 │  scanner.py                      │
 │  Detection engine                │
 │  Behavioural correlation         │
 │  Payload hashing                 │
 └──────────────────────────────────┘
         │
         ▼
 ┌──────────────────────────────────┐
 │  server.py (:7070)               │
 │  Dashboard · Audit log · Rules   │
 └──────────────────────────────────┘

 ┌──────────────────────────────────┐
 │  actor_monitor/                  │
 │  Runtime detection               │
 │  Model download monitoring       │
 │  Behavioural sequencing          │
 └──────────────────────────────────┘

 ┌──────────────────────────────────┐
 │  mcp_trust/                      │
 │  Injection · Metadata · Unicode  │
 │  Policy enforcement              │
 └──────────────────────────────────┘
```

---

## Privacy

CoworkGuard never sends data externally.

* Proxy runs on `localhost`
* Dashboard runs locally
* Chrome extension communicates only with localhost
* Raw payloads are never stored
* No telemetry
* No analytics
* No accounts
* Audit logs stay on-device

---

## Roadmap

### Pro

Confirmed actor tracking, developer environment protection (`.env`, SSH keys, GitHub tokens, VS Code extension monitoring), advanced behavioural timelines, and audit export.

### Shield

Fleet-wide observability, policy-as-code, alert routing, compliance export, and organisation-level AI runtime governance.

[Join the waitlist](https://coworkguard.com/shield.html)

---

## Security

For security disclosures please open a private GitHub issue or contact:

[hello@coworkguard.com](mailto:hello@coworkguard.com)

---

## License

**MIT with Commons Clause** · © 2026 Katherine Weston

* Free for personal and internal non-commercial use
* Fork and modify for personal use
* Cannot be sold or hosted commercially without a separate licence

Built on open source:
mitmproxy · Flask · Tauri
