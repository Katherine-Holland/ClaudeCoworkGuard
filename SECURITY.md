# Security Policy

## Reporting a Vulnerability

CoworkGuard handles sensitive data interception and local certificate trust. Security disclosures are taken seriously.

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability:

1. Go to the [Security Advisories](https://github.com/Katherine-Holland/ClaudeCoworkGuard/security/advisories/new) page on GitHub and open a private advisory.
2. Or email directly: littlerobinagency@gmail.com with subject line `[CoworkGuard Security]`

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix if you have one

## Response

You will receive an acknowledgement within 48 hours. Fixes for critical issues will be prioritised and a patched release issued as soon as possible.

## Scope

In scope:
- scanner.py detection engine
- proxy.py mitmproxy interceptor
- server.py Flask API
- skill_scanner.py
- Chrome extension (background.js, content.js)
- menubar app (main.rs)
- Certificate generation and trust flow

Out of scope:
- mitmproxy itself (report to the mitmproxy project)
- Chrome browser vulnerabilities
- macOS Tauri framework vulnerabilities

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Current |
