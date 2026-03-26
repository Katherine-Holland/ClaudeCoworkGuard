# CoworkGuard Privacy Policy

**Last updated: March 2026**

## Summary

CoworkGuard is a local privacy tool. All data stays on your machine. We collect nothing. We store nothing remotely. There is no server, no account, no analytics.

---

## What CoworkGuard does

CoworkGuard monitors outbound network requests from your browser to `api.anthropic.com` and warns you when potentially sensitive data — such as personal information, authentication tokens, or internal URLs — may be included in those requests.

## Data we do NOT collect

- We do not collect, transmit, or store any of your personal data
- We do not log the content of your messages or requests
- We do not track your browsing history
- We do not send any data to any remote server operated by CoworkGuard
- We do not use analytics, crash reporting, or any third-party tracking services

## Data stored locally on your device

CoworkGuard stores the following data **only on your local machine**, in `~/.coworkguard/`:

| Data | Purpose | Raw content stored? |
|------|---------|-------------------|
| Audit log entries | Local review of intercepted requests | **No** — only SHA-256 hash of payload, redacted previews, and metadata |
| Settings file | Your configuration preferences | Yes — contains only your chosen settings, no personal data |

**Raw payload content is never stored.** When a request is scanned, CoworkGuard stores only:
- The SHA-256 hash of the payload (cannot be reversed to recover original content)
- The byte size of the payload
- The type and severity of any detected pattern (e.g. "SSN", "JWT")
- A redacted preview showing only the first 2 and last 2 characters of any match

## Permissions used

CoworkGuard requests the following Chrome permissions and uses them only as described:

| Permission | Why it's needed |
|-----------|----------------|
| `tabs` | Detect when Claude.ai or Cowork is open in a tab |
| `activeTab` | Read the URL of the current tab to check against the sensitive domain list |
| `storage` | Save your settings and audit log locally in Chrome storage |
| `webRequest` | Inspect outbound request headers to detect CoworkGuard proxy tags |
| `notifications` | Show a browser notification when a sensitive domain is visited while Cowork is active |
| `<all_urls>` | Required to inject the warning banner into any page when a domain warning is triggered |

## Third parties

CoworkGuard does not share data with any third party. The extension communicates only with:
- `localhost:7070` — the local CoworkGuard server running on your own machine
- The page content of tabs you are currently viewing (to inject warning banners)

It does not communicate with any external server operated by CoworkGuard or any partner.

## Children's privacy

CoworkGuard is a developer/security tool not directed at children under 13.

## Changes to this policy

If this policy changes materially, we will update the "Last updated" date above and note the changes in the Chrome Web Store listing description.

## Contact

For questions about this privacy policy or CoworkGuard's data practices, please open an issue on the GitHub repository.
