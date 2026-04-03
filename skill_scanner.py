"""
CoworkGuard Skill Scanner
Watches for new AI agent skills (Cowork, OpenClaw, MCP) and scans them
for security risks before they execute.

Watch mode: runs as a background process, fires macOS notifications on findings.
On-demand: python3 skill_scanner.py /path/to/skill

© 2026 Katherine Weston. All Rights Reserved.
"""

import re
import os
import sys
import json
import time
import hashlib
import logging
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional

# ─────────────────────────────────────────────
# Logging — suppress werkzeug noise
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[CoworkGuard Skill Scanner] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("skill_scanner")

# ─────────────────────────────────────────────
# Load monitored AI API domains from domains.json
# Keeps FETCH_EXTERNAL allowlist in sync with proxy.py and background.js
# ─────────────────────────────────────────────

def _load_ai_api_domains() -> list:
    """Load monitored AI API hostnames from shared domains.json."""
    domains_file = Path(__file__).parent / "domains.json"
    if domains_file.exists():
        try:
            with open(domains_file) as f:
                data = json.load(f)
                return data.get("ai_api_domains", [])
        except Exception:
            pass
    # Fallback — hardcoded list matches proxy.py
    return [
        "api.anthropic.com", "api.openai.com",
        "generativelanguage.googleapis.com", "api.mistral.ai",
        "api.cohere.com", "api.groq.com", "api.x.ai",
        "api.perplexity.ai", "api.cursor.sh",
        "copilot-proxy.githubusercontent.com",
    ]

# Build negative lookahead from domains list — keeps patterns in sync with domains.json
_AI_DOMAINS = _load_ai_api_domains()
_AI_DOMAIN_LOOKAHEAD = "|".join(
    re.escape(d).replace(r"\.", r"\.") for d in _AI_DOMAINS
)

# ─────────────────────────────────────────────
# Skill-specific detection patterns
# These extend the core CoworkGuard scanner patterns
# with patterns specific to skill file content
# ─────────────────────────────────────────────

SKILL_PATTERNS = {
    # ── Code execution / privilege escalation ────────────────────────────
    "EVAL_EXEC":        r"\beval\s*\(|new\s+Function\s*\(|exec\s*\(|execSync\s*\(",
    "SUBPROCESS":       r"\bchild_process\b|subprocess\.(?:run|call|Popen|check_output)|os\.system\s*\(",
    "SHELL_INJECT":     r"\bspawn\s*\(['\"](?:bash|sh|zsh|cmd|powershell)['\"]|\bexecFile\s*\(",

    # ── Obfuscation signals ───────────────────────────────────────────────
    "BASE64_DECODE":    r"\batob\s*\(|base64\.b64decode\s*\(|Buffer\.from\s*\([^,)]+,\s*['\"]base64['\"]",
    "HEX_DECODE":       r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}",
    "CHAR_CODE":        r"String\.fromCharCode\s*\(",

    # ── Network calls to non-AI domains ──────────────────────────────────
    # Allowlist loaded from domains.json — stays in sync with proxy.py and background.js
    "FETCH_EXTERNAL":   r"\bfetch\s*\(\s*['\"]https?://(?!__AI_DOMAINS__)[^'\"]+['\"]",
    "AXIOS_EXTERNAL":   r"\baxios\.(get|post|put|delete)\s*\(\s*['\"]https?://(?!__AI_DOMAINS__)[^'\"]+['\"]",
    "CURL_COMMAND":     r"\bcurl\s+(?:-[a-zA-Z]+\s+)*https?://(?!__AI_DOMAINS__)[^\s]+",
    "WGET_COMMAND":     r"\bwget\s+https?://(?!__AI_DOMAINS__)[^\s]+",
    "XHR_OPEN":         r"\.open\s*\(\s*['\"](?:GET|POST)['\"],\s*['\"]https?://(?!__AI_DOMAINS__)[^'\"]+['\"]",

    # ── Sensitive filesystem access ───────────────────────────────────────
    "SSH_KEY_READ":     r"['\"]?~?/\.ssh/|readFileSync\s*\(['\"][^'\"]*\.ssh[^'\"]*['\"]",
    "AWS_CREDS_READ":   r"['\"]?~?/\.aws/credentials|readFileSync\s*\(['\"][^'\"]*\.aws[^'\"]*['\"]",
    "ENV_FILE_READ":    r"readFileSync\s*\(['\"][^'\"]*\.env[^'\"]*['\"]|dotenv\.config\s*\(\s*\{[^}]*path[^}]*\}",
    "KEYCHAIN_ACCESS":  r"security\s+find-generic-password|security\s+find-internet-password",
    "PASSWD_READ":      r"/etc/passwd|/etc/shadow|/etc/sudoers",

    # ── Data exfiltration via messaging platforms ─────────────────────────
    "WHATSAPP_SEND":    r"(?i)whatsapp|baileys|@whiskeysockets",
    "TELEGRAM_SEND":    r"(?i)telegram(?:bot)?\.sendMessage|bot\.sendMessage|grammy|grammY",
    "DISCORD_SEND":     r"(?i)discord\.js|webhook\.send|channel\.send",
    "SLACK_POST":       r"(?i)slack(?:sdk|bolt|client)?\.(?:chat|files)\.(?:postMessage|upload)",
    "EMAIL_SEND":       r"(?i)nodemailer|smtplib\.SMTP|sendmail\s*\(",

    # ── MCP permission escalation ─────────────────────────────────────────
    "MCP_FULL_FS":      r'"filesystem"\s*:\s*\{[^}]*"/"',
    "MCP_SHELL_ACCESS": r'"shell"\s*:\s*(?:true|\{[^}]*"enabled"\s*:\s*true)',
    "MCP_NO_SANDBOX":   r'"sandbox"\s*:\s*false|"isolation"\s*:\s*false',

    # ── Credential harvesting ─────────────────────────────────────────────
    # ENV_HARVEST is LOW — reading env vars is normal in any Node/Python skill.
    # Only flag if combined with exfiltration patterns.
    "ENV_HARVEST":      r"process\.env\.[A-Z_]{5,}|os\.environ(?:\.get)?\s*\(['\"][A-Z_]{5,}['\"]",
    "KEYSTORE_READ":    r"(?i)keytar\.getPassword|keychain\.get|credential(?:s)?\.get",

    # ── Persistence mechanisms ────────────────────────────────────────────
    # Anchored to actual code — not just the word in comments/docs
    "LAUNCHAGENT":      r"(?i)(?:cp|copy|install|write|create|plist)\s[^\n]*LaunchAgents|LaunchAgents[^\n]*(?:cp|copy|install|write|create|plist)|launchctl\s+(?:load|submit|start)|systemctl\s+(?:enable|start)\s",
    "STARTUP_ENTRY":    r"(?i)HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|echo\s[^\n]*>>\s*~?/\.(?:bashrc|zshrc|profile)|append.*(?:bashrc|zshrc|profile)",
}

# Severity for skill-specific patterns
SKILL_SEVERITY = {
    "EVAL_EXEC":        "CRITICAL",
    "SUBPROCESS":       "CRITICAL",
    "SHELL_INJECT":     "CRITICAL",
    "BASE64_DECODE":    "HIGH",
    "HEX_DECODE":       "HIGH",
    "CHAR_CODE":        "HIGH",
    "FETCH_EXTERNAL":   "HIGH",
    "AXIOS_EXTERNAL":   "HIGH",
    "CURL_COMMAND":     "HIGH",
    "WGET_COMMAND":     "HIGH",
    "XHR_OPEN":         "HIGH",
    "SSH_KEY_READ":     "CRITICAL",
    "AWS_CREDS_READ":   "CRITICAL",
    "ENV_FILE_READ":    "HIGH",
    "KEYCHAIN_ACCESS":  "CRITICAL",
    "PASSWD_READ":      "CRITICAL",
    "WHATSAPP_SEND":    "HIGH",
    "TELEGRAM_SEND":    "HIGH",
    "DISCORD_SEND":     "HIGH",
    "SLACK_POST":       "HIGH",
    "EMAIL_SEND":       "HIGH",
    "MCP_FULL_FS":      "CRITICAL",
    "MCP_SHELL_ACCESS": "CRITICAL",
    "MCP_NO_SANDBOX":   "HIGH",
    "ENV_HARVEST":      "LOW",      # Reading env vars is normal — LOW to avoid noise
    "KEYSTORE_READ":    "HIGH",
    "LAUNCHAGENT":      "HIGH",
    "STARTUP_ENTRY":    "HIGH",
}

# ─────────────────────────────────────────────
# File patterns that identify skill files
# ─────────────────────────────────────────────

SKILL_FILENAMES = {
    "SKILL.md", "skill.md", "SKILL.MD",
    "manifest.json", "package.json",
    "claude_desktop_config.json",
    "mcp_config.json", ".mcp.json",
}

SKILL_EXTENSIONS = {".md", ".js", ".ts", ".mjs", ".cjs", ".json"}

# Directory names that suggest skill content
SKILL_DIR_HINTS = {
    "skill", "skills", "mcp", "mcpservers", "agents",
    "openclaw", "cowork", ".anthropic", ".openclaw",
    "claude", "clawhub",
}

# Known skill storage paths — watched directly
SKILL_WATCH_PATHS = [
    Path.home() / ".openclaw" / "workspace" / "skills",
    Path.home() / ".anthropic" / "cowork" / "skills",
    Path.home() / ".config" / "claude",
    Path.home() / ".config" / "mcp",
    Path.home() / "Downloads",
    Path.home() / "Desktop",
]

# High-traffic directories where we apply stricter filtering
HIGH_TRAFFIC_DIRS = {
    Path.home() / "Downloads",
    Path.home() / "Desktop",
}

# ─────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────

LOG_DIR = Path.home() / ".coworkguard" / "logs"

def get_log_path() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now().strftime("%Y%m%d")
    return LOG_DIR / f"skill_scan_{date}.jsonl"

def write_log(entry: dict):
    with open(get_log_path(), "a") as f:
        f.write(json.dumps(entry) + "\n")

# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class SkillFinding:
    pattern_name: str
    severity: str
    match_preview: str
    line_number: int
    blocked: bool = False

@dataclass
class SkillScanResult:
    timestamp: str
    file_path: str
    file_hash: str
    file_size_bytes: int
    skill_type: str          # COWORK / OPENCLAW / MCP / UNKNOWN
    findings: List[SkillFinding] = field(default_factory=list)
    action: str = "CLEAN"
    blocked: bool = False
    risk_score: int = 0

    @property
    def has_critical(self):
        return any(f.severity == "CRITICAL" for f in self.findings)

    @property
    def has_high(self):
        return any(f.severity == "HIGH" for f in self.findings)

    def to_jsonl(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "type": "SKILL_SCAN",
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size_bytes": self.file_size_bytes,
            "skill_type": self.skill_type,
            "action": self.action,
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "finding_count": len(self.findings),
            "findings": [
                {
                    "type": f.pattern_name,
                    "severity": f.severity,
                    "preview": f.match_preview,
                    "line": f.line_number,
                    "blocked": f.blocked,
                }
                for f in self.findings
            ],
        }

# ─────────────────────────────────────────────
# Skill type detection
# ─────────────────────────────────────────────

def detect_skill_type(path: Path, content: str) -> str:
    path_str = str(path).lower()
    if ".openclaw" in path_str or "openclaw" in path_str or "clawhub" in path_str:
        return "OPENCLAW"
    if ".anthropic" in path_str or "cowork" in path_str:
        return "COWORK"
    if "claude_desktop_config" in path.name.lower() or "mcp" in path_str:
        return "MCP"
    if '"mcpServers"' in content or '"mcp_servers"' in content:
        return "MCP"
    if "SKILL.md" in path.name or "## Skill" in content or "## Tools" in content:
        return "COWORK"
    return "UNKNOWN"

# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class SkillScanner:
    # Max findings per pattern — prevents score inflation from repeated matches
    MAX_FINDINGS_PER_PATTERN = 5

    def __init__(self):
        # Build patterns — replace __AI_DOMAINS__ placeholder with live domain list
        self._compiled = {}
        for name, pattern in SKILL_PATTERNS.items():
            resolved = pattern.replace("__AI_DOMAINS__", _AI_DOMAIN_LOOKAHEAD)
            self._compiled[name] = re.compile(resolved, re.IGNORECASE)

    def _redact(self, match_str: str) -> str:
        n = len(match_str)
        if n <= 6:
            return "*" * n
        return match_str[:2] + "*" * (n - 4) + match_str[-2:]

    def _risk_score(self, findings: List[SkillFinding]) -> int:
        score = 0
        for f in findings:
            if f.severity == "CRITICAL":
                score += 40
            elif f.severity == "HIGH":
                score += 15
            elif f.severity == "MEDIUM":
                score += 5
            # LOW (ENV_HARVEST etc.) does not contribute to risk score
        return min(score, 100)

    def scan_file(self, path: Path) -> Optional[SkillScanResult]:
        """Scan a skill file. Returns None if file should be skipped."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log.warning(f"Could not read {path}: {e}")
            return None
        return self.scan_file_content(content, path.name, path)

    def scan_file_content(self, content: str, filename: str, path: Optional[Path] = None) -> SkillScanResult:
        """Scan raw text content as a skill file. Used by tests and watch mode."""
        if path is None:
            path = Path(filename)

        file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        skill_type = detect_skill_type(path, content)
        findings = []
        pattern_counts: dict = {}

        for name, pattern in self._compiled.items():
            for match in pattern.finditer(content):
                # Cap findings per pattern to avoid score inflation
                count = pattern_counts.get(name, 0)
                if count >= self.MAX_FINDINGS_PER_PATTERN:
                    continue
                pattern_counts[name] = count + 1

                line_num = content[:match.start()].count("\n") + 1
                findings.append(SkillFinding(
                    pattern_name=name,
                    severity=SKILL_SEVERITY.get(name, "MEDIUM"),
                    match_preview=self._redact(match.group()),
                    line_number=line_num,
                ))

        risk = self._risk_score(findings)

        # Only non-LOW findings affect the action
        notable_findings = [f for f in findings if f.severity != "LOW"]

        result = SkillScanResult(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            file_path=str(path),
            file_hash=file_hash,
            file_size_bytes=len(content.encode("utf-8")),
            skill_type=skill_type,
            findings=findings,
            action="CLEAN",
            risk_score=risk,
        )

        if notable_findings:
            result.action = "BLOCKED" if result.has_critical else "FLAGGED"
            result.blocked = result.has_critical
            for f in findings:
                if f.severity == "CRITICAL":
                    f.blocked = True

        return result

# ─────────────────────────────────────────────
# macOS notification
# ─────────────────────────────────────────────

def notify(title: str, message: str):
    if platform.system() != "Darwin":
        log.info(f"NOTIFY: {title} — {message}")
        return
    script = f'display notification "{message}" with title "{title}" sound name "Basso"'
    try:
        subprocess.run(["osascript", "-e", script], check=False, timeout=5)
    except Exception:
        pass

def is_quiet_mode() -> bool:
    """Check if quiet mode is enabled in CoworkGuard settings."""
    settings_file = Path.home() / ".coworkguard" / "settings.json"
    if settings_file.exists():
        try:
            with open(settings_file) as f:
                settings = json.load(f)
                return settings.get("quiet_mode", False)
        except Exception:
            pass
    return False

def notify_finding(result: SkillScanResult):
    # Respect quiet mode — log but don't notify
    if is_quiet_mode():
        log.info(f"[quiet mode] {result.action} — {Path(result.file_path).name} "
                 f"(risk score: {result.risk_score})")
        return

    path = Path(result.file_path)
    critical_count = sum(1 for f in result.findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in result.findings if f.severity == "HIGH")

    if result.has_critical:
        title = "🛡️ CoworkGuard — Skill BLOCKED"
        parts = []
        if critical_count:
            parts.append(f"{critical_count} CRITICAL")
        if high_count:
            parts.append(f"{high_count} HIGH")
        msg = f"{path.name}: {', '.join(parts)} findings detected. Skill blocked."
    elif result.has_high:
        title = "⚠️ CoworkGuard — Skill Warning"
        msg = f"{path.name}: {high_count} HIGH severity findings. Review before use."
    else:
        return  # Don't notify for MEDIUM-only findings

    notify(title, msg)

# ─────────────────────────────────────────────
# File filter — decides if a file is a skill
# ─────────────────────────────────────────────

def is_skill_file(path: Path, in_high_traffic_dir: bool = False) -> bool:
    """Returns True if the file looks like a skill that should be scanned."""
    # Must have a scannable extension
    if path.suffix.lower() not in SKILL_EXTENSIONS:
        return False

    # In high-traffic directories (Downloads, Desktop), require stronger signals
    # to avoid noise from common files like package.json, manifest.json
    if in_high_traffic_dir:
        # Only scan if the filename is unambiguously a skill
        if path.name in {"SKILL.md", "skill.md", "claude_desktop_config.json", ".mcp.json"}:
            return True
        # Or if it's in a subdirectory with a skill-hint name
        parent_name = path.parent.name.lower()
        if parent_name in SKILL_DIR_HINTS and path.name not in {"package.json", "manifest.json"}:
            return True
        return False

    # For known skill directories — match by filename
    if path.name in SKILL_FILENAMES:
        return True

    # Match by directory name
    parts = {p.lower() for p in path.parts}
    if parts & SKILL_DIR_HINTS:
        return True

    return False

# ─────────────────────────────────────────────
# Watch mode
# ─────────────────────────────────────────────

class SkillWatcher:
    def __init__(self):
        self.scanner = SkillScanner()
        self._scanned = set()  # Avoid double-scanning

    def scan_and_report(self, path: Path):
        """Scan a file and log/notify results."""
        # Debounce — skip if already scanned this file recently
        key = (str(path), path.stat().st_mtime if path.exists() else 0)
        if key in self._scanned:
            return
        self._scanned.add(key)

        log.info(f"Scanning: {path}")
        result = self.scanner.scan_file(path)
        if result is None:
            return

        # Always write to audit log
        write_log(result.to_jsonl())

        if result.action == "CLEAN":
            log.info(f"✓ CLEAN — {path.name} (risk score: {result.risk_score})")
        else:
            log.warning(
                f"{'🚫 BLOCKED' if result.blocked else '⚠️  FLAGGED'} — "
                f"{path.name} | {len(result.findings)} findings | "
                f"risk score: {result.risk_score}"
            )
            for f in result.findings:
                log.warning(f"  [{f.severity:8}] line {f.line_number:4} — {f.pattern_name}: {f.match_preview}")

            notify_finding(result)

    def scan_existing(self):
        """Scan any existing skill files on startup."""
        log.info("Scanning existing skill files...")
        found = 0
        for watch_path in SKILL_WATCH_PATHS:
            if not watch_path.exists():
                continue
            in_high_traffic = watch_path in HIGH_TRAFFIC_DIRS
            for path in watch_path.rglob("*"):
                if path.is_file() and is_skill_file(path, in_high_traffic_dir=in_high_traffic):
                    self.scan_and_report(path)
                    found += 1
        log.info(f"Startup scan complete — {found} skill files checked")

    def watch(self):
        """
        Watch mode — monitors filesystem for new skill files.
        Uses watchdog if available, falls back to polling.
        """
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class Handler(FileSystemEventHandler):
                def __init__(self, watcher):
                    self.watcher = watcher

                def _check(self, src_path: str):
                    path = Path(src_path)
                    in_high_traffic = any(
                        str(path).startswith(str(d)) for d in HIGH_TRAFFIC_DIRS
                    )
                    if is_skill_file(path, in_high_traffic_dir=in_high_traffic):
                        time.sleep(0.5)
                        self.watcher.scan_and_report(path)

                def on_created(self, event):
                    if not event.is_directory:
                        self._check(event.src_path)

                def on_modified(self, event):
                    if not event.is_directory:
                        self._check(event.src_path)

            observer = Observer()
            handler = Handler(self)

            watched = []
            for watch_path in SKILL_WATCH_PATHS:
                watch_path.mkdir(parents=True, exist_ok=True)
                observer.schedule(handler, str(watch_path), recursive=True)
                watched.append(str(watch_path))

            # Also watch home directory at top level for Downloads/Desktop
            observer.schedule(handler, str(Path.home()), recursive=False)

            observer.start()
            log.info(f"👁  Watching {len(watched)} directories for new skills")
            for p in watched:
                log.info(f"   → {p}")

            notify("🛡️ CoworkGuard Skill Scanner", "Watching for new AI agent skills...")

            try:
                while observer.is_alive():
                    observer.join(timeout=1)
            except KeyboardInterrupt:
                observer.stop()
            observer.join()

        except ImportError:
            log.warning("watchdog not installed — falling back to polling (pip install watchdog)")
            self._poll_watch()

    def _poll_watch(self):
        """Fallback polling watcher if watchdog not available."""
        log.info("Polling for new skill files every 5 seconds...")
        seen = {}

        while True:
            for watch_path in SKILL_WATCH_PATHS:
                if not watch_path.exists():
                    continue
                for path in watch_path.rglob("*"):
                    if not path.is_file() or not is_skill_file(path):
                        continue
                    try:
                        mtime = path.stat().st_mtime
                        if str(path) not in seen or seen[str(path)] != mtime:
                            seen[str(path)] = mtime
                            self.scan_and_report(path)
                    except Exception:
                        pass
            time.sleep(5)

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def print_result(result: SkillScanResult):
    """Pretty-print a scan result to stdout."""
    print(f"\n{'═'*60}")
    print(f"CoworkGuard Skill Scanner")
    print(f"{'═'*60}")
    print(f"File:       {result.file_path}")
    print(f"Type:       {result.skill_type}")
    print(f"Action:     {result.action}")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Findings:   {len(result.findings)}")
    print(f"Hash:       {result.file_hash}")

    if result.findings:
        print(f"\nFindings:")
        for f in result.findings:
            blocked_tag = " [BLOCKED]" if f.blocked else ""
            print(f"  [{f.severity:8}] line {f.line_number:4} — {f.pattern_name:20} → {f.match_preview}{blocked_tag}")
    else:
        print(f"\n✓ No security issues detected")
    print(f"{'═'*60}\n")

def main():
    if len(sys.argv) < 2:
        # No arguments — start watch mode
        log.info("Starting CoworkGuard Skill Scanner in watch mode...")
        watcher = SkillWatcher()
        watcher.scan_existing()
        watcher.watch()
    else:
        # Scan specific file or directory
        target = Path(sys.argv[1])
        scanner = SkillScanner()

        if target.is_file():
            result = scanner.scan_file(target)
            if result:
                print_result(result)
                write_log(result.to_jsonl())
                sys.exit(1 if result.blocked else 0)
        elif target.is_dir():
            found = 0
            blocked = 0
            for path in target.rglob("*"):
                if path.is_file() and is_skill_file(path):
                    result = scanner.scan_file(path)
                    if result:
                        print_result(result)
                        write_log(result.to_jsonl())
                        found += 1
                        if result.blocked:
                            blocked += 1
            print(f"\nScanned {found} skill files. {blocked} blocked.")
            sys.exit(1 if blocked else 0)
        else:
            print(f"Error: {target} not found")
            sys.exit(1)

if __name__ == "__main__":
    main()
