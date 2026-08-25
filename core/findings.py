"""
RedTeam Harness — Auto-Findings Extractor (v4.0 Assassin's Blade)
Scans tool output for known security indicators and classifies them into
structured findings with severity ratings. Auto-populates workflow state
so every task gets a machine-readable findings list without LLM involvement.
"""
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("redteam.findings")

# ── Severity weights ──
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Detection patterns ──
# Each entry: (severity, category, title, regex, dedupe_key_regex)
FINDING_PATTERNS: List[tuple] = [
    # ── CREDENTIALS (critical) ──
    ("critical", "credential", "Kerberos TGS ticket captured (Kerberoasting)",
     r"\$krb5tgs\$[^\s\"']+", r"\$krb5tgs\$[A-Za-z0-9_\-.]*"),
    ("critical", "credential", "Kerberos AS-REP ticket captured (AS-REP Roasting)",
     r"\$krb5asrep\$[^\s\"']+", r"\$krb5asrep\$[A-Za-z0-9_\-.]*"),
    ("critical", "credential", "NT hash captured (DCSync / secretsdump)",
     r"(?:^|\s)([0-9a-fA-F]{32}):[0-9a-fA-F]{32}", r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}"),
    ("critical", "credential", "AWS access key found",
     r"AKIA[0-9A-Z]{16}", r"AKIA[0-9A-Z]{16}"),
    ("critical", "credential", "Azure/other cloud secret found",
     r"(?:AccountKey|SharedAccessKey|ClientSecret)[=:][^\s\"']+", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("critical", "credential", "Private key material exposed",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", r"PRIVATE KEY"),
    ("critical", "credential", "Plaintext password in output",
     r"(?:password|passwd|pwd)[\s:=]+[\"']?[^\s\"']{4,}", r"password[\s:=]+[\"']?[^\s\"']{4,}"),
    ("high", "credential", "API key / bearer token exposed",
     r"(?:api[_-]?key|access[_-]?token|bearer)[\s:=]+[\"']?[A-Za-z0-9_\-\.]{16,}",
     r"(?:api[_-]?key|access[_-]?token|bearer)"),

    # ── VULNERABILITIES (high) ──
    ("high", "vulnerability", "CVE reference detected",
     r"CVE-\d{4}-\d{4,7}", r"CVE-\d{4}-\d{4,7}"),
    ("high", "vulnerability", "SQL injection indicator",
     r"(?:is vulnerable|sql injection|union select|error in your SQL)", r"sql injection|is vulnerable"),
    ("high", "vulnerability", "Known exploit suggested",
     r"(?:exploit found|searchsploit.*\d{5}|EDB-ID[: ]?\d+)", r"EDB-ID|exploit"),
    ("high", "vulnerability", "SMBv1 / EternalBlue indicator",
     r"(?:ms17-010|eternalblue|SMBv1)", r"ms17-010|eternalblue"),
    ("high", "vulnerability", "Log4Shell indicator",
     r"(?:\$\{jndi:|log4j|CVE-2021-44228)", r"\$\{jndi:|CVE-2021-44228"),
    ("high", "vulnerability", "Exposed Docker/container API",
     r"(?:Docker API|2375/tcp open|/containers/json|/v\d+\.\d+/containers)", r"2375/tcp|/containers/json"),
    ("high", "vulnerability", "Unauthenticated service access",
     r"(?:anonymous login|no password|without password|auth bypass|unauthenticated)",
     r"anonymous login|auth bypass|unauthenticated"),

    # ── MISCONFIGURATIONS (medium) ──
    ("medium", "misconfig", "Directory listing enabled",
     r"(?:Index of /|directory listing|autoindex)", r"Index of /|autoindex"),
    ("medium", "misconfig", "Exposed administrative interface",
     r"(?:/admin/|Admin Login|admin panel|/console|/jenkins|/grafana|/kibana)",
     r"/admin/|admin login|/console|/jenkins"),
    ("medium", "misconfig", "Sensitive file exposed",
     r"(?:/\.git/|\.env file|backup\.zip|phpinfo|/server-status)", r"\.git/|\.env|phpinfo|backup"),
    ("medium", "misconfig", "Debug/verbose error disclosure",
     r"(?:stack trace|debug mode|traceback|SQLSTATE|Fatal error:)", r"stack trace|SQLSTATE|Fatal error"),
    ("medium", "misconfig", "Weak TLS / SSL issues",
     r"(?:SSLv3|TLSv1\.0|weak cipher|RC4)", r"SSLv3|TLSv1\.0|RC4"),
    ("medium", "misconfig", "Default credentials detected",
     r"(?:admin[:/]admin|root[:/]root|guest[:/]guest|default password)", r"admin:admin|root:root"),

    # ── INFO (low/info) ──
    ("low", "info", "Outdated service version",
     r"(?:Apache/1\.|nginx/1\.\d\.|OpenSSH_[0-7]\.|vsftpd 2\.3\.4)", r"Apache/1\.|OpenSSH_[0-7]\."),
    ("low", "info", "Open port discovered",
     r"(\d{1,5})/tcp\s+open", r"\d{1,5}/tcp open"),
    ("info", "info", "Version disclosure",
     r"(?:Server:|X-Powered-By:|nginx/|Apache/|IIS/)", r"Server:|X-Powered-By:"),
]


class FindingsExtractor:
    """Scans tool output and extracts severity-classified findings."""

    def __init__(self):
        # Pre-compile regexes once
        self._compiled = []
        for severity, category, title, pattern, dedupe in FINDING_PATTERNS:
            try:
                self._compiled.append((
                    severity, category, title,
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE),
                    re.compile(dedupe, re.IGNORECASE),
                ))
            except re.error as e:
                logger.warning(f"Bad finding pattern '{pattern}': {e}")

    def scan(self, step_name: str, tool: str, stdout: str, stderr: str = "") -> List[Dict]:
        """
        Scan tool output for findings.
        Returns a list of finding dicts:
          {severity, category, title, evidence, source_step, source_tool, dedupe_key}
        """
        combined = f"{stdout}\n{stderr}"
        findings: List[Dict] = []
        seen_keys: set = set()

        for severity, category, title, regex, dedupe_re in self._compiled:
            for m in regex.finditer(combined):
                evidence = m.group(0).strip()[:200]
                if len(evidence) < 3:
                    continue
                # Dedupe by the dedupe key within this scan
                dk_match = dedupe_re.search(evidence)
                dedupe_key = dk_match.group(0) if dk_match else evidence[:40]
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)

                findings.append({
                    "severity": severity,
                    "category": category,
                    "title": title,
                    "evidence": evidence,
                    "source_step": step_name,
                    "source_tool": tool,
                    "dedupe_key": dedupe_key,
                })

        return findings

    def summarize(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        return counts

    def worst_severity(self, findings: List[Dict]) -> str:
        """Return the worst severity present (or 'none')."""
        worst = "none"
        worst_w = -1
        for f in findings:
            w = SEVERITY_ORDER.get(f.get("severity", "info"), 0)
            if w > worst_w:
                worst_w = w
                worst = f["severity"]
        return worst


# ── Module-level singleton for convenience ──
_extractor: Optional[FindingsExtractor] = None


def get_extractor() -> FindingsExtractor:
    """Return a shared FindingsExtractor instance."""
    global _extractor
    if _extractor is None:
        _extractor = FindingsExtractor()
    return _extractor


def extract_findings(step_name: str, tool: str, stdout: str, stderr: str = "") -> List[Dict]:
    """Convenience wrapper."""
    return get_extractor().scan(step_name, tool, stdout, stderr)
