"""
RedTeam Harness — Auto-Findings Extractor (v4.0 Assassin's Blade)
Scans tool output for known security indicators and classifies them into
structured findings with severity ratings. Auto-populates workflow state
so every task gets a machine-readable findings list without LLM involvement.

v4.0 enhancements:
  - 50+ cutting-edge detection patterns (SSRF, OAuth, cloud, K8s, Docker, GraphQL, XXE, NoSQL)
  - Context extraction: captures surrounding lines for richer evidence
  - Structured summaries: severity counts, category breakdown, asset grouping
  - Remediation mapping: each finding category maps to concrete fix steps
"""
import re
import bisect
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger("redteam.findings")

# ── Severity weights ──
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_SCORE = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# ── Context lines to capture around each match ──
CONTEXT_LINES = 2

# ══════════════════════════════════════════════════════════════════
# DETECTION PATTERNS — 50+ cutting-edge rules
# Each entry: (severity, category, title, regex, dedupe_key_regex)
# ══════════════════════════════════════════════════════════════════
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
    ("critical", "credential", "OAuth/JWT token leaked",
     r"(?:eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})", r"eyJ[A-Za-z0-9_-]+\.eyJ"),
    ("critical", "credential", "SAML assertion token captured",
     r"(?:SAMLResponse|saml:Assertion)[^\s]{20,}", r"SAMLResponse|saml:Assertion"),
    ("critical", "credential", "GCP service account key exposed",
     r"(?:\"type\"\s*:\s*\"service_account\")", r"service_account"),
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
     r"(?:anonymous login|no password|without password|auth bypass|unauthenticated)", r"anonymous login|auth bypass|unauthenticated"),
    ("high", "vulnerability", "SSRF vulnerability detected",
     r"(?:169\.254\.169\.254|metadata\.google\.internal|IMDS|ssrf)", r"169\.254\.169\.254|ssrf"),
    ("high", "vulnerability", "GraphQL introspection enabled",
     r"(?:__schema|__type|introspection|queryType|mutationType)", r"__schema|__type|introspection"),
    ("high", "vulnerability", "XXE injection possible",
     r"(?:ENTITY.*SYSTEM|DOCTYPE.*ENTITY|external entity|xml parser)", r"ENTITY.*SYSTEM|DOCTYPE.*ENTITY"),
    ("high", "vulnerability", "NoSQL injection indicator",
     r"(?:\$ne|\$gt|\$regex|\$where|nosql injection)", r"\$ne|\$gt|\$regex|\$where"),
    ("high", "vulnerability", "Kubernetes API exposed",
     r"(?:kubernetes|kubectl|kubelet|etcd|6443/tcp open)", r"kubernetes|kubelet|etcd|6443/tcp"),
    ("high", "vulnerability", "OAuth misconfiguration detected",
     r"(?:open redirect|redirect_uri.*attacker|client_secret|state.*bypass)", r"open redirect|redirect_uri|client_secret"),
    ("high", "vulnerability", "Cloud IAM privilege escalation vector",
     r"(?:iam:PassRole|sts:AssumeRole|iam:CreateLoginProfile|iam:AttachUserPolicy)", r"iam:PassRole|sts:AssumeRole|iam:CreateLoginProfile"),
    ("high", "vulnerability", "Docker socket mounted in container",
     r"(?:/var/run/docker\.sock|docker\.sock|MountType.*volume)", r"docker\.sock"),
    ("high", "vulnerability", "Container breakout possible (privileged)",
     r"(?:Privileged.*true|privileged.*mode|hostPID|hostNetwork)", r"Privileged.*true|hostPID|hostNetwork"),
    ("high", "vulnerability", "Broken Object-Level Authorization (BOLA/IDOR)",
     r"(?:IDOR|object-level authorization|broken access control)", r"IDOR|object-level authorization"),
    ("high", "vulnerability", "Mass assignment vulnerability",
     r"(?:mass assignment|role.*admin|isAdmin.*true)", r"mass assignment|role.*admin"),
    ("high", "vulnerability", "LDAP injection indicator",
     r"(?:ldap injection|\(.*cn=|\(.*uid=|LDAPResult)", r"ldap injection|cn=|uid="),
    ("high", "vulnerability", "Prototype pollution detected",
     r"(?:__proto__|constructor\[|prototype pollution)", r"__proto__|constructor\["),
    ("high", "vulnerability", "Request smuggling indicator",
     r"(?:Transfer-Encoding.*chunked.*Content-Length|CL\.TE|TE\.CL|smuggling)", r"Transfer-Encoding.*chunked|smuggling"),
    ("high", "vulnerability", "Insecure deserialization detected",
     r"(?:ObjectInputStream|pickle\.loads|yaml\.load|unserialize|__reduce__)", r"ObjectInputStream|pickle\.loads|yaml\.load|unserialize"),

    # ── MISCONFIGURATIONS (medium) ──
    ("medium", "misconfig", "Directory listing enabled",
     r"(?:Index of /|directory listing|autoindex)", r"Index of /|autoindex"),
    ("medium", "misconfig", "Exposed administrative interface",
     r"(?:/admin/|Admin Login|admin panel|/console|/jenkins|/grafana|/kibana)", r"/admin/|admin login|/console|/jenkins"),
    ("medium", "misconfig", "Sensitive file exposed",
     r"(?:/\.git/|\.env file|backup\.zip|phpinfo|/server-status)", r"\.git/|\.env|phpinfo|backup"),
    ("medium", "misconfig", "Debug/verbose error disclosure",
     r"(?:stack trace|debug mode|traceback|SQLSTATE|Fatal error:)", r"stack trace|SQLSTATE|Fatal error"),
    ("medium", "misconfig", "Weak TLS / SSL issues",
     r"(?:SSLv3|TLSv1\.0|weak cipher|RC4)", r"SSLv3|TLSv1\.0|RC4"),
    ("medium", "misconfig", "Default credentials detected",
     r"(?:admin[:/]admin|root[:/]root|guest[:/]guest|default password)", r"admin:admin|root:root"),
    ("medium", "misconfig", "CORS misconfiguration",
     r"(?:Access-Control-Allow-Origin.*\*|cors.*misconfiguration)", r"Access-Control-Allow-Origin.*\*"),
    ("medium", "misconfig", "Server information disclosure",
     r"(?:Server:|X-Powered-By:|X-AspNet-Version|X-Generator)", r"Server:|X-Powered-By:|X-AspNet"),
    ("medium", "misconfig", "Elasticsearch open access",
     r"(?:cluster_name.*\"|cluster_uuid|elastic.*open|/_cat/)", r"cluster_name|/_cat/"),
    ("medium", "misconfig", "Redis unauthenticated access",
     r"(?:redis_version|Redis.*unauthenticated|connected_clients)", r"redis_version|connected_clients"),
    ("medium", "misconfig", "MongoDB open access",
     r"(?:MongoDB.*open|ismaster.*true|rs\.status)", r"MongoDB.*open|ismaster"),
    ("medium", "misconfig", "Jenkins unauthenticated access",
     r"(?:/script|Jenkins.*unauthenticated|hudson.*model|jenkins.*dashboard)", r"/script|jenkins.*unauthenticated"),
    ("medium", "misconfig", "Kubernetes dashboard exposed",
     r"(?:kubernetes.*dashboard|/api/v1.*namespaces|kube.*proxy)", r"dashboard|kube.*proxy"),
    ("medium", "misconfig", "WordPress debug mode enabled",
     r"(?:WP_DEBUG.*true|wp-config.*debug|WordPress.*debug)", r"WP_DEBUG|wp-config.*debug"),
    ("medium", "misconfig", "Git repository exposed",
     r"(?:\.git/HEAD|git.*repository|refs/heads/main)", r"\.git/HEAD|refs/heads"),

    # ── WIRELESS (high/medium) ──
    ("high", "wireless", "WPA2 handshake captured",
     r"(?:WPA handshake|handshake captured|4-way handshake)", r"WPA handshake|handshake captured"),
    ("medium", "wireless", "Evil twin AP detected",
     r"(?:evil twin|rogue AP|deauth|disassoc)", r"evil twin|rogue AP|deauth"),
    ("high", "wireless", "WPS PIN vulnerability",
     r"(?:WPS.*pin|reaver.*wps|pixie dust)", r"WPS.*pin|pixie dust"),

    # ── INFO (low/info) ──
    ("low", "info", "Outdated service version",
     r"(?:Apache/1\.|nginx/1\.\d\.|OpenSSH_[0-7]\.|vsftpd 2\.3\.4)", r"Apache/1\.|OpenSSH_[0-7]\."),
    ("low", "info", "Open port discovered",
     r"(\d{1,5})/tcp\s+open", r"\d{1,5}/tcp open"),
    ("info", "info", "Version disclosure",
     r"(?:Server:|X-Powered-By:|nginx/|Apache/|IIS/)", r"Server:|X-Powered-By:"),
]


# ══════════════════════════════════════════════════════════════════
# REMEDIATION MAP — category → concrete fix steps
# ══════════════════════════════════════════════════════════════════
REMEDIATION_MAP: Dict[str, List[str]] = {
    "credential": [
        "Rotate compromised credentials immediately",
        "Revoke and regenerate API keys/tokens",
        "Move secrets to a vault (HashiCorp Vault, AWS Secrets Manager)",
        "Enable credential scanning in CI/CD pipelines",
    ],
    "vulnerability": [
        "Apply vendor patches or upgrade to latest stable version",
        "Implement WAF rules for the detected attack vector",
        "Enable input validation and output encoding",
        "Review and restrict network access to affected services",
    ],
    "misconfig": [
        "Harden configuration following CIS benchmarks",
        "Remove default credentials and enforce strong passwords",
        "Disable unnecessary services and features",
        "Enable HTTPS and security headers (CSP, HSTS, X-Frame-Options)",
    ],
    "wireless": [
        "Change WPA2/WPA3 passphrase to a strong random value",
        "Enable 802.1X enterprise authentication",
        "Implement wireless IDS to detect rogue APs",
        "Disable WPS on all access points",
    ],
}


class FindingsExtractor:
    """Scans tool output and extracts severity-classified findings with context."""

    def __init__(self):
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

    # ────────────────────────────────────────────────────────────
    # CORE SCAN
    # ────────────────────────────────────────────────────────────

    def scan(self, step_name: str, tool: str, stdout: str, stderr: str = "") -> List[Dict]:
        """
        Scan tool output for findings with surrounding context.
        Returns list of finding dicts with severity, category, title,
        evidence, context, source_step, source_tool, dedupe_key.
        """
        combined = f"{stdout}\n{stderr}"
        lines = combined.split("\n")
        # Pre-compute line offset map once (avoids O(n) per-match)
        line_offsets = []
        offset = 0
        for line in lines:
            line_offsets.append(offset)
            offset += len(line) + 1  # +1 for \n

        findings: List[Dict] = []
        seen_keys: set = set()

        for severity, category, title, regex, dedupe_re in self._compiled:
            for m in regex.finditer(combined):
                evidence = m.group(0).strip()[:200]
                if len(evidence) < 3:
                    continue

                # Dedupe
                dk_match = dedupe_re.search(evidence)
                dedupe_key = dk_match.group(0) if dk_match else evidence[:40]
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)

                # Extract surrounding context using pre-computed offsets
                context = self._extract_context(lines, line_offsets, m.start())

                findings.append({
                    "severity": severity,
                    "category": category,
                    "title": title,
                    "evidence": evidence,
                    "context": context,
                    "source_step": step_name,
                    "source_tool": tool,
                    "dedupe_key": dedupe_key,
                })

        return findings

    def _extract_context(self, lines: List[str], line_offsets: List[int], match_start: int) -> str:
        """Extract surrounding lines around a match for richer evidence.
        Uses binary search on pre-computed line_offsets (O(log n) per match)."""
        match_line = bisect.bisect_right(line_offsets, match_start) - 1
        match_line = max(0, match_line)

        start = max(0, match_line - CONTEXT_LINES)
        end = min(len(lines), match_line + CONTEXT_LINES + 1)
        return "\n".join(lines[start:end])[:500]

    # ────────────────────────────────────────────────────────────
    # STRUCTURED SUMMARIES
    # ────────────────────────────────────────────────────────────

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

    def group_by_category(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by category (credential, vulnerability, misconfig, etc.)."""
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            groups[f.get("category", "unknown")].append(f)
        return dict(groups)

    def group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity level."""
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            groups[f.get("severity", "info")].append(f)
        return dict(groups)

    def group_by_tool(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by source tool."""
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            groups[f.get("source_tool", "unknown")].append(f)
        return dict(groups)

    def compute_risk_score(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Compute a weighted risk score (0-100) from findings.
        Returns {score, breakdown, grade}.
        """
        if not findings:
            return {"score": 0, "breakdown": {}, "grade": "A+"}

        breakdown = {}
        total = 0.0
        for f in findings:
            sev = f.get("severity", "info")
            score = SEVERITY_SCORE.get(sev, 0)
            total += score
            breakdown[sev] = breakdown.get(sev, 0) + 1

        # Normalize to 0-100 (cap at 100)
        normalized = min(100.0, total)

        # Grade
        if normalized <= 5:
            grade = "A+"
        elif normalized <= 15:
            grade = "A"
        elif normalized <= 30:
            grade = "B"
        elif normalized <= 50:
            grade = "C"
        elif normalized <= 75:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": round(normalized, 1),
            "breakdown": breakdown,
            "grade": grade,
        }

    def get_remediation(self, category: str) -> List[str]:
        """Return remediation steps for a finding category."""
        return REMEDIATION_MAP.get(category, [
            "Investigate the finding manually",
            "Apply principle of least privilege",
            "Document and track for remediation",
        ])

    def to_report_section(self, findings: List[Dict]) -> str:
        """Generate a structured markdown findings section for reports."""
        if not findings:
            return "No findings extracted during this run.\n"

        lines = []
        severity_groups = self.group_by_severity(findings)
        risk = self.compute_risk_score(findings)

        # Risk summary header
        lines.append(f"**Overall Risk Score: {risk['score']}/100 (Grade: {risk['grade']})**")
        lines.append("")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = risk["breakdown"].get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

        # Per-severity detail sections
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = severity_groups.get(sev, [])
            if not sev_findings:
                continue

            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚪")
            lines.append(f"### {emoji} {sev.upper()} Findings ({len(sev_findings)})")
            lines.append("")

            for i, f in enumerate(sev_findings, 1):
                lines.append(f"**{i}. {f.get('title', 'Finding')}**")
                lines.append(f"- **Category**: {f.get('category', 'n/a')}")
                lines.append(f"- **Source**: `{f.get('source_tool', '')}` (step: {f.get('source_step', '')})")
                lines.append(f"- **Evidence**: `{f.get('evidence', '')[:300]}`")
                if f.get("context"):
                    lines.append(f"- **Context**:")
                    lines.append(f"  ```")
                    lines.append(f"  {f['context'][:300]}")
                    lines.append(f"  ```")
                # Add remediation
                remediation = self.get_remediation(f.get("category", ""))
                if remediation:
                    lines.append(f"- **Remediation**:")
                    for r in remediation[:3]:
                        lines.append(f"  - {r}")
                lines.append("")

        return "\n".join(lines)


# ── Module-level singleton ──
_extractor: Optional[FindingsExtractor] = None


def get_extractor() -> FindingsExtractor:
    """Return a shared FindingsExtractor instance."""
    global _extractor
    if _extractor is None:
        _extractor = FindingsExtractor()
    return _extractor


def extract_findings(step_name: str, tool: str, stdout: str, stderr: str = "") -> List[Dict]:
    """Convenience wrapper for scanning tool output."""
    return get_extractor().scan(step_name, tool, stdout, stderr)
