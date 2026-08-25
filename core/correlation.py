"""
RedTeam Harness — Finding Correlation & Auto-Remediation (v4.0)
Links auto-extracted findings into coherent attack paths, scores them, and
maps each path/finding to concrete remediation steps.

Fully offline: a static rule table (no LLM) keyed by finding title keywords,
category, and dedupe_key. Correlates findings across steps and targets by
shared evidence tokens (IPs, hosts, hash prefixes).
"""
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("redteam.correlation")

# ── Severity weights ──
SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


# ── Correlation rule table ──
# Each rule: trigger keywords (match finding title/dedupe_key), companion
# keywords (optional findings that strengthen the path), path title, severity,
# remediation steps.
CORRELATION_RULES = [
    {
        "id": "smb_compromise",
        "path_title": "SMB / EternalBlue Lateral Movement Path",
        "trigger": ["eternalblue", "ms17-010", "smbv1"],
        "companions": ["445/tcp", "anonymous login", "no password"],
        "severity": "critical",
        "remediation": [
            "Apply MS17-010 security patch to all Windows hosts",
            "Disable SMBv1 across the domain (registry + GPO)",
            "Restrict SMB traffic (445) at the host firewall / network segmentation",
            "Monitor for suspicious SMB sessions and pass-the-hash activity",
        ],
    },
    {
        "id": "cred_exfil",
        "path_title": "Credential Exfiltration Path (DB / web → hashes)",
        "trigger": ["sql injection", "is vulnerable", "sqlmap"],
        "companions": ["hash", "password", "32 hex", "dump"],
        "severity": "critical",
        "remediation": [
            "Fix SQL injection with parameterized queries / prepared statements",
            "Rotate all credentials exposed in the leaked database",
            "Enable WAF rules and input validation on the vulnerable endpoints",
            "Hash stored passwords with bcrypt/argon2 and enforce MFA",
        ],
    },
    {
        "id": "ad_cred_theft",
        "path_title": "Active Directory Credential Theft Path",
        "trigger": ["kerberos", "krb5tgs", "krb5asrep", "dcsync", "nt hash", "secretsdump"],
        "companions": ["password", "hash", "domain"],
        "severity": "critical",
        "remediation": [
            "Enforce AES Kerberos encryption (disable RC4/HMAC-MD5)",
            "Rotate service account passwords and use group-managed service accounts (gMSA)",
            "Restrict replication rights (DCSync) to legitimate domain controllers",
            "Monitor event ID 4769/4770 for abnormal service ticket requests",
        ],
    },
    {
        "id": "container_escape",
        "path_title": "Container Escape / Host Takeover Path",
        "trigger": ["docker", "/containers/json", "2375/tcp", "privileged"],
        "companions": ["mount", "/etc/", "hostconfig"],
        "severity": "critical",
        "remediation": [
            "Never expose the Docker API (2375/2376) to untrusted networks",
            "Run containers with seccomp/AppArmor profiles and no privileged flag",
            "Use read-only root filesystems and drop all Linux capabilities",
            "Pin container images and scan with trivy/grype in CI/CD",
        ],
    },
    {
        "id": "web_disclosure",
        "path_title": "Web Application Information Disclosure Path",
        "trigger": ["directory listing", "index of", ".git", ".env", "admin login",
                    "/admin/", "/console", "phpinfo", "backup"],
        "companions": ["200", "version", "server:"],
        "severity": "medium",
        "remediation": [
            "Disable directory listing on all web servers",
            "Block access to .git/.env/backup files at the web server layer",
            "Restrict admin panels to allow-listed IPs + enforce MFA",
            "Remove default pages, sample files, and version banners",
        ],
    },
    {
        "id": "known_cve",
        "path_title": "Known Vulnerability Exploitation Path",
        "trigger": ["cve-"],
        "companions": ["open", "version", "exploit"],
        "severity": "high",
        "remediation": [
            "Apply vendor patches for the identified CVEs",
            "Subscribe to CVE feeds and enforce patch SLAs",
            "Run continuous vulnerability scanning (nuclei/nessus) on the asset",
            "Compensate with WAF rules / IPS signatures until patched",
        ],
    },
    {
        "id": "imds_abuse",
        "path_title": "Cloud Metadata / IAM Credential Theft Path",
        "trigger": ["169.254.169.254", "metadata", "access_token", "aws access key",
                    "accountkey", "clientsecret"],
        "companions": ["iam", "token", "credential"],
        "severity": "critical",
        "remediation": [
            "Block IMDS access from web-facing proxies / SSRF-prone apps",
            "Enforce IMDSv2 with session tokens (AWS)",
            "Rotate any leaked cloud credentials immediately",
            "Restrict IAM roles with least-privilege policies",
        ],
    },
    {
        "id": "wifi_psk",
        "path_title": "Wireless Network Compromise Path",
        "trigger": ["wpa", "handshake", "key found", "psk"],
        "companions": ["deauth", "bssid"],
        "severity": "high",
        "remediation": [
            "Replace WPA2-PSK with WPA2/WPA3-Enterprise (802.1X)",
            "Enforce a strong PSK policy (16+ random chars) for legacy networks",
            "Deploy Rogue AP detection / wireless intrusion prevention",
        ],
    },
]

# ── Per-finding remediation by category/title keyword (fallback) ──
CATEGORY_REMEDIATION = {
    "credential": ["Rotate the exposed credential immediately", "Enforce MFA on all accounts"],
    "vulnerability": ["Apply vendor security patches", "Run a follow-up scan to verify"],
    "misconfig": ["Harden the misconfiguration per vendor hardening guide"],
    "info": ["No action required — informational only"],
}


class FindingCorrelator:
    """Links findings into scored attack paths and maps remediation."""

    def __init__(self):
        # Pre-compile trigger/companion keyword regexes
        self._rules = []
        for rule in CORRELATION_RULES:
            compiled = {
                "id": rule["id"],
                "path_title": rule["path_title"],
                "severity": rule["severity"],
                "remediation": rule["remediation"],
                "trigger": [re.compile(re.escape(k), re.IGNORECASE) for k in rule["trigger"]],
                "companions": [re.compile(re.escape(k), re.IGNORECASE) for k in rule["companions"]],
            }
            self._rules.append(compiled)

    # ═══════════════════════════════════════════════════════════════
    # Token extraction (shared evidence linking across steps/targets)
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _extract_tokens(finding: Dict[str, Any]) -> List[str]:
        """Extract linkable tokens from a finding's evidence (IPs, hosts, hashes)."""
        evidence = f"{finding.get('evidence', '')} {finding.get('title', '')}"
        tokens = set()
        tokens.update(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", evidence))
        tokens.update(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", evidence))
        # Hash prefixes (first 12 hex chars of long hashes)
        for m in re.findall(r"\b([0-9a-fA-F]{32,})\b", evidence):
            tokens.add(m[:12].lower())
        return sorted(tokens)

    @staticmethod
    def _finding_text(finding: Dict[str, Any]) -> str:
        """Combined searchable text of a finding."""
        return " ".join([
            str(finding.get("title", "")),
            str(finding.get("evidence", "")),
            str(finding.get("dedupe_key", "")),
        ])

    # ═══════════════════════════════════════════════════════════════
    # Correlation
    # ═══════════════════════════════════════════════════════════════

    def correlate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate findings into attack paths.
        Returns a list of path dicts:
          {id, title, severity, score, findings: [...], remediation: [...], tokens: [...]}
        """
        if not findings:
            return []

        paths = []

        # Group findings by shared tokens (evidence linkage)
        token_map: Dict[str, List[Dict]] = {}
        for f in findings:
            for tok in self._extract_tokens(f):
                token_map.setdefault(tok, []).append(f)

        for rule in self._rules:
            triggers = [f for f in findings
                        if any(rx.search(self._finding_text(f)) for rx in rule["trigger"])]
            if not triggers:
                continue

            # Companions: findings matching companion keywords AND sharing a
            # token with a trigger finding. When NEITHER side has extractable
            # tokens, fall back to keyword match only (small evidence corpus).
            companions = []
            trigger_tokens = set()
            for t in triggers:
                trigger_tokens.update(self._extract_tokens(t))
            for f in findings:
                if f in triggers:
                    continue
                if any(rx.search(self._finding_text(f)) for rx in rule["companions"]):
                    ft = set(self._extract_tokens(f))
                    if trigger_tokens and ft:
                        # Both sides have tokens → require overlap to avoid
                        # pulling in unrelated findings
                        if not (ft & trigger_tokens):
                            continue
                    elif not trigger_tokens and not ft:
                        # Neither side has tokens → keyword match is the best we
                        # can do (small/no-evidence corpus)
                        pass
                    else:
                        # Only one side has tokens → require the token-less
                        # finding to at least share the rule's context by not
                        # admitting it when the trigger has tokens it lacks
                        if trigger_tokens and not ft:
                            continue
                    companions.append(f)

            members = triggers + companions
            # Severity: rule severity, boosted if many companions
            sev = rule["severity"]
            if len(companions) >= 2 and SEV_WEIGHT.get(sev, 3) >= 4:
                sev = "critical"
            score = SEV_WEIGHT.get(sev, 3) + min(len(companions), 3)

            paths.append({
                "id": rule["id"],
                "title": rule["path_title"],
                "severity": sev,
                "score": score,
                "findings": [f.get("dedupe_key") or f.get("title") for f in members][:20],
                "evidence": [f.get("evidence", "")[:160] for f in members[:5]],
                "remediation": rule["remediation"],
                "tokens": sorted(trigger_tokens)[:10],
            })

        # Sort by score desc
        paths.sort(key=lambda p: p["score"], reverse=True)
        return paths

    # ═══════════════════════════════════════════════════════════════
    # Remediation mapping
    # ═══════════════════════════════════════════════════════════════

    def remediation_for(self, finding: Dict[str, Any]) -> List[str]:
        """Map a single finding to remediation steps (rule table then category)."""
        text = self._finding_text(finding)
        for rule in self._rules:
            if any(rx.search(text) for rx in rule["trigger"]):
                return rule["remediation"]
        return CATEGORY_REMEDIATION.get(
            finding.get("category", "info"), CATEGORY_REMEDIATION["info"])

    def augment_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return findings with a 'remediation' list attached."""
        out = []
        for f in findings:
            f = dict(f)
            f["remediation"] = self.remediation_for(f)
            out.append(f)
        return out

    # ═══════════════════════════════════════════════════════════════
    # Report helpers
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def paths_to_markdown(paths: List[Dict[str, Any]]) -> str:
        """Render correlated paths as markdown section content."""
        if not paths:
            return "No correlated attack paths identified.\n"
        lines = []
        for p in paths:
            lines.append(f"### {p['severity'].upper()}: {p['title']}")
            lines.append(f"- **Score**: {p['score']}")
            if p.get("evidence"):
                for ev in p["evidence"]:
                    lines.append(f"- **Evidence**: `{ev}`")
            lines.append("**Remediation:**")
            for r in p["remediation"]:
                lines.append(f"  - {r}")
            lines.append("")
        return "\n".join(lines)


# ── Module-level singleton ──
_correlator: Optional[FindingCorrelator] = None


def get_correlator() -> FindingCorrelator:
    """Return a shared FindingCorrelator instance."""
    global _correlator
    if _correlator is None:
        _correlator = FindingCorrelator()
    return _correlator


def correlate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convenience wrapper."""
    return get_correlator().correlate(findings)
