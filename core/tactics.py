"""
RedTeam Harness — Tactical Attack Engine (v4.0 Phase 5)
Rules-based system that maps findings to next actions, enabling
autonomous engagement continuation without an LLM planning round.

Each rule: <finding pattern> → <suggested tool + args template>
with a confidence score. When the orchestrator processes a finding,
the engine suggests the highest-confidence next step.
"""
import re
import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("redteam.tactics")

# ── Tactical Rules ──
# Format: (pattern, flags, tool, args_template, confidence, reasoning)
# Confidence: 0.0–1.0  (1.0 = always run, 0.5 = suggest, 0.2 = optional)
TACTICAL_RULES: List[Tuple[str, int, str, Dict[str, str], float, str]] = [
    # ── Recon → Vuln Scanning ──
    (r'(\d+)/(?:tcp|udp)\s+open\s+(?:http|https|www|nginx|apache|iis|tomcat)',
     re.IGNORECASE, "nikto_scan", {"target": "http://{host}:{port}"},
     0.85, "Web server detected — run Nikto scan"),
    (r'(\d+)/(?:tcp|udp)\s+open\s+ssh', re.IGNORECASE,
     "hydra_brute", {"target": "{host}", "service": "ssh", "port": "{port}"},
     0.60, "SSH open — optional brute-force"),
    (r'(\d+)/(?:tcp|udp)\s+open\s+(?:smb|netbios|microsoft-ds)',
     re.IGNORECASE, "enum4linux", {"target": "{host}"},
     0.90, "SMB open — enumerate shares & users"),
    (r'(\d+)/(?:tcp|udp)\s+open\s+(?:mysql|mariadb|postgresql|mssql|oracle|mongodb|redis)',
     re.IGNORECASE, "hydra_brute",
     {"target": "{host}", "service": "{service}", "port": "{port}"},
     0.50, "Database open — optional brute-force"),
    (r'(\d+)/(?:tcp|udp)\s+open\s+(?:rdp|ms-wbt-server)',
     re.IGNORECASE, "hydra_brute",
     {"target": "{host}", "service": "rdp", "port": "{port}"},
     0.45, "RDP open — optional brute-force"),
    (r'(\d+)/(?:tcp|udp)\s+open\s+(?:ftp|vsftpd|proftpd)',
     re.IGNORECASE, "hydra_brute",
     {"target": "{host}", "service": "ftp", "port": "{port}"},
     0.40, "FTP open — optional brute-force"),

    # ── Web Findings → Deeper Scanning ──
    (r'(?:login|admin|dashboard|panel|console|cpannel|cpanel|wp-admin|phpmyadmin)',
     re.IGNORECASE, "hydra_brute",
     {"target": "{host}", "service": "http-form", "port": "{port}"},
     0.55, "Login portal found — optional form brute-force"),
    (r'(?:\.php\?|\.asp\?|\.jsp\?|\.aspx\?)', re.IGNORECASE,
     "sqlmap_scan", {"target": "{url}"},
     0.75, "Dynamic parameter detected — test for SQL injection"),
    (r'(?:upload|file_upload|attachment)', re.IGNORECASE,
     "gobuster", {"target": "http://{host}", "wordlist": "directory-list-2.3-medium.txt"},
     0.40, "Upload endpoint — enumerate more paths"),
    (r'WordPress', re.IGNORECASE,
     "wpscan", {"target": "http://{host}"},
     0.90, "WordPress detected — full WP scan"),

    # ── Credentials → Lateral Movement ──
    (r'(?:password|passwd|pwd)\s*[:=]\s*(\S+)', re.IGNORECASE,
     "crackmapexec_exec", {"target": "{host}", "username": "{user}", "password": "{password}"},
     0.80, "Credentials found — try lateral movement with CME"),
    (r'(?:ntlm|nt hash|lm hash|ntlmv2)[:\s]*([0-9a-fA-F]{32,})', re.IGNORECASE,
     "hashcat_crack", {"hash": "{hash}", "mode": "1000"},
     0.95, "NT hash found — crack with hashcat"),
    (r'(?:kerberos|krb5|as-rep|tgt|service ticket)', re.IGNORECASE,
     "impacket_tools", {"module": "GetNPUsers", "target": "{host}"},
     0.85, "Kerberos — attempt AS-REP roasting"),

    # ── Vuln Findings → Exploitation ──
    (r'(?:eternalblue|ms17-?010|smbv1)', re.IGNORECASE,
     "msfvenom_payload", {"target": "{host}", "exploit": "windows/smb/ms17_010_eternalblue"},
     0.90, "EternalBlue — MS17-010 exploitation"),
    (r'(?:log4j|log4shell|cve-2021-44228)', re.IGNORECASE,
     "nuclei", {"target": "{url}", "template": "cves/2021/CVE-2021-44228.yaml"},
     0.95, "Log4Shell detected — verify with Nuclei"),
    (r'(?:spring4shell|springshell|cve-2022-22965)', re.IGNORECASE,
     "nuclei", {"target": "{url}", "template": "cves/2022/CVE-2022-22965.yaml"},
     0.95, "Spring4Shell detected — verify"),

    # ── Post-exploitation signals ──
    (r'(?:root:|SYSTEM|NT AUTHORITY\\\\SYSTEM|Administrator:)',
     re.IGNORECASE, "bloodhound_analyze",
     {"target": "{host}"}, 0.70, "Elevated access — map AD with BloodHound"),
    (r'(?:docker\.sock|/var/run/docker)', re.IGNORECASE,
     "socat", {"connect_addr": "{host}:{port}"},
     0.75, "Docker socket — container escape path"),
    (r'(?:imds|169\.254\.169\.254)', re.IGNORECASE,
     "curl_request", {"url": "http://169.254.169.254/latest/meta-data/"},
     0.85, "Cloud metadata — IMDS enumeration"),

    # ── Directory listing / info leaks → recon ──
    (r'(?:directory listing|index of /)', re.IGNORECASE,
     "gobuster", {"target": "http://{host}", "wordlist": "directory-list-2.3-medium.txt"},
     0.65, "Directory listing — enumerate more"),
    (r'(?:\.git/|\.svn/|\.env|\.aws/|\.config)', re.IGNORECASE,
     "curl_request", {"url": "{url}"}, 0.80,
     "Sensitive file exposure — fetch contents"),
]

# ── Confidence thresholds ──
AUTO_RUN_THRESHOLD = 0.85   # Auto-run without asking
SUGGEST_THRESHOLD = 0.50    # Suggest in chat but require confirmation
# Below 0.50: ignored unless autonomous mode


class TacticalEngine:
    """Maps findings → next actions using predefined rules (+ vector memory)."""

    def __init__(self):
        self._total_suggestions = 0
        self._auto_actions = 0
        self._memory = None  # optional VectorMemory for cross-session memory
        self._memory_suggestions_count = 0

    def set_memory(self, memory) -> None:
        """Attach the harness's VectorMemory so suggestions can leverage
        prior sessions (e.g. open port found but never exploited → suggest
        exploitation; service down last time but now up → suggest re-test)."""
        self._memory = memory

    def evaluate(self, findings: List[Dict[str, Any]],
                 context: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Evaluate findings against tactical rules and return suggested actions.
        Each action: {tool, args, confidence, reasoning, auto_run}.

        When vector memory is attached, findings that carry target context are
        cross-checked against prior sessions (v5.5):
          - a port/service that prior sessions found open but never exploited
            → raise an exploitation suggestion (hydra/sqlmap/…)
          - a service that was DOWN in a prior session but is now UP (i.e. the
            current finding sees it open) → suggest re-testing it
        These memory-derived suggestions are tagged with
        `memory_grounded: true` and `prior_session: <target>`.
        """
        suggestions = []
        context = context or {}

        for finding in findings:
            text = self._finding_to_text(finding)
            if not text:
                continue

            for pattern, flags, tool, args_tmpl, confidence, reasoning in TACTICAL_RULES:
                match = re.search(pattern, text, flags)
                if not match:
                    continue

                # Fill args template with captured groups + context
                args = dict(args_tmpl)
                resolved = self._resolve_args(args, match, finding, context)
                if not resolved:
                    continue

                suggestions.append({
                    "tool": tool,
                    "args": resolved,
                    "confidence": confidence,
                    "reasoning": reasoning,
                    "auto_run": confidence >= AUTO_RUN_THRESHOLD,
                    "triggered_by": finding.get("title", finding.get("description", ""))[:80],
                })
                self._total_suggestions += 1

        # ── v5.5: memory-grounded suggestions (vector memory attached) ──
        if self._memory is not None:
            suggestions.extend(self._memory_suggestions(findings, context))

        # Deduplicate (same tool+args = single suggestion, keep highest confidence)
        seen = {}
        unique = []
        for s in suggestions:
            key = f"{s['tool']}:{json.dumps(s['args'], sort_keys=True)}"
            if key not in seen or s["confidence"] > seen[key].confidence:
                seen[key] = s
        unique = sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)

        self._auto_actions += sum(1 for s in unique if s["auto_run"])
        return unique

    def _memory_suggestions(self, findings: List[Dict[str, Any]],
                            context: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Query vector memory for prior-session context on each finding's target:
          - Prior open port/service never exploited → suggest exploitation.
          - Prior DOWN service now OPEN in this session → suggest re-testing.
        Never raises; missing/unfitted memory returns [].
        """
        out = []
        try:
            from core.vector_memory import VectorMemory  # noqa: F401
            for finding in findings:
                target = finding.get("target") or context.get("host")
                text = self._finding_to_text(finding)
                if not target or not text:
                    continue
                # Pull the top prior findings for this target
                prior = self._memory.query_by_target(str(target), top_k=10)
                if not prior:
                    continue
                port_m = re.search(r'(\d{2,5})/(?:tcp|udp)\s+open\s+(\S+)', text)
                if not port_m:
                    continue
                port, service = port_m.group(1), port_m.group(2)
                # 1. Open now + seen open before but never exploited → exploit
                exploited_before = any(
                    self._looks_exploited(p) for p in prior)
                if not exploited_before:
                    # Suggest exploitation of the discovered service
                    exploit_map = {
                        "ssh": ("hydra_brute", {"target": target, "service": "ssh",
                                                  "port": port}, 0.70,
                                 f"Memory: {target}:{port} ({service}) was open in a "
                                 f"prior session but never exploited — attempt exploitation now"),
                        "http": ("nikto_scan", {"target": f"http://{target}:{port}"},
                                  0.65,
                                  f"Memory: {target}:{port} HTTP service was never "
                                  f"scanned for vulns in prior sessions — scan now"),
                        "https": ("nikto_scan", {"target": f"https://{target}:{port}"},
                                   0.65,
                                   f"Memory: {target}:{port} HTTPS service was never "
                                   f"vuln-scanned — scan now"),
                        "smb": ("enum4linux", {"target": target}, 0.75,
                                f"Memory: SMB on {target} was open but never "
                                f"enumerated in prior sessions — enumerate now"),
                    }
                    mapped = exploit_map.get(service.lower())
                    if mapped:
                        tool, args, conf, reason = mapped
                        out.append({
                            "tool": tool, "args": args, "confidence": conf,
                            "reasoning": reason,
                            "auto_run": conf >= AUTO_RUN_THRESHOLD,
                            "memory_grounded": True,
                            "prior_session": target,
                            "triggered_by": f"memory:{target}:{port}",
                        })
                        self._memory_suggestions_count += 1
                # 2. Down before + open now → re-test (service recently appeared)
                was_down = any(
                    "down" in str(p.get("title", "")).lower() or
                    "closed" in str(p.get("title", "")).lower() or
                    "no response" in str(p.get("evidence", "")).lower()
                    for p in prior)
                if was_down:
                    out.append({
                        "tool": "nmap_scan",
                        "args": {"target": target, "ports": f"{port}"},
                        "confidence": 0.60,
                        "reasoning": f"Memory: {target}:{port} ({service}) was DOWN/"
                                     f"closed in a prior session but is OPEN now — "
                                     f"re-test the newly-exposed service",
                        "auto_run": False,
                        "memory_grounded": True,
                        "prior_session": target,
                        "triggered_by": f"memory-revive:{target}:{port}",
                    })
                    self._memory_suggestions_count += 1
        except Exception as e:
            logger.warning(f"Memory-grounded suggestions skipped: {e}")
        return out

    @staticmethod
    def _looks_exploited(prior_finding: Dict[str, Any]) -> bool:
        """Heuristic: does a prior session show exploitation of this target?"""
        blob = " ".join(str(prior_finding.get(k, "")) for k in
                        ("title", "description", "evidence", "source_tool"))
        blob = blob.lower()
        return any(k in blob for k in ("exploit", "meterpreter", "shell",
                                       "gained access", "session opened",
                                       "pwned", "credential"))

    def _finding_to_text(self, finding: Dict[str, Any]) -> str:
        """Convert a finding dict to a searchable text blob."""
        parts = []
        for key in ("title", "description", "evidence", "raw_output",
                     "stdout_preview", "severity"):
            val = finding.get(key, "")
            if val:
                parts.append(str(val))
        return " ".join(parts)

    def _resolve_args(self, args: Dict[str, str], match: re.Match,
                      finding: Dict, context: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Resolve {host}, {port}, {url}, {user}, {password}, {hash} placeholders."""
        resolved = {}
        groups = match.groups()
        evidence = finding.get("evidence", "") or finding.get("description", "") or ""
        raw = finding.get("raw_output", "") or finding.get("stdout_preview", "") or ""

        for key, value in args.items():
            val = str(value)

            # Try regex groups first
            if "{host}" in val:
                host = (groups[0] if groups else None) or \
                       context.get("host") or \
                       re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', evidence)
                val = val.replace("{host}", (host.group(1) if hasattr(host, 'group') else
                                            (host if isinstance(host, str) else "127.0.0.1")))

            if "{port}" in val:
                port = (groups[0] if groups and groups[0].isdigit() else None) or \
                       re.search(r'(\d{2,5})/(?:tcp|udp)\s+open', raw)
                val = val.replace("{port}",
                                  (port.group(1) if hasattr(port, 'group') else
                                   (port if isinstance(port, str) else "80")))

            if "{url}" in val:
                url = re.search(r'(https?://\S+)', evidence) or \
                      re.search(r'(https?://\S+)', raw)
                val = val.replace("{url}",
                                  url.group(1) if url else
                                  f"http://{context.get('host', '127.0.0.1')}")

            if "{service}" in val:
                svc = re.search(r'(\d+)/(?:tcp|udp)\s+open\s+(\w+)', raw)
                val = val.replace("{service}", svc.group(2) if svc else "unknown")

            if "{user}" in val:
                user = re.search(r'(?:user(?:name)?|login)\s*[:=]\s*(\S+)', evidence,
                                 re.IGNORECASE) or context.get("username")
                val = val.replace("{user}", (user.group(1) if hasattr(user, 'group') else
                                            (user if isinstance(user, str) else "admin")))

            if "{password}" in val:
                pw = re.search(r'(?:password|passwd|pwd)\s*[:=]\s*(\S+)', evidence,
                               re.IGNORECASE) or context.get("password")
                val = val.replace("{password}", (pw.group(1) if hasattr(pw, 'group') else
                                                (pw if isinstance(pw, str) else "password")))

            if "{hash}" in val:
                h = re.search(r'([0-9a-fA-F]{32,})', evidence) or \
                    re.search(r'([0-9a-fA-F]{32,})', raw)
                val = val.replace("{hash}",
                                  h.group(1) if h else "0" * 32)

            # Skip arg if any placeholder remains unresolved
            if "{" in val and "}" in val:
                continue

            resolved[key] = val

        return resolved if resolved else None

    def get_auto_run_actions(self, findings: List[Dict[str, Any]],
                             context: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Return only actions that should auto-run (confidence >= AUTO_RUN_THRESHOLD)."""
        return [s for s in self.evaluate(findings, context) if s["auto_run"]]

    def get_stats(self) -> Dict[str, Any]:
        """Return tactical engine statistics."""
        return {
            "rules_loaded": len(TACTICAL_RULES),
            "total_suggestions": self._total_suggestions,
            "auto_actions_taken": self._auto_actions,
            "memory_suggestions": self._memory_suggestions_count,
            "memory_grounded": self._memory is not None,
        }


# Need json at module level for dedup
import json