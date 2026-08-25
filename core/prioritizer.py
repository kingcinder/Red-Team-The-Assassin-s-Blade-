"""
RedTeam Harness — Target Prioritizer (v4.0 Phase 7)
Scores hosts by attackability based on open ports, services, and
findings to produce a priority-ordered multi-target execution plan.

Scoring dimensions:
  - Port Score: weighted by service criticality (higher = more attack surface)
  - Vuln Score: CVE severity from findings (CVSS mapped)
  - Exposure Score: external vs internal, number of open ports
  - Exploitability: combination of known vulns + accessible services

Output: ordered list of (target, score, breakdown, suggested_workflow).
"""
import re
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger("redteam.prioritizer")

# ── Service criticality weights (0.0–1.0) ──
# Higher = more interesting for pentesters
SERVICE_WEIGHTS = {
    "http": 0.6, "https": 0.7, "www": 0.6,
    "ssh": 0.8, "telnet": 0.9,             # remote access
    "smb": 0.9, "netbios-ssn": 0.8, "microsoft-ds": 0.9,  # Windows domain
    "rdp": 0.8, "ms-wbt-server": 0.8,
    "mysql": 0.7, "mariadb": 0.7, "postgresql": 0.7,
    "mssql": 0.8, "oracle": 0.8, "mongodb": 0.6,
    "redis": 0.6, "memcached": 0.4,
    "ftp": 0.5, "vsftpd": 0.5, "proftpd": 0.5,
    "dns": 0.3, "domain": 0.4,
    "smtp": 0.3, "pop3": 0.4, "imap": 0.4,
    "snmp": 0.6, "ldap": 0.7, "ldaps": 0.7,
    "kerberos": 0.8, "kpasswd5": 0.8,
    "nfs": 0.6, "rpcbind": 0.5, "mountd": 0.6,
    "vnc": 0.7, "x11": 0.7,
    "docker": 0.9, "kubernetes": 0.9,
    "jenkins": 0.8, "tomcat": 0.7,
    "elasticsearch": 0.6, "kibana": 0.6,
    "winrm": 0.8, "wsman": 0.8,
    "msrpc": 0.7, "epmap": 0.6,
    "ajp13": 0.7, "java-rmi": 0.6,
}

# ── Severity → numeric score ──
SEVERITY_SCORE = {
    "critical": 10.0, "high": 7.0, "medium": 4.0,
    "low": 2.0, "info": 1.0, "unknown": 3.0,
}

MAX_PORT_SCORE = 10.0
MAX_HOST_SCORE = 100.0


class TargetPrioritizer:
    """Scores and prioritizes targets for multi-target campaigns."""

    def prioritize(self, targets_data: List[Dict[str, Any]],
                   findings: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Score each target and return a priority-ordered list.

        targets_data: list of {target, ports: [{port, service, state}], ...}
        findings: global findings list (tagged by target)
        """
        findings = findings or []
        scored = []

        for td in targets_data:
            target = td.get("target", td.get("host", "unknown"))
            ports = td.get("ports", [])
            target_findings = [f for f in findings
                               if f.get("target") == target or target in str(f)]

            port_score = self._score_ports(ports)
            vuln_score = self._score_vulns(target_findings)
            exposure = self._score_exposure(ports, td)

            total = (port_score * 0.4) + (vuln_score * 0.4) + (exposure * 0.2)
            total = round(min(total, MAX_HOST_SCORE), 1)

            scored.append({
                "target": target,
                "score": total,
                "breakdown": {
                    "port_score": round(port_score, 1),
                    "vuln_score": round(vuln_score, 1),
                    "exposure_score": round(exposure, 1),
                },
                "open_ports": len([p for p in ports if p.get("state") == "open"]),
                "findings_count": len(target_findings),
                "suggested_workflow": self._suggest_workflow(ports, target_findings),
                "tier": self._tier(total),
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _score_ports(self, ports: List[Dict]) -> float:
        """Score based on open ports weighted by service criticality."""
        if not ports:
            return 0.0
        open_ports = [p for p in ports if p.get("state") == "open"]
        if not open_ports:
            return 0.0

        total = 0.0
        for p in open_ports:
            service = (p.get("service", "") or "").lower()
            # Find best matching weight
            weight = 0.1  # default for unknown
            for svc, w in SERVICE_WEIGHTS.items():
                if svc in service or service in svc:
                    weight = max(weight, w)
            total += weight

        return min(total, MAX_PORT_SCORE)

    def _score_vulns(self, findings: List[Dict]) -> float:
        """Score based on findings severity."""
        if not findings:
            return 0.0
        total = 0.0
        for f in findings:
            sev = (f.get("severity") or "unknown").lower()
            total += SEVERITY_SCORE.get(sev, 1.0)
        return min(total, MAX_PORT_SCORE)

    def _score_exposure(self, ports: List[Dict], target_data: Dict) -> float:
        """Score based on attack surface breadth."""
        open_count = len([p for p in ports if p.get("state") == "open"])
        if open_count == 0:
            return 0.0
        # Logarithmic scale: 1 port = 2, 5 ports = 5, 20 ports = 8, 100 ports = 10
        import math
        exposure = min(MAX_PORT_SCORE, 2.0 + math.log2(open_count + 1) * 2.5)
        return exposure

    def _suggest_workflow(self, ports: List[Dict],
                          findings: List[Dict]) -> str:
        """Suggest the best workflow template based on open services."""
        services = set()
        for p in ports:
            if p.get("state") == "open":
                svc = (p.get("service", "") or "").lower()
                services.add(svc)

        svc_str = " ".join(services)

        # Heuristic matching
        if any(s in svc_str for s in ("http", "https", "www", "nginx", "apache")):
            if any(s in svc_str for s in ("mysql", "postgres", "mssql", "oracle")):
                return "web_full_assessment"
            return "web_recon"

        if any(s in svc_str for s in ("smb", "netbios", "microsoft-ds", "ldap", "kerberos")):
            if any(s in svc_str for s in ("msrpc", "winrm", "epmap")):
                return "adcs_abuse_chain"
            return "domain_recon"

        if any(s in svc_str for s in ("ssh", "rdp", "vnc", "ftp")):
            return "remote_access_brute"

        if any(s in svc_str for s in ("docker", "kubernetes", "2375", "2376", "6443")):
            return "kubernetes_assessment"

        if any(s in svc_str for s in ("imds", "169.254")):
            return "cloud_iam_enumeration"

        # Default: start with recon
        return "network_recon"

    def _tier(self, score: float) -> str:
        """Map score to a tier label."""
        if score >= 70:
            return "🔴 Critical"
        elif score >= 50:
            return "🟠 High"
        elif score >= 30:
            return "🟡 Medium"
        elif score > 0:
            return "🟢 Low"
        return "⚪ Unknown"

    def get_stats(self) -> Dict[str, Any]:
        """Return prioritizer statistics."""
        return {
            "service_weights_loaded": len(SERVICE_WEIGHTS),
            "severity_levels": len(SEVERITY_SCORE),
        }