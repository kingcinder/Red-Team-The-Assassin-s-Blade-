"""
RedTeam Harness — Reconnaissance Tools Module
Network discovery, port scanning, service enumeration, SMB/DNS enum.
"""
from tools.base import BaseTool


class ReconTools(BaseTool):
    """Reconnaissance and network discovery tools."""

    def get_tools(self):
        return ["nmap_scan", "nmap_vuln_scan", "masscan_scan", "httpx_probe",
                "host_discovery", "service_enum", "banner_grab", "subdomain_enum",
                "amass_enum", "subfinder_enum", "dnsx_probe", "naabu_scan",
                "enum4linux_enum", "nbtscan_scan", "zmap_scan", "dnswalk_enum",
                "smbmap_enum"]

    def get_quick_commands(self):
        return [
            {"name": "Quick Port Scan", "description": "Fast scan of common ports",
             "tool": "nmap_scan",
             "args_template": {"target": "TARGET", "ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3389,5900,8080", "scan_type": "-sV"}},
            {"name": "Full Port Scan", "description": "All 65535 ports + version + scripts",
             "tool": "nmap_scan",
             "args_template": {"target": "TARGET", "ports": "1-65535", "scan_type": "-sV -sC"}},
            {"name": "Vulnerability Scan", "description": "Nmap NSE vulnerability scripts",
             "tool": "nmap_vuln_scan",
             "args_template": {"target": "TARGET", "script": "vuln"}},
            {"name": "Host Discovery", "description": "Find live hosts on a network",
             "tool": "host_discovery",
             "args_template": {"target": "TARGET", "method": "ping"}},
            {"name": "Service Enumeration", "description": "Detailed version detection",
             "tool": "service_enum",
             "args_template": {"target": "TARGET"}},
            {"name": "Banner Grabbing", "description": "Grab service banners",
             "tool": "banner_grab",
             "args_template": {"target": "TARGET", "ports": "21,22,25,80,443"}},
            {"name": "Masscan Fast Sweep", "description": "Ultra-fast port sweep",
             "tool": "masscan_scan",
             "args_template": {"target": "TARGET", "ports": "1-65535", "rate": "5000"}},
            {"name": "HTTP Probe", "description": "Probe web servers for tech stack",
             "tool": "httpx_probe",
             "args_template": {"targets": "TARGET", "tech_detect": True}},
            {"name": "Amass Subdomain", "description": "Deep subdomain enumeration (Amass)",
             "tool": "amass_enum",
             "args_template": {"domain": "TARGET"}},
            {"name": "Subfinder Enum", "description": "Passive subdomain discovery",
             "tool": "subfinder_enum",
             "args_template": {"domain": "TARGET"}},
            {"name": "DNSX Probe", "description": "Fast DNS resolution toolkit",
             "tool": "dnsx_probe",
             "args_template": {"domain": "TARGET"}},
            {"name": "SMB Enumeration", "description": "Enum4linux SMB share enumeration",
             "tool": "enum4linux_enum",
             "args_template": {"target": "TARGET"}},
            {"name": "NetBIOS Scan", "description": "Windows NetBIOS name scanner",
             "tool": "nbtscan_scan",
             "args_template": {"target": "TARGET"}},
            {"name": "SMBMap Enum", "description": "SMB share permission checker",
             "tool": "smbmap_enum",
             "args_template": {"target": "TARGET"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Network Recon Pipeline",
             "description": "Host discovery → port scan → service enum → banner grab → OSINT",
             "steps": [
                 {"tool": "host_discovery", "args": {"target": "TARGET", "method": "ping"}, "description": "Discover live hosts"},
                 {"tool": "nmap_scan", "args": {"target": "TARGET", "ports": "1-65535", "scan_type": "-sV"}, "description": "Full port scan"},
                 {"tool": "banner_grab", "args": {"target": "TARGET", "ports": "21,22,25,80,443,8080"}, "description": "Grab banners"},
             ]},
            {"name": "Domain Recon Pipeline",
             "description": "Amass → Subfinder → DNSx → SNMP → SMB",
             "steps": [
                 {"tool": "amass_enum", "args": {"domain": "TARGET"}, "description": "Deep subdomain enum"},
                 {"tool": "subfinder_enum", "args": {"domain": "TARGET"}, "description": "Passive subdomain enum"},
                 {"tool": "dnsx_probe", "args": {"domain": "TARGET"}, "description": "DNS resolution"},
                 {"tool": "enum4linux_enum", "args": {"target": "TARGET_IP"}, "description": "SMB/CIFS enumeration"},
             ]},
        ]