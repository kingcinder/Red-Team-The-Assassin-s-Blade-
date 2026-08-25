"""
RedTeam Harness — Tool Registry (Kali Linux Complete)
Discovers, validates, and manages ALL security tools in the Kali Linux arsenal.
140+ tools across 14 categories with a generic command builder.
"""
import os
import shutil
import logging
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
from core.command_builder import _build_command as _build_command_impl

logger = logging.getLogger("redteam.tools")


class ToolDefinition:
    """Defines a single tool's metadata, parameters, and execution method."""

    def __init__(self, name: str, category: str, description: str, binary: str,
                 parameters: dict = None, subcommand: str = None,
                 destructive: bool = False, timeout: int = 300,
                 prereq_tools: List[str] = None):
        self.name = name
        self.category = category
        self.description = description
        self.binary = binary
        self.subcommand = subcommand
        self.parameters = parameters or {}
        self.destructive = destructive
        self.timeout = timeout
        self.prereq_tools = prereq_tools or []
        self.installed = False
        self.path = None

    def detect(self):
        """Check if the tool is installed on the system."""
        if self.binary:
            self.path = shutil.which(self.binary)
            self.installed = self.path is not None
        return self.installed

    def to_dict(self) -> dict:
        return {
            "name": self.name, "category": self.category,
            "description": self.description, "binary": self.binary,
            "installed": self.installed, "path": self.path,
            "destructive": self.destructive, "parameters": self.parameters,
        }

    def to_llm_definition(self) -> dict:
        props = {}
        required = []
        for pname, pinfo in self.parameters.items():
            props[pname] = {"type": pinfo.get("type", "string"),
                            "description": pinfo.get("description", "")}
            if pinfo.get("required"):
                required.append(pname)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": f"[{self.category}] {self.description}",
                "parameters": {"type": "object", "properties": props,
                               "required": required},
            },
        }


# ── Tools whose command-building is complex enough to need hand-written or positional builders ──

class ToolRegistry:
    """Manages all security tools — discovery, validation, and execution."""

    def __init__(self, config: dict):
        self.config = config
        self._tools: Dict[str, ToolDefinition] = {}
        self._output_dir = os.path.abspath(config.get("output_dir", "./output"))
        os.makedirs(self._output_dir, exist_ok=True)
        self._register_all_tools()
        self._detect_installed()

    # ═══════════════════════════════════════════════════════════════
    # REGISTRATION — Complete Kali Linux Tool Arsenal
    # ═══════════════════════════════════════════════════════════════

    def _register_all_tools(self):
        self._register_recon()
        self._register_vuln()
        self._register_web()
        self._register_password()
        self._register_wireless()
        self._register_sniffing()
        self._register_exploit()
        self._register_forensics()
        self._register_reversing()
        self._register_social()
        self._register_postex()
        self._register_osint()
        self._register_stress()
        self._register_hardware()
        self._register_utility()

    # ──────────────── RECONNAISSANCE ────────────────
    def _register_recon(self):
        cat = "recon"
        self._register(ToolDefinition("nmap_scan", cat,
            "Port scanner — discovers hosts, ports, services, OS on a target network.",
            "nmap", {"target": {"type":"string","description":"Target IP, CIDR, or hostname","required":True},
            "ports":{"type":"string","description":"Port range (e.g. '1-1000','80,443','-')"},
            "scan_type":{"type":"string","description":"Scan flags: -sS (SYN), -sT (TCP), -sU (UDP), -sV (version), -sC (scripts)"},
            "flags":{"type":"string","description":"Additional nmap flags"}}, timeout=600))
        self._register(ToolDefinition("nmap_vuln_scan", cat,
            "Nmap NSE vulnerability scripts against target.","nmap",
            {"target":{"type":"string","description":"Target","required":True},
            "script":{"type":"string","description":"NSE script category (vuln,exploit,auth)"}}, timeout=900))
        self._register(ToolDefinition("masscan_scan", cat,
            "Ultra-fast port scanner — scans the entire internet in minutes.","masscan",
            {"target":{"type":"string","description":"Target IP/CIDR","required":True},
            "ports":{"type":"string","description":"Port range (0-65535)","required":True},
            "rate":{"type":"integer","description":"Packets per second"}}, timeout=300))
        self._register(ToolDefinition("host_discovery", cat,
            "Live-host discovery via ping/ARP sweep on a CIDR range.","nmap",
            {"target":{"type":"string","description":"CIDR range","required":True},
            "method":{"type":"string","description":"ping or arp"}}, timeout=120))
        self._register(ToolDefinition("service_enum", cat,
            "Detailed service/version detection on open ports (-sV -sC).","nmap",
            {"target":{"type":"string","description":"Target","required":True},
            "ports":{"type":"string","description":"Ports to enumerate"}}, timeout=300))
        self._register(ToolDefinition("banner_grab", cat,
            "Grab service banners from open ports for fingerprinting.","nmap",
            {"target":{"type":"string","description":"Target","required":True},
            "ports":{"type":"string","description":"Ports","required":True}}, timeout=120))
        self._register(ToolDefinition("subdomain_enum", cat,
            "DNS brute-force subdomain enumeration via Nmap.","nmap",
            {"domain":{"type":"string","description":"Target domain","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=300))
        self._register(ToolDefinition("httpx_probe", cat,
            "Fast HTTP probe — status codes, titles, tech-detect.","httpx",
            {"targets":{"type":"string","description":"IPs/URLs/file","required":True},
            "ports":{"type":"string","description":"Ports to probe"},
            "tech_detect":{"type":"boolean","description":"Enable tech detection"}}, timeout=120))
        self._register(ToolDefinition("amass_enum", cat,
            "In-depth subdomain enumeration via multiple sources.","amass",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=600))
        self._register(ToolDefinition("subfinder_enum", cat,
            "Passive subdomain discovery tool.","subfinder",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=300))
        self._register(ToolDefinition("dnsx_probe", cat,
            "Fast DNS toolkit for A/AAAA/CNAME/MX/NS resolution.","dnsx",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=120))
        self._register(ToolDefinition("naabu_scan", cat,
            "Fast port scanner (Go) for initial recon.","naabu",
            {"target":{"type":"string","description":"Target IP/host","required":True},
            "ports":{"type":"string","description":"Port range"}}, timeout=120))
        self._register(ToolDefinition("enum4linux_enum", cat,
            "SMB/CIFS enumeration — users, shares, policies, OS info.","enum4linux",
            {"target":{"type":"string","description":"Target IP","required":True}}, timeout=300))
        self._register(ToolDefinition("nbtscan_scan", cat,
            "NetBIOS name scanner for Windows networks.","nbtscan",
            {"target":{"type":"string","description":"Target IP/range","required":True}}, timeout=60, destructive=True))
        self._register(ToolDefinition("zmap_scan", cat,
            "Single-packet fast Internet-wide scanner.","zmap",
            {"target":{"type":"string","description":"Target subnet","required":True},
            "port":{"type":"integer","description":"Target port"}}, timeout=600))
        self._register(ToolDefinition("dnswalk_enum", cat,
            "DNS zone file debugger — checks for misconfigurations.","dnswalk",
            {"domain":{"type":"string","description":"Domain","required":True}}, timeout=60))
        self._register(ToolDefinition("smbmap_enum", cat,
            "SMB share enumeration and permission checking tool.","smbmap",
            {"target":{"type":"string","description":"Target IP","required":True}}, timeout=120, destructive=True))

    # ──────────────── VULNERABILITY ANALYSIS ────────────────
    def _register_vuln(self):
        cat = "vuln"
        self._register(ToolDefinition("nuclei_scan", cat,
            "Fast vulnerability scanner using YAML templates.","nuclei",
            {"target":{"type":"string","description":"Target URL/IP","required":True},
            "templates":{"type":"string","description":"Template path or tag"}}, timeout=600))
        self._register(ToolDefinition("wpscan_enum", cat,
            "WordPress vulnerability scanner — plugins, themes, users, vulns.","wpscan",
            {"url":{"type":"string","description":"Target WP site URL","required":True},
            "enumerate":{"type":"string","description":"What to enumerate (u/p/t/vp/ap)"}}, timeout=600))
        self._register(ToolDefinition("searchsploit_search", cat,
            "ExploitDB local search — find exploits by keyword.","searchsploit",
            {"query":{"type":"string","description":"Search query","required":True}}, timeout=30))
        self._register(ToolDefinition("linux_exploit_suggester", cat,
            "LES — suggest privilege-escalation exploits for Linux kernel.","linux-exploit-suggester",
            {"kernel":{"type":"string","description":"Target kernel version"}}, timeout=120))
        self._register(ToolDefinition("linux_smart_enum", cat,
            "Linux Smart Enumeration — comprehensive local privesc checks.","lse",
            {"level":{"type":"integer","description":"Detail level 0-2"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("linpeas_run", cat,
            "LinPEAS — Linux Privilege Escalation Awesome Script.","linpeas",
            {"output":{"type":"string","description":"Output file"}}, timeout=600, destructive=True))
        self._register(ToolDefinition("snmpwalk_enum", cat,
            "SNMP enumeration — walk MIB tree for device info.","snmpwalk",
            {"target":{"type":"string","description":"Target IP","required":True},
            "community":{"type":"string","description":"Community string (public)"}}, timeout=120))
        self._register(ToolDefinition("onesixtyone_scan", cat,
            "Fast SNMP community string brute-forcer.","onesixtyone",
            {"target":{"type":"string","description":"Target IP","required":True}}, timeout=60))
        self._register(ToolDefinition("grype_scan", cat,
            "Container/SBOM vulnerability scanner.","grype",
            {"image":{"type":"string","description":"Container image name","required":True}}, timeout=300))
        self._register(ToolDefinition("trivy_scan", cat,
            "Comprehensive security scanner for containers, filesystems, git.","trivy",
            {"image":{"type":"string","description":"Container image","required":True}}, timeout=300))
        self._register(ToolDefinition("lynis_audit", cat,
            "Security auditing tool for Linux/Unix systems.","lynis",
            {"audit_type":{"type":"string","description":"system or remote"}}, timeout=300, destructive=True))

    # ──────────────── WEB APPLICATION ANALYSIS ────────────────
    def _register_web(self):
        cat = "web"
        self._register(ToolDefinition("nikto_scan", cat,
            "Web server scanner — dangerous files, outdated software, misconfigs.","nikto",
            {"target":{"type":"string","description":"Target host/URL","required":True},
            "port":{"type":"string","description":"Port (default 80)"},
            "tuning":{"type":"string","description":"Tuning flags (1-9,a-c)"}}, timeout=600))
        self._register(ToolDefinition("sqlmap_scan", cat,
            "SQL injection detection and exploitation tool.","sqlmap",
            {"url":{"type":"string","description":"Target URL with param","required":True},
            "method":{"type":"string","description":"HTTP method"},
            "data":{"type":"string","description":"POST data string"},
            "level":{"type":"integer","description":"Test level 1-5"},
            "risk":{"type":"integer","description":"Risk level 1-3"},
            "dbs":{"type":"boolean","description":"Enumerate databases"},
            "batch":{"type":"boolean","description":"Never prompt user"}}, destructive=True, timeout=900))
        self._register(ToolDefinition("gobuster_dir", cat,
            "Directory/file brute-forcer for discovering hidden web paths.","gobuster",
            {"url":{"type":"string","description":"Target URL","required":True},
            "wordlist":{"type":"string","description":"Wordlist path","required":True},
            "extensions":{"type":"string","description":"File extensions"},
            "threads":{"type":"integer","description":"Thread count"}}, timeout=600))
        self._register(ToolDefinition("whatweb_scan", cat,
            "Web technology fingerprinting — CMS, frameworks, libraries.","whatweb",
            {"target":{"type":"string","description":"Target URL","required":True},
            "aggression":{"type":"integer","description":"Level 1-4"}}, timeout=120))
        self._register(ToolDefinition("waf_detect", cat,
            "WAFW00F — detect if target sits behind a Web Application Firewall.","wafw00f",
            {"target":{"type":"string","description":"Target URL","required":True}}, timeout=60))
        self._register(ToolDefinition("curl_request", cat,
            "Custom HTTP requests for manual web testing.","curl",
            {"url":{"type":"string","description":"Target URL","required":True},
            "method":{"type":"string","description":"HTTP method"},
            "headers":{"type":"string","description":"Headers (k:v;k:v)"},
            "data":{"type":"string","description":"Request body"},
            "cookies":{"type":"string","description":"Cookie string"},
            "follow_redirects":{"type":"boolean","description":"Follow redirects"},
            "insecure":{"type":"boolean","description":"Skip TLS verify"}}, timeout=30))
        self._register(ToolDefinition("dirb_scan", cat,
            "Classic web directory brute-forcer.","dirb",
            {"url":{"type":"string","description":"Target URL","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=600))
        self._register(ToolDefinition("wfuzz_fuzz", cat,
            "Web application fuzzer — fuzz params, dirs, headers.","wfuzz",
            {"url":{"type":"string","description":"Target URL with FUZZ placeholder","required":True},
            "wordlist":{"type":"string","description":"Wordlist path","required":True}}, timeout=600))
        self._register(ToolDefinition("feroxbuster_scan", cat,
            "Fast recursive content discovery tool (Rust).","feroxbuster",
            {"url":{"type":"string","description":"Target URL","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=600))
        self._register(ToolDefinition("ffuf_fuzz", cat,
            "Fast web fuzzer (Go) — directory, vhost, param fuzzing.","ffuf",
            {"url":{"type":"string","description":"Target URL with FUZZ","required":True},
            "wordlist":{"type":"string","description":"Wordlist path","required":True}}, timeout=600))
        self._register(ToolDefinition("burpsuite_proxy", cat,
            "Burp Suite — intercepting proxy for web app testing.","burpsuite",
            {"mode":{"type":"string","description":"gui or headless"}}, timeout=30))
        self._register(ToolDefinition("zap_scan", cat,
            "OWASP ZAP — automated web application scanner.","zaproxy",
            {"target":{"type":"string","description":"Target URL","required":True}}, timeout=900, destructive=True))
        self._register(ToolDefinition("katana_crawl", cat,
            "Next-gen crawling and spidering (Go).","katana",
            {"url":{"type":"string","description":"Target URL","required":True}}, timeout=300))
        self._register(ToolDefinition("gospider_crawl", cat,
            "Fast web spider (Go) — extracts links, JS, forms.","gospider",
            {"url":{"type":"string","description":"Target URL","required":True}}, timeout=300))
        self._register(ToolDefinition("hakrawler_crawl", cat,
            "Simple web crawler designed for bug bounty/security testing.","hakrawler",
            {"url":{"type":"string","description":"Target URL","required":True}}, timeout=300))
        self._register(ToolDefinition("gau_fetch", cat,
            "Get All URLs — fetch known URLs from AlienVault, Wayback, etc.","gau",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=120))
        self._register(ToolDefinition("waybackurls_fetch", cat,
            "Fetch all known URLs from Wayback Machine for a domain.","waybackurls",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=120))

    # ──────────────── PASSWORD ATTACKS ────────────────
    def _register_password(self):
        cat = "password"
        self._register(ToolDefinition("hydra_brute", cat,
            "Network login cracker — brute-force passwords across protocols.","hydra",
            {"target":{"type":"string","description":"Target host","required":True},
            "service":{"type":"string","description":"Service (ssh,ftp,http,smb,rdp,…)","required":True},
            "username":{"type":"string","description":"Username or userlist","required":True},
            "password_list":{"type":"string","description":"Password wordlist path","required":True},
            "port":{"type":"integer","description":"Service port"},
            "threads":{"type":"integer","description":"Parallel threads"}}, destructive=True, timeout=600))
        self._register(ToolDefinition("john_crack", cat,
            "John the Ripper — hash cracker (dict, rules, brute).","john",
            {"hash_file":{"type":"string","description":"Hash file path","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"},
            "format":{"type":"string","description":"Hash format (raw-md5,…)"},
            "rules":{"type":"string","description":"Rule set to apply"}}, timeout=3600))
        self._register(ToolDefinition("hashcat_crack", cat,
            "World's fastest GPU-accelerated hash cracker.","hashcat",
            {"hash_file":{"type":"string","description":"Hash file","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"},
            "mode":{"type":"integer","description":"Hash-mode number"},
            "attack_mode":{"type":"integer","description":"Attack mode (0=straight, 3=brute, 6/7=hybrid)"},
            "rules":{"type":"string","description":"Rule file"}}, timeout=3600))
        self._register(ToolDefinition("hashid_identify", cat,
            "Identify hash types from a given hash string.","hashid",
            {"hash":{"type":"string","description":"Hash to identify","required":True}}, timeout=10))
        self._register(ToolDefinition("cewl_gen", cat,
            "Custom wordlist generator from website content.","cewl",
            {"url":{"type":"string","description":"Target URL","required":True},
            "depth":{"type":"integer","description":"Spider depth"}}, timeout=120))
        self._register(ToolDefinition("crunch_gen", cat,
            "Generate custom wordlists with charset pattern rules.","crunch",
            {"min_len":{"type":"integer","description":"Min password length","required":True},
            "max_len":{"type":"integer","description":"Max password length","required":True},
            "charset":{"type":"string","description":"Character set"},
            "output":{"type":"string","description":"Output file"}}, timeout=600))
        self._register(ToolDefinition("rsmangler_mangle", cat,
            "Password list mangle tool — apply common permutations.","rsmangler",
            {"wordlist":{"type":"string","description":"Input wordlist","required":True}}, timeout=120))
        self._register(ToolDefinition("chntpw_dump", cat,
            "Offline Windows SAM/NT password hash dump/reset.","chntpw",
            {"sam_file":{"type":"string","description":"Path to SAM hive","required":True}}, timeout=60, destructive=True))
        self._register(ToolDefinition("ophcrack_crack", cat,
            "Rainbow-table based Windows password cracker.","ophcrack",
            {"hash_file":{"type":"string","description":"Hash file","required":True}}, timeout=600))
        self._register(ToolDefinition("fcrackzip_crack", cat,
            "Brute-force ZIP archive passwords.","fcrackzip",
            {"archive":{"type":"string","description":"ZIP file path","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=600))
        self._register(ToolDefinition("pdfcrack_crack", cat,
            "Brute-force PDF document passwords.","pdfcrack",
            {"pdf":{"type":"string","description":"PDF file path","required":True},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=600))

    # ──────────────── WIRELESS ATTACKS ────────────────
    def _register_wireless(self):
        cat = "wireless"
        self._register(ToolDefinition("aircrack_crack", cat,
            "Aircrack-ng — crack WEP/WPA/WPA2 keys from captured handshake.","aircrack-ng",
            {"cap_file":{"type":"string","description":"Capture file (.cap)","required":True},
            "wordlist":{"type":"string","description":"Wordlist for WPA"}}, timeout=3600))
        self._register(ToolDefinition("airodump_capture", cat,
            "Airodump-ng — capture raw 802.11 frames.","airodump-ng",
            {"interface":{"type":"string","description":"Monitor-mode interface","required":True},
            "channel":{"type":"string","description":"Channel(s)"}}, timeout=300))
        self._register(ToolDefinition("aireplay_attack", cat,
            "Aireplay-ng — inject frames for deauth, fake auth, replay.","aireplay-ng",
            {"interface":{"type":"string","description":"Monitor-mode interface","required":True},
            "bssid":{"type":"string","description":"Target AP BSSID"},
            "attack":{"type":"string","description":"Attack type (0-9)"}}, timeout=120, destructive=True))
        self._register(ToolDefinition("reaver_attack", cat,
            "Brute-force WPS PIN to recover WPA passphrase.","reaver",
            {"interface":{"type":"string","description":"Monitor-mode interface","required":True},
            "bssid":{"type":"string","description":"Target AP BSSID","required":True}}, timeout=3600, destructive=True))
        self._register(ToolDefinition("wifite_auto", cat,
            "Automated wireless attack tool — scans, attacks, cracks.","wifite",
            {"interface":{"type":"string","description":"Wireless interface"}}, timeout=3600, destructive=True))
        self._register(ToolDefinition("kismet_scan", cat,
            "Wireless network detector, sniffer, and IDS.","kismet",
            {"interface":{"type":"string","description":"Wireless interface"}, "time":{"type":"integer","description":"Capture duration seconds"}}, timeout=600))
        self._register(ToolDefinition("bettercap_mitm", cat,
            "Swiss-Army knife for WiFi, BLE, and Ethernet attacks.","bettercap",
            {"target":{"type":"string","description":"Target IP/range"},
            "module":{"type":"string","description":"Module (net.probe,wifi,…)"}}, timeout=300, destructive=True))

    # ──────────────── SNIFFING & SPOOFING ────────────────
    def _register_sniffing(self):
        cat = "sniffing"
        self._register(ToolDefinition("tcpdump_capture", cat,
            "Network packet capture and analysis.","tcpdump",
            {"interface":{"type":"string","description":"Network interface"},
            "filter":{"type":"string","description":"BPF filter expression"},
            "count":{"type":"integer","description":"Packet count limit"},
            "output_file":{"type":"string","description":"Write to pcap file"}}, timeout=300))
        self._register(ToolDefinition("tshark_capture", cat,
            "Wireshark CLI — capture and analyze network traffic.","tshark",
            {"interface":{"type":"string","description":"Network interface"},
            "filter":{"type":"string","description":"Display filter"},
            "duration":{"type":"integer","description":"Capture duration seconds"}}, timeout=300))
        self._register(ToolDefinition("ettercap_mitm", cat,
            "Man-in-the-middle attack suite for LAN.","ettercap",
            {"target1":{"type":"string","description":"Target 1 IP"},
            "target2":{"type":"string","description":"Target 2 IP"},
            "method":{"type":"string","description":"arp, icmp, dhcp, port"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("responder_poison", cat,
            "LLMNR/NBT-NS/mDNS poisoner and credential harvester.","responder",
            {"interface":{"type":"string","description":"Network interface"},
            "options":{"type":"string","description":"Additional flags"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("dsniff_suite", cat,
            "Collection of network auditing and penetration-testing tools.","dsniff",
            {"tool":{"type":"string","description":"Sub-tool (arpspoof,dnsspoof,urlsnarf)","required":True},
            "target":{"type":"string","description":"Target IP"}}, timeout=120, destructive=True))
        self._register(ToolDefinition("mitm6_attack", cat,
            "IPv6 MITM attack tool — spoof DNS and capture credentials.","mitm6",
            {"domain":{"type":"string","description":"Target domain","required":True}}, timeout=300, destructive=True))

    # ──────────────── EXPLOITATION ────────────────
    def _register_exploit(self):
        cat = "exploit"
        self._register(ToolDefinition("msfvenom_payload", cat,
            "Metasploit payload generator — create reverse shells, meterpreter.","msfvenom",
            {"payload":{"type":"string","description":"Payload name","required":True},
            "lhost":{"type":"string","description":"Listener host","required":True},
            "lport":{"type":"integer","description":"Listener port","required":True},
            "format":{"type":"string","description":"Output format (exe,elf,python,…)"},
            "output":{"type":"string","description":"Output file path"}}, timeout=60, destructive=True))
        self._register(ToolDefinition("msf_resource", cat,
            "Metasploit resource script — automate exploit chains.","msfconsole",
            {"resource":{"type":"string","description":"Resource script path","required":True}}, timeout=900, destructive=True))
        self._register(ToolDefinition("msf_auto_exploit", cat,
            "Auto-exploit pipeline: parse nmap output → searchsploit → generate .rc → validate → execute via msfconsole.","msfconsole",
            {"nmap_output":{"type":"string","description":"Raw nmap scan output text","required":True},
            "lhost":{"type":"string","description":"Attacker IP for reverse shells","required":True},
            "lport":{"type":"integer","description":"Listener port","default":4444},
            "payload":{"type":"string","description":"Metasploit payload (auto-detect if empty)"},
            "objective":{"type":"string","description":"Attack objective for LLM context"},
            "execute":{"type":"boolean","description":"Actually execute the .rc script (True) or just generate (False)","default":False}}, timeout=900, destructive=True, prereq_tools=["msfconsole","searchsploit"]))
        self._register(ToolDefinition("searchsploit_exploit", cat,
            "ExploitDB search — find public exploits by service/version.","searchsploit",
            {"query":{"type":"string","description":"Search query","required":True}}, timeout=30))
        self._register(ToolDefinition("crackmapexec_exec", cat,
            "Swiss-Army knife for pentesting networks (SMB/SSH/WinRM/MSSQL).","crackmapexec",
            {"target":{"type":"string","description":"Target IP/range","required":True},
            "username":{"type":"string","description":"Username"},
            "password":{"type":"string","description":"Password"},
            "protocol":{"type":"string","description":"Protocol (smb,ssh,winrm,mssql)"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("netexec_exec", cat,
            "Network execution tool — successor of crackmapexec.","netexec",
            {"target":{"type":"string","description":"Target","required":True},
            "protocol":{"type":"string","description":"Protocol","required":True}}, timeout=300, destructive=True))
        self._register(ToolDefinition("impacket_tools", cat,
            "Impacket suite — collection of Python classes for network protocols.","impacket",
            {"tool":{"type":"string","description":"Tool (secretsdump,psexec,GetNPUsers,…)","required":True},
            "target":{"type":"string","description":"Target host","required":True}}, timeout=300, destructive=True))
        self._register(ToolDefinition("evil_winrm", cat,
            "WinRM shell for pentesting — post-exploitation shell on Windows.","evil-winrm",
            {"target":{"type":"string","description":"Target IP","required":True},
            "username":{"type":"string","description":"Username","required":True},
            "password":{"type":"string","description":"Password"}}, timeout=120, destructive=True))
        self._register(ToolDefinition("sshuttle_pivot", cat,
            "Transparent proxy/VPN over SSH for pivoting.","sshuttle",
            {"target":{"type":"string","description":"Subnet to route","required":True},
            "ssh_host":{"type":"string","description":"SSH pivot host","required":True}}, timeout=300, destructive=True))
        self._register(ToolDefinition("chisel_tunnel", cat,
            "Fast TCP/UDP tunnel over HTTP (pivoting through firewalls).","chisel",
            {"mode":{"type":"string","description":"server or client","required":True},
            "bind":{"type":"string","description":"Bind address"}}, timeout=300, destructive=True))

    # ──────────────── FORENSICS ────────────────
    def _register_forensics(self):
        cat = "forensics"
        self._register(ToolDefinition("binwalk_analyze", cat,
            "Firmware analysis — extract embedded files and filesystems.","binwalk",
            {"file":{"type":"string","description":"Firmware/file to analyze","required":True},
            "extract":{"type":"boolean","description":"Extract embedded files"}}, timeout=300))
        self._register(ToolDefinition("foremost_carve", cat,
            "File carving — recover files based on headers/footers.","foremost",
            {"image":{"type":"string","description":"Disk image/file","required":True},
            "output_dir":{"type":"string","description":"Output directory"}}, timeout=600))
        self._register(ToolDefinition("testdisk_recover", cat,
            "Partition recovery and file undelete tool.","testdisk",
            {"device":{"type":"string","description":"Disk device","required":True}}, timeout=600))
        self._register(ToolDefinition("photorec_recover", cat,
            "PhotoRec — recover lost files from disk images.","photorec",
            {"device":{"type":"string","description":"Disk device","required":True}}, timeout=600))
        self._register(ToolDefinition("volatility_analyze", cat,
            "Memory forensics framework — analyze RAM dumps.","volatility",
            {"image":{"type":"string","description":"Memory dump file","required":True},
            "plugin":{"type":"string","description":"Volatility plugin (pslist,netscan,…)"}}, timeout=300))
        self._register(ToolDefinition("dcfldd_image", cat,
            "Enhanced dd with hashing — forensic disk imaging.","dcfldd",
            {"input":{"type":"string","description":"Input device","required":True},
            "output":{"type":"string","description":"Output image file","required":True}}, timeout=3600))
        self._register(ToolDefinition("ddrescue_image", cat,
            "Data recovery — copy data from failing drives.","ddrescue",
            {"input":{"type":"string","description":"Input device","required":True},
            "output":{"type":"string","description":"Output file","required":True}}, timeout=3600))
        self._register(ToolDefinition("exiftool_read", cat,
            "Read/write/edit metadata in files (GPS, dates, camera, etc.).","exiftool",
            {"file":{"type":"string","description":"File to analyze","required":True}}, timeout=30))
        self._register(ToolDefinition("strings_extract", cat,
            "Extract printable strings from binary files.","strings",
            {"file":{"type":"string","description":"Binary file","required":True},
            "min_length":{"type":"integer","description":"Minimum string length"}}, timeout=60))
        self._register(ToolDefinition("steghide_extract", cat,
            "Steganography tool — hide/extract data in images/audio.","steghide",
            {"file":{"type":"string","description":"Stego file","required":True},
            "extract":{"type":"boolean","description":"Extract hidden data"},
            "password":{"type":"string","description":"Passphrase"}}, timeout=60))
        self._register(ToolDefinition("stegseek_crack", cat,
            "Fast steghide brute-force cracking tool.","stegseek",
            {"file":{"type":"string","description":"Stego file","required":True},
            "wordlist":{"type":"string","description":"Wordlist path","required":True}}, timeout=600))
        self._register(ToolDefinition("bulk_extractor", cat,
            "Extract emails, URLs, credit cards, and other PII from disk images.","bulk_extractor",
            {"input":{"type":"string","description":"Input image/directory","required":True},
            "output_dir":{"type":"string","description":"Output directory"}}, timeout=600))

    # ──────────────── REVERSE ENGINEERING ────────────────
    def _register_reversing(self):
        cat = "reversing"
        self._register(ToolDefinition("radare2_analyze", cat,
            "Radare2 — advanced reverse engineering framework.","radare2",
            {"file":{"type":"string","description":"Binary to analyze","required":True},
            "command":{"type":"string","description":"r2 command (aaa, afl, pdf,…)"}}, timeout=120))
        self._register(ToolDefinition("gdb_debug", cat,
            "GNU Debugger — debug and analyze binaries.","gdb",
            {"binary":{"type":"string","description":"Binary to debug","required":True},
            "args":{"type":"string","description":"Binary arguments"}}, timeout=300))
        self._register(ToolDefinition("objdump_disasm", cat,
            "Display information from object/binary files.","objdump",
            {"file":{"type":"string","description":"Binary file","required":True},
            "section":{"type":"string","description":"Section to dump (.text,.data)"}}, timeout=60))
        self._register(ToolDefinition("readelf_analyze", cat,
            "Display information about ELF files.","readelf",
            {"file":{"type":"string","description":"ELF binary","required":True},
            "flags":{"type":"string","description":"Flags (-a,-h,-s,-d)"}}, timeout=30))
        self._register(ToolDefinition("strace_trace", cat,
            "System call tracer — trace binary syscalls and signals.","strace",
            {"binary":{"type":"string","description":"Binary to trace","required":True},
            "args":{"type":"string","description":"Binary arguments"}}, timeout=120))
        self._register(ToolDefinition("ltrace_trace", cat,
            "Library call tracer — trace dynamic library calls.","ltrace",
            {"binary":{"type":"string","description":"Binary to trace","required":True},
            "args":{"type":"string","description":"Binary arguments"}}, timeout=120))
        self._register(ToolDefinition("apktool_decompile", cat,
            "APK reverse engineering — decode Android apps to source.","apktool",
            {"apk":{"type":"string","description":"APK file path","required":True},
            "operation":{"type":"string","description":"d (decode) or b (build)"}}, timeout=120))
        self._register(ToolDefinition("jadx_decompile", cat,
            "Dex to Java decompiler — produce Java source from APK/DEX.","jadx",
            {"file":{"type":"string","description":"APK/DEX file","required":True},
            "output_dir":{"type":"string","description":"Output directory"}}, timeout=300))
        self._register(ToolDefinition("dex2jar_convert", cat,
            "Convert Android DEX to JAR for further decompilation.","dex2jar",
            {"dex":{"type":"string","description":"DEX file path","required":True}}, timeout=60))
        self._register(ToolDefinition("ghidra_headless", cat,
            "Ghidra headless analysis — automated binary analysis.","analyzeHeadless",
            {"project_dir":{"type":"string","description":"Ghidra project dir","required":True},
            "binary":{"type":"string","description":"Binary to analyze","required":True}}, timeout=600))
        self._register(ToolDefinition("yara_scan", cat,
            "Pattern-matching swiss army knife for malware research.","yara",
            {"rules":{"type":"string","description":"YARA rule file","required":True},
            "target":{"type":"string","description":"File/directory/PID to scan","required":True}}, timeout=300))

    # ──────────────── SOCIAL ENGINEERING ────────────────
    def _register_social(self):
        cat = "social"
        self._register(ToolDefinition("setoolkit_attack", cat,
            "Social Engineer Toolkit — phishing, credential harvesting.","setoolkit",
            {"attack":{"type":"string","description":"Attack vector"}}, timeout=30, destructive=True))
        self._register(ToolDefinition("beef_hook", cat,
            "BeEF — Browser Exploitation Framework for client-side attacks.","beef-xss",
            {"target":{"type":"string","description":"Target URL"}}, timeout=30, destructive=True))
        self._register(ToolDefinition("gophish_setup", cat,
            "Open-source phishing toolkit — campaign management.","gophish",
            {"config":{"type":"string","description":"Config file path"}}, timeout=30))

    # ──────────────── POST-EXPLOITATION ────────────────
    def _register_postex(self):
        cat = "postex"
        self._register(ToolDefinition("mimikatz_dump", cat,
            "Mimikatz — extract plaintext passwords, hashes, PINs, kerberos tickets.","mimikatz",
            {"command":{"type":"string","description":"Mimikatz command (sekurlsa::logonpasswords,…)","required":True}}, timeout=60, destructive=True))
        self._register(ToolDefinition("bloodhound_analyze", cat,
            "Active Directory attack path analysis via Neo4j graph.","bloodhound",
            {"neo4j_url":{"type":"string","description":"Neo4j URL","required":True}}, timeout=30))
        self._register(ToolDefinition("proxychains_tunnel", cat,
            "Force any TCP connection through proxy chains (Tor/SOCKS).","proxychains",
            {"binary":{"type":"string","description":"Command to proxy","required":True},
            "args":{"type":"string","description":"Arguments for binary"}}, timeout=300))
        self._register(ToolDefinition("torify_tunnel", cat,
            "Torify — route traffic through Tor network.","torify",
            {"binary":{"type":"string","description":"Command to torify","required":True}}, timeout=300))
        self._register(ToolDefinition("socat_relay", cat,
            "Multipurpose relay — forward TCP/UDP connections, create shells.","socat",
            {"listen_addr":{"type":"string","description":"Listen address (TCP-L:port)"},
            "connect_addr":{"type":"string","description":"Connect address (TCP:host:port)"},
            "exec_cmd":{"type":"string","description":"Command to execute on connect"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("netcat_listener", cat,
            "Netcat TCP/UDP listener — receive reverse shells.","nc",
            {"port":{"type":"integer","description":"Listen port","required":True},
            "ssl":{"type":"boolean","description":"Use SSL (ncat)"}}, timeout=300))
        self._register(ToolDefinition("netcat_connect", cat,
            "Netcat TCP/UDP connect — send data or spawn shells.","nc",
            {"target":{"type":"string","description":"Target host","required":True},
            "port":{"type":"integer","description":"Target port","required":True}}, timeout=60))
        self._register(ToolDefinition("ligolo_tunnel", cat,
            "Lightweight reverse tunnel with TUN interface for pivoting.","ligolo",
            {"server":{"type":"string","description":"Server address","required":True}}, timeout=300, destructive=True))
        self._register(ToolDefinition("certipy_ad", cat,
            "Active Directory certificate services enumeration and abuse.","certipy",
            {"command":{"type":"string","description":"Command (find,req,auth,…)","required":True},
            "target":{"type":"string","description":"Target DC","required":True}}, timeout=300, destructive=True))
        self._register(ToolDefinition("ssh_brute_local", cat,
            "SSH client for post-exploitation lateral movement.","ssh",
            {"target":{"type":"string","description":"Target host","required":True},
            "command":{"type":"string","description":"Remote command to execute"}}, timeout=60, destructive=True))

    # ──────────────── OSINT ────────────────
    def _register_osint(self):
        cat = "osint"
        self._register(ToolDefinition("whois_lookup", cat,
            "WHOIS domain/IP registration info lookup.","whois",
            {"target":{"type":"string","description":"Domain or IP","required":True}}, timeout=30))
        self._register(ToolDefinition("dig_dns", cat,
            "DNS lookup — query ANY record type from any server.","dig",
            {"domain":{"type":"string","description":"Domain","required":True},
            "record_type":{"type":"string","description":"A,AAAA,MX,NS,TXT,SOA,CNAME,AXFR"},
            "server":{"type":"string","description":"DNS server to query"}}, timeout=30))
        self._register(ToolDefinition("dns_enum", cat,
            "DNSenum — full DNS enumeration of a domain.","dnsenum",
            {"domain":{"type":"string","description":"Target domain","required":True},
            "brute":{"type":"boolean","description":"Subdomain brute-force"},
            "wordlist":{"type":"string","description":"Wordlist path"}}, timeout=300))
        self._register(ToolDefinition("theharvester_gather", cat,
            "Email, subdomain, name OSINT gatherer from public sources.","theHarvester",
            {"domain":{"type":"string","description":"Target domain","required":True},
            "source":{"type":"string","description":"Data source (google,linkedin,…)"}}, timeout=120))
        self._register(ToolDefinition("recon_ng_gather", cat,
            "Full-featured web reconnaissance framework.","recon-ng",
            {"workspace":{"type":"string","description":"Workspace name"}}, timeout=300))
        self._register(ToolDefinition("wget_download", cat,
            "Download files/web content for offline analysis.","wget",
            {"url":{"type":"string","description":"URL to download","required":True},
            "output":{"type":"string","description":"Output file path"},
            "recursive":{"type":"boolean","description":"Recursive download"}}, timeout=120))
        self._register(ToolDefinition("exiftool_osint", cat,
            "Extract OSINT metadata from documents/images (author, GPS, software).","exiftool",
            {"file":{"type":"string","description":"File to analyze","required":True}}, timeout=30))
        self._register(ToolDefinition("sherlock_search", cat,
            "Hunt down social media accounts by username across platforms.","sherlock",
            {"username":{"type":"string","description":"Username to search","required":True}}, timeout=300))
        self._register(ToolDefinition("holehe_check", cat,
            "Check if email is registered on various websites.","holehe",
            {"email":{"type":"string","description":"Email to check","required":True}}, timeout=120))

    # ──────────────── STRESS TESTING ────────────────
    def _register_stress(self):
        cat = "stress"
        self._register(ToolDefinition("hping3_test", cat,
            "Network packet crafter and stress-testing tool.","hping3",
            {"target":{"type":"string","description":"Target host","required":True},
            "port":{"type":"integer","description":"Target port"},
            "flood":{"type":"boolean","description":"Flood mode"},
            "syn":{"type":"boolean","description":"SYN packets"}}, timeout=120, destructive=True))
        self._register(ToolDefinition("slowhttptest_test", cat,
            "Application-layer DoS — Slowloris, Slow POST, Slow Read, Range Attack.","slowhttptest",
            {"target":{"type":"string","description":"Target URL","required":True},
            "mode":{"type":"string","description":"Attack mode (B,R,X)"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("ab_bench", cat,
            "ApacheBench — HTTP server benchmarking tool.","ab",
            {"url":{"type":"string","description":"Target URL","required":True},
            "requests":{"type":"integer","description":"Number of requests"},
            "concurrency":{"type":"integer","description":"Concurrent requests"}}, timeout=120))
        self._register(ToolDefinition("siege_bench", cat,
            "HTTP/HTTPS load testing and benchmarking tool.","siege",
            {"url":{"type":"string","description":"Target URL","required":True},
            "concurrent":{"type":"integer","description":"Concurrent users"},
            "time":{"type":"string","description":"Test duration"}}, timeout=300, destructive=True))

    # ──────────────── HARDWARE HACKING ────────────────
    def _register_hardware(self):
        cat = "hardware"
        self._register(ToolDefinition("minicom_serial", cat,
            "Serial communication program for UART/JTAG debugging.","minicom",
            {"device":{"type":"string","description":"Serial device","required":True}}, timeout=30))
        self._register(ToolDefinition("flashrom_flash", cat,
            "Flash BIOS/EFI/coreboot/firmware images to chips.","flashrom",
            {"chip":{"type":"string","description":"Flash chip"},
            "read":{"type":"string","description":"Read to file"},
            "write":{"type":"string","description":"Write from file"}}, timeout=300, destructive=True))
        self._register(ToolDefinition("screen_serial", cat,
            "Terminal multiplexer for serial console access.","screen",
            {"device":{"type":"string","description":"Serial device","required":True},
            "baud":{"type":"integer","description":"Baud rate"}}, timeout=30))

    # ──────────────── UTILITY ────────────────
    def _register_utility(self):
        cat = "utility"
        self._register(ToolDefinition("wireshark_gui", cat,
            "Wireshark — graphical network protocol analyzer.","wireshark",
            {"file":{"type":"string","description":"PCAP file to open"}}, timeout=30))
        self._register(ToolDefinition("hexeditor_edit", cat,
            "Hex editor for binary file analysis and patching.","hexeditor",
            {"file":{"type":"string","description":"File to edit","required":True}}, timeout=30))
        self._register(ToolDefinition("ldd_analyze", cat,
            "List dynamic library dependencies of a binary.","ldd",
            {"binary":{"type":"string","description":"Binary to analyze","required":True}}, timeout=10))
        self._register(ToolDefinition("ssh_client", cat,
            "OpenSSH client for secure remote access.","ssh",
            {"target":{"type":"string","description":"Target host","required":True},
            "command":{"type":"string","description":"Remote command to execute"}}, timeout=60))
        # ──────────────── TOOL INSTALLER (self-healing) ────────────────
        self._register(ToolDefinition("install_tool", cat,
            "Install a missing security tool on-demand. Use this when a needed tool is not installed. Supports apt, pip, Go binaries, and GitHub releases. All downloads cached locally for offline use.","",
            {"tool_name":{"type":"string","description":"Binary name or tool name to install (e.g. 'nuclei', 'ffuf', 'enum4linux')","required":True}}, timeout=600))
        self._register(ToolDefinition("list_missing_tools", cat,
            "List all security tools that are registered but not currently installed, with their install method.","",
            {}, timeout=10))
        self._register(ToolDefinition("install_all_missing", cat,
            "Batch-install up to N missing tools that have install recipes. Use to quickly bootstrap a fresh environment.","",
            {"max_tools":{"type":"integer","description":"Max tools to install in one batch (default 20)"}}, timeout=1800))
        self._register(ToolDefinition("check_tool_status", cat,
            "Check if a specific tool is installed, where it lives, and if it can be auto-installed.","",
            {"tool_name":{"type":"string","description":"Tool name to check","required":True}}, timeout=10))

    # ═══════════════════════════════════════════════════════════════
    # REGISTRY MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    def _register(self, tool: ToolDefinition):
        self._tools[tool.name] = tool

    def _detect_installed(self):
        for name, tool in self._tools.items():
            config_path = self.config.get(tool.binary, "") or self.config.get(name, "")
            if config_path and os.path.isfile(config_path):
                tool.path = config_path
                tool.installed = True
            else:
                tool.detect()
            if tool.installed:
                logger.debug(f"✓ {name}")
            else:
                logger.debug(f"✗ {name} ({tool.binary})")

    # ── queries ──
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def get_all_tools(self) -> Dict[str, ToolDefinition]:
        return self._tools.copy()

    def get_tools_by_category(self, category: str) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if t.category == category]

    def get_installed_tools(self) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if t.installed]

    def get_available_count(self) -> int:
        return sum(1 for t in self._tools.values() if t.installed)

    def get_total_count(self) -> int:
        return len(self._tools)

    def get_tool_definitions_json(self) -> str:
        lines = []
        for t in self._tools.values():
            if not t.installed:
                continue
            lines.append(f"- **{t.name}** [{t.category}]: {t.description}")
            if t.parameters:
                for pn, pi in t.parameters.items():
                    req = " [REQUIRED]" if pi.get("required") else ""
                    lines.append(f"    - {pn}: {pi.get('description','')}{req}")
        return "\n".join(lines)

    def get_tool_definitions_for_llm(self) -> list:
        return [t.to_llm_definition() for t in self._tools.values() if t.installed]

    # ═══════════════════════════════════════════════════════════════
    # COMMAND BUILDING & EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def execute(self, tool_name: str, args: dict) -> Dict[str, Any]:
        tool = self._tools.get(tool_name)
        if not tool:
            return {"stdout":"", "stderr":f"Unknown tool: {tool_name}", "exit_code":-1, "duration":0}
        if not tool.installed and tool.binary not in ("",):  # empty binary = informational
            return {"stdout":"", "stderr":f"Tool not installed: {tool_name} ({tool.binary})", "exit_code":-1, "duration":0}

        cmd = self._build_command(tool, args)
        logger.info(f"Execute: {' '.join(cmd)}")

        start = datetime.now()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=tool.timeout)
            dur = (datetime.now() - start).total_seconds()
            return {"stdout": r.stdout, "stderr": r.stderr, "exit_code": r.returncode,
                    "duration": round(dur, 2), "command": " ".join(cmd)}
        except subprocess.TimeoutExpired:
            dur = (datetime.now() - start).total_seconds()
            return {"stdout":"", "stderr":f"Timeout after {tool.timeout}s",
                    "exit_code":-1, "duration": round(dur, 2), "command":" ".join(cmd)}
        except Exception as e:
            dur = (datetime.now() - start).total_seconds()
            return {"stdout":"", "stderr":str(e), "exit_code":-1,
                    "duration": round(dur, 2), "command":" ".join(cmd)}

    def _build_command(self, tool: ToolDefinition, args: dict) -> list:
        """Delegate command construction to the dedicated command_builder module."""
        return _build_command_impl(self._output_dir, tool, args)

    def get_status(self) -> dict:
        categories = {}
        for t in self._tools.values():
            c = categories.setdefault(t.category, {"total":0,"installed":0})
            c["total"] += 1
            if t.installed: c["installed"] += 1
        return {"total_tools": self.get_total_count(),
                "installed_tools": self.get_available_count(),
                "categories": categories}