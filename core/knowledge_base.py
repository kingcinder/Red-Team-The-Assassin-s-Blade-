"""
RedTeam Harness — Offline Cybersecurity Knowledge Base (v5.6)
=============================================================

A curated, air-gap-safe knowledge base the LLM can reference during
engagements — CVE database, MITRE ATT&CK technique mappings, exploit
signatures, and remediation playbooks — all embedded in this module (no
network access required) and indexed for fast retrieval alongside the
vector memory system.

Components:
  - CVE_DATABASE: curated list of high-value CVEs with severity, affected
    software, exploit signatures (regex patterns), ATT&CK technique links,
    and concrete remediation playbooks (steps + shell commands).
  - ATTACK_TECHNIQUES: MITRE ATT&CK technique catalogue (id, name, tactic,
    detection, mitigation) mirroring the correlation engine's table plus
    detection/mitigation guidance.
  - EXPLOIT_SIGNATURES: regex patterns that match tool output / banners to
    known CVEs (e.g. "MS17-010", "Log4Shell") for automatic grounding.
  - KnowledgeBase class: TF-IDF vector index (mirrors VectorMemory's
    scikit-learn approach) for fast similarity search, plus
    signature-based exact grounding.

Usage:
    kb = KnowledgeBase()
    kb.lookup_cve("CVE-2021-44228")
    kb.search("log4j remote code execution", top_k=5)
    kb.signature_match("445/tcp MS17-010 vulnerable")  # -> [CVE-2017-0144]
    kb.ground_findings(findings)   # attach cves/techniques/remediation
    kb.get_context_block("log4shell")  # sanitized, LLM-ready
"""

import os
import re
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("redteam.knowledge")

# ── Optional scikit-learn (already used by VectorMemory) for TF-IDF search ──
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    _HAS_SKLEARN = True
except Exception:  # pragma: no cover - graceful degradation
    _HAS_SKLEARN = False

from core.injection_defense import sanitize_for_llm

SIMILARITY_THRESHOLD = 0.12
CONTEXT_MAX_CHARS = 4000
CONTEXT_MAX_ENTRIES = 8


# ═══════════════════════════════════════════════════════════════════
# CURATED ATT&CK TECHNIQUE CATALOGUE
# (id -> {name, tactic, detection, mitigation})
# ═══════════════════════════════════════════════════════════════════
ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "detection": "Monitor for large-volume port scans (SYN floods, sequential ports) from a single source via firewall/IDS logs.",
              "mitigation": "Restrict reachable services to least-privilege access lists; block scanning sources; rate-limit connection attempts."},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "detection": "Web/WAF logs showing exploit payloads (SQLi, LFI/RFI, command injection) against public endpoints.",
              "mitigation": "Patch public apps, WAF rules, input validation, disable unnecessary modules, segment public-facing tiers."},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement",
              "detection": "SMB/RDP/SSH exploit signatures (EternalBlue, BlueKeep) in network telemetry; anomalous authentication bursts.",
              "mitigation": "Patch remote services, disable SMBv1, enforce MFA on RDP/SSH, restrict management interfaces."},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access",
              "detection": "Browser exploit indicators: malformed documents, obfuscated JS, unexpected downloads.",
              "mitigation": "Patch browsers/plugins, web-filtering, disable ActiveX/Flash, sandbox browsing."},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access",
              "detection": "Anomalous VPN/RDP/SSH logins from unfamiliar IPs, off-hours access.",
              "mitigation": "MFA, account lockout, geo-fencing, monitor for credential stuffing."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "detection": "Shell/PowerShell/script execution logs; encoded commands (base64, -enc).",
              "mitigation": "AppLocker/WDAC, PowerShell Constrained Language, monitor child processes."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                  "detection": "PowerShell module logging, script block logging, AMSI detections.",
                  "mitigation": "Constrained Language Mode, script block logging, block malicious modules."},
    "T1059.006": {"name": "Python", "tactic": "Execution",
                  "detection": "Monitor python processes spawned from non-interactive contexts.",
                  "mitigation": "Restrict python execution on servers, application allowlisting."},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
              "detection": "Beaconing intervals, unusual HTTP/S traffic to non-standard hosts.",
              "mitigation": "Network segmentation, egress filtering, TLS inspection."},
    "T1005": {"name": "Data from Local System", "tactic": "Collection",
              "detection": "Sensitive file access (SAM, credentials, archives) by unusual processes.",
              "mitigation": "Credential Guard, file permissions, EDR rules on sensitive paths."},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
              "detection": "Encoded/obfuscated payloads in memory or on disk; packer heuristics.",
              "mitigation": "EDR behavioral detections, sandboxing, code-signing enforcement."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "detection": "LSASS access attempts, mimikatz/SecLogon activity, dump files.",
              "mitigation": "Credential Guard, LSASS protection, restricted admin accounts."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "detection": "Repeated failed logins (SSH/RDP/web forms) from single/rotating sources.",
              "mitigation": "Account lockout, rate limiting, MFA, fail2ban-style controls."},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence",
              "detection": "New admin/SSH-key additions, privilege changes outside change windows.",
              "mitigation": "Privileged account monitoring, key rotation, change management."},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
              "detection": "Kernel exploit signatures (DirtyPipe, PrintNightmare), unexpected SYSTEM/root processes.",
              "mitigation": "Patch kernels/printers, restrict privileged services, container hardening."},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
              "detection": "sudo misconfigurations (NOPASSWD), UAC bypasses, setuid anomalies.",
              "mitigation": "Audit sudoers, least privilege, remove setuid where possible."},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence",
              "detection": "DLL search-order hijacking, LD_PRELOAD, modified PATH entries.",
              "mitigation": "Signed DLLs, secure PATH, monitor DLL loads."},
    "T1136": {"name": "Create Account", "tactic": "Persistence",
              "detection": "New local/domain accounts created outside IT change processes.",
              "mitigation": "Monitor account creation events, approval workflows."},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery",
              "detection": "systeminfo/hostname/uname enumeration from non-admin processes.",
              "mitigation": "Endpoint monitoring, restrict discovery tooling."},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery",
              "detection": "whoami/id enumeration bursts before lateral movement.",
              "mitigation": "Monitor identity queries, tiered access."},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery",
              "detection": "Directory traversal enumeration (find/dir) of sensitive paths.",
              "mitigation": "Restrict file shares, monitor enumeration."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion",
              "detection": "Use of compromised/stale accounts; impossible travel.",
              "mitigation": "MFA, credential rotation, privileged access management."},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "detection": "SMB/SSH/WinRM/RDP connections between internal hosts at scale.",
              "mitigation": "Segment networks, restrict lateral protocols, monitor inter-host connections."},
    "T1566": {"name": "Phishing", "tactic": "Initial Access",
              "detection": "Malicious email indicators, sandbox detonations, user-reported phishing.",
              "mitigation": "Email filtering, DMARC/DKIM/SPF, user awareness, URL isolation."},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion",
              "detection": "Signed binaries (rundll32, mshta, certutil) fetching/executing remote content.",
              "mitigation": "Block dangerous LOLBins, application control."},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery",
              "detection": "net view / AD enumeration from compromised hosts.",
              "mitigation": "Monitor enumeration, limit AD query access."},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "Discovery",
              "detection": "nltest/trust queries from unexpected hosts.",
              "mitigation": "Monitor trust queries, limit who can query trusts."},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access",
              "detection": "Golden/silver ticket artifacts, AS-REP roasting, Kerberoasting activity.",
              "mitigation": "Monitor TGT/TGS requests, rotate krbtgt, disable RC4, long/complex service passwords."},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access",
              "detection": "ARP spoofing, rogue DHCP, SSL stripping indicators.",
              "mitigation": "802.1X, DHCP snooping, TLS everywhere."},
    "T1556": {"name": "Modify Authentication Process", "tactic": "Credential Access",
              "detection": "Installed credential providers, modified PAM, shadow password tampering.",
              "mitigation": "File integrity monitoring, secure boot, audit auth modules."},
    "T1587": {"name": "Develop Capabilities", "tactic": "Resource Development",
              "detection": "Compilation of custom tooling on internal hosts.",
              "mitigation": "Restrict compilers on production, monitor build activity."},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance",
              "detection": "OSINT harvesting of employee identities/emails.",
              "mitigation": "Minimize public data, monitor credential exposure."},
    "T1596": {"name": "Search Open Technical Databases", "tactic": "Reconnaissance",
              "detection": "Certificate transparency / DNS brute-force enumeration spikes.",
              "mitigation": "Wildcard certs sparingly, monitor DNS queries."},
    "T1593": {"name": "Search Open Websites/Domains", "tactic": "Reconnaissance",
              "detection": "Automated OSINT sweeps of the org's web presence.",
              "mitigation": "Reduce exposed data, honeypot detection."},
    "T1609": {"name": "Container Administration Command", "tactic": "Execution",
              "detection": "docker/kubectl exec from unexpected sources.",
              "mitigation": "RBAC, container runtime audit, restrict exec."},
    "T1610": {"name": "Deploy Container", "tactic": "Execution",
              "detection": "Unexpected container/image deployment on hosts.",
              "mitigation": "Image signing, admission control, supply-chain scanning."},
    "T1611": {"name": "Escape to Host", "tactic": "Privilege Escalation",
              "detection": "Container escape exploit signatures (CVE-2022-0492, runc CVEs), unexpected host processes from containers.",
              "mitigation": "Least-privilege containers, seccomp/AppArmor, patch runc/kernel, no privileged containers."},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access",
              "detection": "Credentials in files (bash history, configs, .env, cloud metadata endpoints).",
              "mitigation": "Secret managers, scan repos, disable IMDS where possible."},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection",
              "detection": "Access to wikis/sharepoint/git repos beyond role need.",
              "mitigation": "Least privilege, monitor repo access."},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access",
              "detection": "Promiscuous mode NICs, tcpdump/tshark on non-admin hosts.",
              "mitigation": "Port security, encrypted protocols, monitor sniffers."},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "detection": "Large outbound transfers over beacon channels.",
              "mitigation": "Data-loss prevention, egress inspection."},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection",
              "detection": "zip/tar/rar creation on sensitive directories before exfiltration.",
              "mitigation": "Monitor archive tool usage, DLP."},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact",
              "detection": "Traffic floods, amplification (NTP/DNS) spikes.",
              "mitigation": "DDoS mitigation, rate limiting, anycast."},
    # ── v5.7: technique ids referenced by the correlation engine ──
    "T1596.001": {"name": "DNS/Passive DNS", "tactic": "Reconnaissance",
                  "detection": "DNS brute-force/subdomain enumeration spikes in resolver logs.",
                  "mitigation": "Monitor DNS queries; restrict zone transfers; use wildcard certs sparingly."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence",
               "detection": "New scheduled tasks/cron entries created outside change windows (event 4698).",
               "mitigation": "Audit scheduled-task creation; restrict who can create tasks; monitor cron."},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence",
               "detection": "Registry Run keys / startup-folder additions; autorun anomalies.",
               "mitigation": "Monitor autoruns (Sysinternals Autoruns), application allowlisting."},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence",
                   "detection": "Suspicious .aspx/.php/.jsp files in web roots; web shell scanners.",
                   "mitigation": "File-integrity monitoring on web roots, WAF rules, remove write access."},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation",
                   "detection": "sudo misconfigurations (NOPASSWD), timestamp_timeout abuse, unusual sudo usage.",
                   "mitigation": "Audit sudoers, least privilege, disable NOPASSWD, short timestamp_timeout."},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation",
               "detection": "Token duplication/impersonation API calls (DuplicateToken, ImpersonateLoggedOnUser).",
               "mitigation": "Monitor token-manipulation APIs, restrict SeDebugPrivilege, enable PPL."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion",
               "detection": "Injection API calls (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) into other processes.",
               "mitigation": "EDR behavioral monitoring, block cross-process writes, enable ETW."},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access",
                   "detection": "Kerberos service-ticket requests (event 4769) with RC4 encryption from non-service hosts.",
                   "mitigation": "Enforce AES-only Kerberos, long random service passwords (gMSA), monitor 4769."},
    "T1558.004": {"name": "AS-REP Roasting", "tactic": "Credential Access",
                   "detection": "Kerberos AS-REP requests (event 4768) for accounts with pre-auth disabled.",
                   "mitigation": "Enable pre-authentication on all accounts, monitor 4768, rotate exposed hashes."},
    "T1003.006": {"name": "DCSync", "tactic": "Credential Access",
                   "detection": "Directory replication (DRSUAPI) requests from non-domain-controller hosts.",
                   "mitigation": "Restrict replication rights to legitimate DCs, monitor event 4662, use RODCs."},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access",
                   "detection": "LSASS process access (OpenProcess) by non-system processes; mimikatz signatures.",
                   "mitigation": "Credential Guard, LSASS protection, restrict SeDebugPrivilege."},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access",
                   "detection": "Low-volume failed logins (event 4625) across many accounts from one source.",
                   "mitigation": "Account lockout + throttling, MFA, monitor 4625, fail2ban-style controls."},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement",
               "detection": "Pass-the-hash/ticket authentication anomalies; NTLM hash use in network auth.",
               "mitigation": "Enforce Kerberos with AES, disable NTLM where possible, monitor logon types."},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement",
                   "detection": "NTLM logons (type 3) with known-compromised hashes; SMB auth from unusual hosts.",
                   "mitigation": "Disable NTLM, enforce Kerberos, monitor 4624/4625, credential guard."},
    "T1550.003": {"name": "Pass the Ticket", "tactic": "Lateral Movement",
                   "detection": "Kerberos ticket use from hosts/times inconsistent with issuance (4769/4624).",
                   "mitigation": "Monitor ticket usage, use AES, restrict TGT lifetimes, protect krbtgt."},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                   "detection": "RDP inbound connections (4624 logon type 10) from unusual sources.",
                   "mitigation": "Restrict RDP with NLA + firewall, enforce MFA, monitor 4624 type 10."},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                   "detection": "Admin-share (C$, ADMIN$) access from unexpected hosts (event 5140).",
                   "mitigation": "Restrict admin shares, monitor 5140, least privilege, segment network."},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement",
                   "detection": "SSH connections to internal hosts from compromised hosts; key-auth spikes.",
                   "mitigation": "Restrict SSH egress, key management, monitor sshd logs, enforce jump hosts."},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution",
               "detection": "wmic/powershell WMI process creation (4688 with WmiPrvSE.exe parent).",
               "mitigation": "Restrict WMI namespace access, monitor process creation, disable unneeded WMI."},
    "T1552.005": {"name": "Cloud Instance Metadata API", "tactic": "Credential Access",
                   "detection": "HTTP requests to 169.254.169.254 from web/app tiers (SSRF or local).",
                   "mitigation": "Block IMDS from web-facing proxies, enforce IMDSv2, least-privilege roles."},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Defense Evasion",
                   "detection": "Cloud console/API logins with elevated roles from unusual IPs/devices.",
                   "mitigation": "MFA, conditional access, monitor cloud sign-in logs (CloudTrail, Azure AD)."},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance",
               "detection": "Host-fingerprinting sweeps (OS/software version probing).",
               "mitigation": "Minimize exposed banners, network segmentation, monitor scanning."},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance",
               "detection": "Credential-harvesting pages; cloned login portals.",
               "mitigation": "DMARC/DKIM/SPF, browser isolation, security awareness training."},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access",
               "detection": "Tampered software updates/artifacts; unexpected binary hashes.",
               "mitigation": "Code signing + integrity verification, private registries, SBOM."},
    "T1195.001": {"name": "Compromise Software Dependencies and Development Tools", "tactic": "Initial Access",
                   "detection": "Malicious packages in build pipelines (typosquatting, backdoored deps).",
                   "mitigation": "Dependency lockfiles + SCA scanning, private registries, signed commits."},
    "T1195.002": {"name": "Compromise Software Supply Chain", "tactic": "Initial Access",
                   "detection": "Tampered release artifacts or update channels.",
                   "mitigation": "Artifact signing (Sigstore), hash verification, monitored release pipelines."},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution",
               "detection": "Office/browser exploits (macros, embedded objects) detonating malware.",
               "mitigation": "Disable macros, patch clients, sandbox attachments, ASR rules."},
    "T1059.007": {"name": "JavaScript/JScript", "tactic": "Execution",
                   "detection": "node/js execution from non-interactive contexts; JScript engine abuse.",
                   "mitigation": "Application allowlisting, restrict scripting engines, EDR on child processes."},
    "T1204": {"name": "User Execution", "tactic": "Execution",
               "detection": "Malicious documents/links opened by users; attachment sandbox detonations.",
               "mitigation": "Email/URL filtering, disable macros, security awareness, browser isolation."},
    "T1552.007": {"name": "Container API", "tactic": "Credential Access",
                   "detection": "kubectl/container-runtime API calls retrieving secrets or configmaps.",
                   "mitigation": "External secret managers, etcd encryption at rest, RBAC on secret get/list."},
    "T1554": {"name": "Compromise Client Software Binary", "tactic": "Persistence",
               "detection": "Tampered system binaries (e.g. liblzma/sshd interposition) — file-hash drift, LD_PRELOAD anomalies.",
               "mitigation": "Verify package integrity (rpm -V / dpkg -V), code signing, artifact provenance."},
}


# ── Derived single-source exports (consumed by core/correlation.py) ──
# correlation.py previously owned copies of these tables; the delete-test
# passes (deleting its copies concentrates complexity here), and name/tactic
# drift is impossible by construction. T1046 is MITRE-correct "Discovery"
# here — NOT "Reconnaissance" as the old correlation table claimed.
TECHNIQUE_NAMES: Dict[str, str] = {
    tid: meta["name"] for tid, meta in ATTACK_TECHNIQUES.items()}
ATTACK_TACTICS: Dict[str, str] = {
    tid: meta["tactic"] for tid, meta in ATTACK_TECHNIQUES.items()}
ATTACK_TACTIC_ORDER: List[str] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


# ═══════════════════════════════════════════════════════════════════
# CURATED CVE DATABASE
# Each entry: id, title, cvss, severity, description, affected, techniques,
# signatures (regexes matched against tool output / banners), remediation
# (steps + shell commands).
# ═══════════════════════════════════════════════════════════════════
CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "id": "CVE-2017-0144",
        "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
        "cvss": 8.1, "severity": "critical",
        "description": "SMBv1 server RCE in Windows; the basis of WannaCry. Allows unauthenticated remote code execution on port 445.",
        "affected": "Windows XP/Vista/7/8/10, Server 2003-2016 (unpatched)",
        "techniques": ["T1210", "T1190"],
        "signatures": [r"MS17-?010", r"eternalblue", r"smbv1"],
        "remediation": [
            "Apply Microsoft security update MS17-010 (KB4013389+) immediately.",
            "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false.",
            "Block TCP/445 and TCP/139 at the perimeter and host firewalls.",
            "Segment legacy Windows hosts from the rest of the network.",
        ],
        "commands": [
            "powershell -Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
            "sudo ufw deny 445/tcp && sudo ufw deny 139/tcp",
        ],
    },
    {
        "id": "CVE-2019-0708",
        "title": "Remote Desktop Services RCE (BlueKeep)",
        "cvss": 9.8, "severity": "critical",
        "description": "Pre-auth RCE in Remote Desktop Services (RDP). Wormable; exploitable without credentials on port 3389.",
        "affected": "Windows 7, Server 2008/2008 R2, XP (unpatched)",
        "techniques": ["T1210", "T1190"],
        "signatures": [r"bluekeep", r"CVE-2019-0708", r"msrdp"],
        "remediation": [
            "Install the KB4499175/CVE-2019-0708 security update.",
            "Enable Network Level Authentication (NLA) to block pre-auth exploitation.",
            "Restrict RDP to known management hosts via firewall/ACL.",
        ],
        "commands": [
            "sudo ufw deny 3389/tcp",
        ],
    },
    {
        "id": "CVE-2021-44228",
        "title": "Apache Log4j2 RCE (Log4Shell)",
        "cvss": 10.0, "severity": "critical",
        "description": "JNDI lookup injection in Log4j2 2.0-2.14.1 allows unauthenticated remote code execution via crafted log messages (${jndi:ldap://...}).",
        "affected": "Apache Log4j2 2.0 through 2.14.1 (also 2.15.0 with JndiLookup enabled)",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"log4j", r"log4shell", r"CVE-2021-44228", r"\$\{jndi:"],
        "remediation": [
            "Upgrade Log4j2 to 2.17.1+ (or 2.12.4 for Java 7).",
            "Set -Dlog4j2.formatMsgNoLookups=true if upgrade is not possible.",
            "Remove JndiLookup from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class.",
            "Apply WAF rules blocking ${jndi: payloads at the edge.",
        ],
        "commands": [
            "sudo apt install --only-upgrade liblog4j2-java",
            "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
        ],
    },
    {
        "id": "CVE-2021-45046",
        "title": "Log4j2 RCE (Log4Shell variant, 2.15.0)",
        "cvss": 9.0, "severity": "critical",
        "description": "Incomplete fix for CVE-2021-44228 in Log4j 2.15.0 — JNDI lookups still exploitable under certain configurations.",
        "affected": "Apache Log4j2 2.15.0",
        "techniques": ["T1190"],
        "signatures": [r"log4j", r"CVE-2021-45046"],
        "remediation": [
            "Upgrade to Log4j2 2.17.1+.",
            "Re-run the JndiLookup removal and ${jndi: WAF blocking from CVE-2021-44228.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-26855",
        "title": "Microsoft Exchange Server RCE (ProxyLogon)",
        "cvss": 9.8, "severity": "critical",
        "description": "Pre-auth SSRF in Exchange on-premises allows server-side request forgery leading to RCE and mailbox compromise.",
        "affected": "Exchange Server 2013/2016/2019 (unpatched)",
        "techniques": ["T1190", "T1133"],
        "signatures": [r"proxylogon", r"proxyshell", r"CVE-2021-26855", r"exchange"],
        "remediation": [
            "Apply the March 2021 Exchange Cumulative Updates immediately.",
            "Check for webshells: C:\\inetpub\\wwwroot\\aspnet_client\\* and IIS logs for /owa/auth/*.aspx.",
            "Scan for post-exploitation artifacts (Suspicious objects, new mailboxes).",
        ],
        "commands": [
            "python3 -m http.server 80 & curl -k https://HOST/owa/auth/logon.aspx -o /dev/null",
        ],
    },
    {
        "id": "CVE-2022-22965",
        "title": "Spring Framework RCE (Spring4Shell)",
        "cvss": 9.8, "severity": "critical",
        "description": "Data binding on class property allows RCE in Spring MVC/WebFlux apps on JDK 9+ running Tomcat (class.module.classLoader).",
        "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19, Spring Boot 2.6.0-2.6.5 / 2.5.0-2.5.14",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"spring4shell", r"springshell", r"CVE-2022-22965", r"class\.module\.classLoader"],
        "remediation": [
            "Upgrade Spring Framework to 5.3.18+/5.2.20+ or Spring Boot 2.6.6+/2.5.15+.",
            "Apply WAF rules blocking class.module.classLoader in request parameters.",
            "Do NOT rely on Tomcat-only mitigations (patch is mandatory).",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2020-1472",
        "title": "Netlogon Elevation of Privilege (Zerologon)",
        "cvss": 10.0, "severity": "critical",
        "description": "Cryptographic flaw in Netlogon (MS-NRPC) allows unauthenticated attacker to impersonate any computer, including domain controllers, granting domain admin.",
        "affected": "Windows Server 2008-2019 (all domain controllers)",
        "techniques": ["T1558", "T1068"],
        "signatures": [r"zerologon", r"CVE-2020-1472", r"netlogon"],
        "remediation": [
            "Apply the August 2020 patch and enforce the secure RPC protection enforcement phase.",
            "Monitor Netlogon event ID 5827/5828 for vulnerable clients.",
            "Reset any machine account passwords believed compromised (realmd/samba tooling).",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2020-0601",
        "title": "Windows CryptoAPI Spoofing (CurveBall)",
        "cvss": 8.1, "severity": "high",
        "description": "Flaw in Windows CryptoAPI (crypt32.dll) ECC validation allows spoofing of code-signing certs and TLS with attacker-crafted elliptic curves.",
        "affected": "Windows 10, Server 2016/2019",
        "techniques": ["T1190"],
        "signatures": [r"curveball", r"CVE-2020-0601", r"crypt32"],
        "remediation": [
            "Apply the January 2020 Patch Tuesday update.",
            "Monitor for certificates signed with unusual ECC parameters.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-1675",
        "title": "Windows Print Spooler RCE (PrintNightmare)",
        "cvss": 8.8, "severity": "critical",
        "description": "Print Spooler remote code execution via crafted printer driver / PrintNightmare variants; allows SYSTEM execution and often lateral movement.",
        "affected": "Windows 7+, Server 2008+",
        "techniques": ["T1068", "T1210"],
        "signatures": [r"printnightmare", r"CVE-2021-1675", r"CVE-2021-34527", r"spoolsv"],
        "remediation": [
            "Apply July 2021 patches and registry keys (RestrictDriverInstallationToAdministrators).",
            "Disable the Print Spooler service where printers are not needed.",
            "Remove printer drivers no longer used (Remove-PrinterDriver).",
        ],
        "commands": [
            "powershell -Command \"Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled\"",
        ],
    },
    {
        "id": "CVE-2022-0847",
        "title": "Linux Kernel Dirty Pipe",
        "cvss": 7.8, "severity": "high",
        "description": "Kernel pipe-buffer flaw allows overwriting data in read-only files (incl. setuid binaries) → local privilege escalation to root.",
        "affected": "Linux kernels 5.8 through 5.16.10/5.15.25/5.10.102",
        "techniques": ["T1068"],
        "signatures": [r"dirty.?pipe", r"CVE-2022-0847", r"dirtypipe"],
        "remediation": [
            "Upgrade the kernel to a patched release (5.16.11+, 5.15.25+, 5.10.102+).",
            "Restrict access to sensitive read-only files and setuid binaries.",
            "Detect: look for suspicious writes to read-only files in audit logs.",
        ],
        "commands": ["sudo apt upgrade linux-image-generic"],
    },
    {
        "id": "CVE-2022-0492",
        "title": "Linux Kernel cgroups v1 Container Escape",
        "cvss": 7.0, "severity": "high",
        "description": "cgroups v1 release_agent escape lets a container process escape to the host if it can mount the cgroup filesystem (CAP_SYS_ADMIN or unprivileged user namespaces).",
        "affected": "Linux kernels with cgroups v1 + release_agent (all distros)",
        "techniques": ["T1611", "T1068"],
        "signatures": [r"CVE-2022-0492", r"cgroup.*release_agent", r"container.*escape"],
        "remediation": [
            "Patch kernel; prefer cgroups v2.",
            "Do not run privileged containers; drop CAP_SYS_ADMIN.",
            "Disable unprivileged user namespaces: kernel.unprivileged_userns_clone=0 where acceptable.",
        ],
        "commands": [
            "sudo sysctl -w kernel.unprivileged_userns_clone=0",
        ],
    },
    {
        "id": "CVE-2014-6271",
        "title": "GNU Bash RCE (Shellshock)",
        "cvss": 9.8, "severity": "critical",
        "description": "Bash environment variable function definition parsing flaw allows arbitrary command execution via crafted HTTP headers (User-Agent, Cookie).",
        "affected": "Bash < 4.3 patched versions (all OSes shipping old bash)",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"shellshock", r"CVE-2014-6271", r"env x="],
        "remediation": [
            "Update bash: apt/yum upgrade bash.",
            "WAF block header patterns: () { :; }; in User-Agent/Cookie.",
        ],
        "commands": ["sudo apt install --only-upgrade bash"],
    },
    {
        "id": "CVE-2014-0160",
        "title": "OpenSSL Heartbleed",
        "cvss": 7.5, "severity": "high",
        "description": "TLS heartbeat extension buffer over-read leaks up to 64KB of server memory per request (keys, passwords, session data).",
        "affected": "OpenSSL 1.0.1 through 1.0.1f",
        "techniques": ["T1552", "T1046"],
        "signatures": [r"heartbleed", r"CVE-2014-0160"],
        "remediation": [
            "Upgrade OpenSSL to 1.0.1g+ and restart services.",
            "Revoke and reissue TLS certificates after upgrade.",
            "Rotate credentials that may have been exposed.",
        ],
        "commands": ["sudo apt install --only-upgrade openssl"],
    },
    {
        "id": "CVE-2019-15107",
        "title": "Webmin pre-auth RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Webmin <=1.920 password_change.cgi allows unauthenticated RCE when password expiry is enabled.",
        "affected": "Webmin 1.890-1.920",
        "techniques": ["T1190"],
        "signatures": [r"webmin", r"CVE-2019-15107", r"password_change\.cgi"],
        "remediation": [
            "Upgrade Webmin to 1.930+.",
            "Restrict Webmin port (10000) to admin networks.",
        ],
        "commands": ["sudo ufw deny 10000/tcp"],
    },
    {
        "id": "CVE-2020-1350",
        "title": "Windows DNS Server RCE (SIGRed)",
        "cvss": 10.0, "severity": "critical",
        "description": "Windows DNS server heap overflow, wormable, exploitable via crafted DNS responses (no auth, no user interaction).",
        "affected": "Windows Server 2008-2019 DNS roles",
        "techniques": ["T1190", "T1210"],
        "signatures": [r"sigred", r"CVE-2020-1350"],
        "remediation": [
            "Apply the July 2020 patch (KB4565479+).",
            "Registry workaround: set TcpReceivePacketSize=0xFF00 and restart DNS.",
        ],
        "commands": [
            "powershell -Command \"Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters -Name TcpReceivePacketSize -Type DWord -Value 0xFF00\"",
        ],
    },
    {
        "id": "CVE-2020-3452",
        "title": "Cisco ASA/FTD Path Traversal (directory disclosure)",
        "cvss": 7.5, "severity": "high",
        "description": "Unauthenticated path traversal in ASA/FTD web VPN leaks files (include/localized/*) via crafted URL with .%2e/ traversal.",
        "affected": "Cisco ASA 9.x, FTD 6.x (pre-fix)",
        "techniques": ["T1190"],
        "signatures": [r"CVE-2020-3452", r"\+CSCvf7", r"localized.*\.%2e"],
        "remediation": [
            "Upgrade ASA/FTD to patched releases.",
            "Restrict management interface and web VPN exposure.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-34527",
        "title": "Windows Print Spooler RCE (PrintNightmare LPE)",
        "cvss": 8.8, "severity": "critical",
        "description": "PrintNightmare variant enabling remote/local code execution as SYSTEM via Spooler AddPrinterDriver.",
        "affected": "Windows 7+, Server 2008+ (unpatched)",
        "techniques": ["T1068", "T1210"],
        "signatures": [r"printnightmare", r"CVE-2021-34527"],
        "remediation": [
            "Apply KB5004945+; block inbound SMB/RPC to the Spooler.",
            "Disable Spooler where not required (see CVE-2021-1675).",
        ],
        "commands": [
            "powershell -Command \"Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled\"",
        ],
    },
    {
        "id": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset DoS",
        "cvss": 7.5, "severity": "high",
        "description": "HTTP/2 stream cancellation loop enables record-scale DDoS via rapid request/reset without server-side cleanup.",
        "affected": "HTTP/2-capable servers (nginx, Apache, Envoy, etc.)",
        "techniques": ["T1498"],
        "signatures": [r"http/2", r"rapid reset", r"CVE-2023-44487"],
        "remediation": [
            "Apply vendor patches limiting concurrent HTTP/2 streams and reset handling.",
            "Configure rate limits and connection reset caps on load balancers.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2023-27350",
        "title": "PaperCut MF/NG RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Missing authentication check in PaperCut print management allows unauthenticated RCE via SetupCompleted bypass.",
        "affected": "PaperCut MF/NG < 20.1.7, < 21.2.11, < 22.0.9",
        "techniques": ["T1190"],
        "signatures": [r"papercut", r"CVE-2023-27350", r"SetupCompleted"],
        "remediation": [
            "Upgrade PaperCut to patched versions.",
            "Restrict the PaperCut web UI (port 9191) to admin networks.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2023-23397",
        "title": "Microsoft Outlook Elevation of Privilege (NTLM leak)",
        "cvss": 9.8, "severity": "critical",
        "description": "Outlook EoP via crafted meeting invitation with UNC path triggers NTLM credential leak to attacker-controlled server (zero-click).",
        "affected": "Microsoft Outlook 2016/2019/2021, M365 (pre-patch)",
        "techniques": ["T1557", "T1003"],
        "signatures": [r"CVE-2023-23397", r"outlook.*ntlm", r"appointment.*unc"],
        "remediation": [
            "Apply March 2023 patches.",
            "Add firewall rules blocking TCP 445/139 outbound to internal/external hosts.",
            "Enable Extended Protection for Authentication.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2024-3400",
        "title": "Palo Alto GlobalProtect Command Injection",
        "cvss": 10.0, "severity": "critical",
        "description": "Unauthenticated command injection in PAN-OS GlobalProtect portal/gateway on firewall interfaces with device telemetry enabled.",
        "affected": "PAN-OS 10.2 < 10.2.9-h1, 11.0 < 11.0.4-h1, 11.1 < 11.1.2-h3",
        "techniques": ["T1190"],
        "signatures": [r"globalprotect", r"CVE-2024-3400", r"pan-os"],
        "remediation": [
            "Upgrade PAN-OS to patched hotfixes.",
            "If unpatched, disable device telemetry (mitigation per vendor).",
            "Monitor GlobalProtect logs for suspicious commands.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2024-3094",
        "title": "xz Utils Backdoor (liblzma sshd RCE)",
        "cvss": 10.0, "severity": "critical",
        "description": "Backdoor in xz-utils 5.6.0/5.6.1 liblzma compromising sshd via LD_PRELOAD-style interposition — remote auth bypass/RCE on vulnerable distros.",
        "affected": "xz 5.6.0-5.6.1 (Fedora 40, Kali, Arch, openSUSE Tumbleweed, Debian sid)",
        "techniques": ["T1190", "T1554"],
        "signatures": [r"xz.*backdoor", r"CVE-2024-3094", r"liblzma"],
        "remediation": [
            "Downgrade xz to 5.4.x and update liblzma immediately.",
            "Rotate SSH host keys and credentials on affected hosts.",
            "Verify SSH binaries for tampering (rpm -V / dpkg -V).",
        ],
        "commands": [
            "sudo apt install xz-utils=5.4.* 2>/dev/null; sudo systemctl restart ssh",
        ],
    },
    {
        "id": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write",
        "cvss": 9.6, "severity": "critical",
        "description": "Unauthenticated out-of-bounds write in FortiOS SSL-VPN allows RCE on FortiGate devices.",
        "affected": "FortiOS 7.4.0-7.4.1, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.x, 6.2.x, 6.0.x",
        "techniques": ["T1190"],
        "signatures": [r"fortios", r"fortigate", r"CVE-2024-21762", r"ssl-vpn"],
        "remediation": [
            "Upgrade FortiOS to patched releases immediately.",
            "Restrict SSL-VPN to known user groups + enforce MFA.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion RCE (signal handler race)",
        "cvss": 8.1, "severity": "high",
        "description": "Signal handler race in OpenSSH sshd (Portable 8.5p1-9.7p1) on 32-bit glibc allows remote unauthenticated RCE with many attempts.",
        "affected": "OpenSSH 8.5p1 through 9.7p1 (portable) on glibc 32-bit",
        "techniques": ["T1190", "T1210"],
        "signatures": [r"regresshion", r"CVE-2024-6387", r"openssh.*9\.[0-7]"],
        "remediation": [
            "Upgrade OpenSSH to 9.8p1+.",
            "Enable sshd LoginGraceTime=0 workaround if unpatched (high DoS risk tradeoff).",
            "Limit SSH exposure; enforce key-based auth + MFA.",
        ],
        "commands": ["sudo apt install --only-upgrade openssh-server"],
    },
    {
        "id": "CVE-2023-34362",
        "title": "MOVEit Transfer SQLi → RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "SQL injection in MOVEit Transfer web UI allows unauth RCE and data theft (widely exploited in 2023).",
        "affected": "MOVEit Transfer 2021.0-2023.0 (pre-15.0.7/16.0.3/15.1.5/15.1.6 patches)",
        "techniques": ["T1190", "T1190"],
        "signatures": [r"moveit", r"CVE-2023-34362", r"moveittransfer"],
        "remediation": [
            "Upgrade MOVEit to patched builds.",
            "Audit for webshells/backdoors and suspicious account creation post-compromise.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-26084",
        "title": "Confluence Server OGNL Injection (RCE)",
        "cvss": 9.8, "severity": "critical",
        "description": "OGNL injection in Confluence Server/Data Center allows unauthenticated RCE via crafted URI.",
        "affected": "Confluence < 7.4.10, 7.11.6, 7.12.5, 7.13.0",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"confluence", r"CVE-2021-26084", r"ognl"],
        "remediation": [
            "Upgrade Confluence to patched versions.",
            "WAF block OGNL payload patterns.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2022-30190",
        "title": "Microsoft Support Diagnostic Tool RCE (Follina)",
        "cvss": 7.8, "severity": "high",
        "description": "MSDT RCE via crafted Office document with remote OLE/HTML — executes via ms-msdt protocol handler with no macros.",
        "affected": "Windows 7+, Office 2013+ (pre-June-2022 patch)",
        "techniques": ["T1204", "T1059"],
        "signatures": [r"follina", r"CVE-2022-30190", r"ms-msdt"],
        "remediation": [
            "Apply June 2022 patches (KB5014697+).",
            "Registry: disable ms-msdt via HKCU\\Software\\Classes\\ms-msdt.",
            "Block Office apps from spawning msdt.exe in EDR.",
        ],
        "commands": [
            "reg add HKCU\\Software\\Classes\\ms-msdt /v Enabled /t REG_DWORD /d 0 /f",
        ],
    },
    {
        "id": "CVE-2021-40444",
        "title": "Microsoft MSHTML RCE (Office/IE)",
        "cvss": 7.8, "severity": "high",
        "description": "MSHTML engine RCE via crafted Office doc embedding ActiveX control loading a remote malicious CAB/SWF — no macros required.",
        "affected": "Windows Server 2008+, Office 2013+, IE 9-11",
        "techniques": ["T1204", "T1218"],
        "signatures": [r"CVE-2021-40444", r"mshtml", r"activex.*cab"],
        "remediation": [
            "Apply September 2021 patches.",
            "Block ActiveX in Office; restrict internet zone controls.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2023-49103",
        "title": "ownCloud graphapi info disclosure (admin creds)",
        "cvss": 10.0, "severity": "critical",
        "description": "ownCloud graphapi app leaks PHP environment incl. admin credentials via public URL (phpinfo in appdata).",
        "affected": "ownCloud graphapi 0.2.0-0.3.0",
        "techniques": ["T1552"],
        "signatures": [r"owncloud", r"CVE-2023-49103", r"graphapi"],
        "remediation": [
            "Delete apps/graphapi and rotate owncloud admin credentials.",
            "Restrict appdata access.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-4034",
        "title": "polkit pkexec LPE (PwnKit)",
        "cvss": 7.8, "severity": "high",
        "description": "Out-of-bounds write in pkexec allows any local user to gain root (default polkit on most Linux distros).",
        "affected": "polkit pkexec (all versions pre-Jan-2022 patch)",
        "techniques": ["T1068"],
        "signatures": [r"pwnkit", r"CVE-2021-4034", r"pkexec"],
        "remediation": [
            "Update polkit (apt/yum upgrade policykit-1).",
            "If unpatched, remove pkexec SUID bit: chmod 0755 /usr/bin/pkexec.",
        ],
        "commands": [
            "sudo chmod 0755 /usr/bin/pkexec",
            "sudo apt install --only-upgrade policykit-1",
        ],
    },
    {
        "id": "CVE-2018-15473",
        "title": "OpenSSH Username Enumeration",
        "cvss": 5.3, "severity": "medium",
        "description": "Timing/response differences in OpenSSH <7.7 allow user enumeration via malformed authentication requests.",
        "affected": "OpenSSH < 7.7",
        "techniques": ["T1589", "T1110"],
        "signatures": [r"CVE-2018-15473", r"username enumeration"],
        "remediation": [
            "Upgrade OpenSSH to 7.7+.",
            "Use fail2ban / rate limiting to blunt enumeration + brute force.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2019-19781",
        "title": "Citrix ADC/NetScaler Directory Traversal → RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Directory traversal in Citrix ADC/NetScaler VPN allows unauthenticated file read + RCE via templates path.",
        "affected": "Citrix ADC/NetScaler 10.5-13.0 (pre-fix)",
        "techniques": ["T1190"],
        "signatures": [r"citrix", r"netscaler", r"CVE-2019-19781"],
        "remediation": [
            "Apply Citrix hotfixes for ADC/NetScaler.",
            "Restrict management interface; monitor for /vpn/../ template exploitation.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2022-26134",
        "title": "Atlassian Confluence OGNL RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Unauthenticated OGNL injection in Confluence Server/Data Center (all versions) — in-the-wild exploitation.",
        "affected": "Confluence Server/Data Center (all versions pre-patch)",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"confluence", r"CVE-2022-26134", r"ognl"],
        "remediation": [
            "Upgrade Confluence to patched builds immediately.",
            "WAF block OGNL payloads; audit webshells.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2024-21716",
        "title": "Microsoft Word RTF RCE (Font Table)",
        "cvss": 8.8, "severity": "high",
        "description": "Heap overflow in Word RTF font table parsing allows RCE via malicious .rtf (preview pane triggers).",
        "affected": "Microsoft Office 2016/2019/2021, M365 (pre-patch)",
        "techniques": ["T1204"],
        "signatures": [r"CVE-2024-21716", r"rtf.*font"],
        "remediation": [
            "Apply February 2024 patches.",
            "Disable RTF rendering where possible (Follina-style hardening).",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2023-36845",
        "title": "Juniper Junos PHP Environment Variable Injection",
        "cvss": 10.0, "severity": "critical",
        "description": "Junos OS EX/SRX/MX PHP injection via crafted request enables unauth RCE (widely exploited 2023).",
        "affected": "Junos OS 20.4R3-S6-, 21.x, 22.x (pre-patch)",
        "techniques": ["T1190"],
        "signatures": [r"juniper", r"junos", r"CVE-2023-36845", r"php.*env"],
        "remediation": [
            "Upgrade Junos OS to patched versions.",
            "Audit for backdoor accounts/files on affected devices.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2022-22954",
        "title": "VMware Workspace ONE Access SSTI RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Server-side template injection in VMware Workspace ONE Access/Identity Manager allows unauth RCE.",
        "affected": "VMware Workspace ONE Access 21.08/21.08.0.1, Identity Manager 3.3.x",
        "techniques": ["T1190", "T1059"],
        "signatures": [r"workspace one", r"CVE-2022-22954", r"ssti"],
        "remediation": [
            "Apply VMware patches.",
            "Restrict UI access; monitor for SSTI payloads.",
        ],
        "commands": [],
    },
    {
        "id": "CVE-2021-22986",
        "title": "F5 BIG-IP iControl REST Auth Bypass RCE",
        "cvss": 9.8, "severity": "critical",
        "description": "Unauthenticated iControl REST authentication bypass allows RCE on BIG-IP (CVE-2021-22986).",
        "affected": "F5 BIG-IP 11.6.1-16.0.1 (pre-patch)",
        "techniques": ["T1190"],
        "signatures": [r"big-ip", r"CVE-2021-22986", r"icontrol"],
        "remediation": [
            "Upgrade BIG-IP to patched releases.",
            "Restrict iControl REST access; monitor mgmt plane.",
        ],
        "commands": [],
    },
]


# ═══════════════════════════════════════════════════════════════════
# EXPLOIT SIGNATURE INDEX — compiled once at import
# (regex -> list of CVE ids that reference it)
# ═══════════════════════════════════════════════════════════════════
def _build_signature_index() -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = {}
    for cve in CVE_DATABASE:
        for sig in cve.get("signatures", []):
            try:
                re.compile(sig, re.IGNORECASE)
            except re.error:
                logger.warning(f"Invalid signature regex in {cve['id']}: {sig!r}")
                continue
            index.setdefault(sig, []).append(cve["id"])
    return index


SIGNATURE_INDEX: Dict[str, List[str]] = _build_signature_index()
SIGNATURE_PATTERNS: List[Tuple[re.Pattern, List[str]]] = [
    (re.compile(sig, re.IGNORECASE), ids) for sig, ids in SIGNATURE_INDEX.items()
]


class KnowledgeBase:
    """
    Offline cybersecurity knowledge base with fast retrieval.

    - Exact lookup: lookup_cve / lookup_technique (O(1) dict).
    - Similarity search: TF-IDF cosine (mirrors VectorMemory) when
      scikit-learn is available; keyword fallback otherwise.
    - Signature grounding: signature_match() maps raw tool output / banners
      to CVEs via compiled regexes.
    - ground_findings(): attaches cves/techniques/remediation to findings so
      the LLM can ground exploit suggestions and remediation steps.
    - get_context_block(): sanitized, LLM-ready text block.

    NOTE: _load_external() only runs at init time (external data_path is
    merged once). A future runtime reload must re-run _build_index() and
    refresh the _external_loaded/_external_error flags under self._lock.
    """

    def __init__(self, data_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._cves: Dict[str, Dict[str, Any]] = {c["id"]: dict(c)
                                                 for c in CVE_DATABASE}
        self._techniques: Dict[str, Dict[str, str]] = {
            tid: dict(t) for tid, t in ATTACK_TECHNIQUES.items()}
        self._vectorizer = None
        self._vectors = None
        self._corpus_keys: List[str] = []  # parallel to vector rows
        self._corpus_meta: Dict[str, Dict[str, Any]] = {}  # key -> {type,id}
        self._external_loaded = False
        self._external_error: Optional[str] = None
        # Optional external JSON extension (user-curated, air-gapped):
        # {"cves": [...], "techniques": {...}} merged over embedded data.
        if data_path and os.path.isfile(data_path):
            self._load_external(data_path)
        self._build_index()  # ALWAYS build — even if the external load failed
        if not self._external_loaded:
            self._external_error = (self._external_error or
                                    ("data_path not found: " + data_path
                                     if data_path else "no data_path configured"))

    # ── Indexing ──
    def _load_external(self, data_path: str) -> None:
        try:
            with open(data_path) as f:
                data = json.load(f)
            with self._lock:  # guard index-writer state against readers
                for cve in data.get("cves", []) or []:
                    if cve.get("id"):
                        self._cves[cve["id"]] = cve
                for tid, meta in (data.get("techniques", {}) or {}).items():
                    if isinstance(meta, dict):
                        self._techniques[tid] = meta
            self._external_loaded = True
            self._external_error = None
            logger.info(f"KnowledgeBase extended from {data_path}: "
                        f"{len(data.get('cves', []))} cves, "
                        f"{len(data.get('techniques', {}))} techniques")
        except Exception as e:
            self._external_loaded = False
            self._external_error = str(e)
            logger.error(f"Failed to load knowledge base extension {data_path}: {e}")

    def _build_index(self) -> None:
        """Build the TF-IDF retrieval index over CVE + technique text.
        Entire rebuild runs under the lock so readers never observe a
        half-populated index (corpus_meta/vectors updated atomically).
        """
        with self._lock:
            self._corpus_keys = []
            self._corpus_meta = {}
            texts = []
            for cve_id, cve in self._cves.items():
                text = " ".join([
                    cve_id, cve.get("title", ""), cve.get("description", ""),
                    cve.get("affected", ""), " ".join(cve.get("signatures", [])),
                ])
                key = f"cve:{cve_id}"
                texts.append(text)
                self._corpus_keys.append(key)
                self._corpus_meta[key] = {"type": "cve", "id": cve_id}
            for tid, tech in self._techniques.items():
                text = " ".join([
                    tid, tech.get("name", ""), tech.get("tactic", ""),
                    tech.get("detection", ""), tech.get("mitigation", ""),
                ])
                key = f"tech:{tid}"
                texts.append(text)
                self._corpus_keys.append(key)
                self._corpus_meta[key] = {"type": "technique", "id": tid}
            if _HAS_SKLEARN and texts:
                try:
                    self._vectorizer = TfidfVectorizer(
                        lowercase=True, stop_words="english", max_features=5000,
                        ngram_range=(1, 2))
                    self._vectors = self._vectorizer.fit_transform(texts)
                except Exception as e:
                    logger.warning(f"TF-IDF index build failed (keyword fallback): {e}")
                    self._vectorizer = None
                    self._vectors = None
            else:
                self._vectorizer = None
                self._vectors = None

    # ── Lookups ──
    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Exact CVE lookup by ID (case-insensitive)."""
        if not cve_id:
            return None
        cve_id = cve_id.strip().upper()
        cve = self._cves.get(cve_id)
        if not cve:
            # Try alternate formats (CVE-2017-0144 vs 2017-0144)
            for cid, c in self._cves.items():
                if cid.endswith(cve_id) or cve_id.endswith(cid):
                    return dict(c)
            return None
        return dict(cve)

    def lookup_technique(self, tech_id: str) -> Optional[Dict[str, str]]:
        """Exact ATT&CK technique lookup by ID (e.g. T1190)."""
        if not tech_id:
            return None
        tech_id = tech_id.strip().upper()
        tech = self._techniques.get(tech_id)
        return dict(tech) if tech else None

    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    _TECH_RE = re.compile(r"T\d{4}(\.\d{3})?", re.I)

    def search(self, query: str, top_k: int = 5,
               category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Semantic search over CVEs + techniques. Returns entries ranked by
        similarity: [{type, id, title, score, ...}]. Falls back to keyword
        scoring when scikit-learn is unavailable.

        Exact CVE/ATT&CK identifiers embedded in the query are boosted to the
        top of the ranking (an exact ID is always the right answer).
        """
        query = (query or "").strip()
        if not query:
            return []
        top_k = max(1, min(int(top_k), 25))
        results = []
        # Exact-ID boost: "CVE-2021-44228" / "T1059.001" in the query must
        # surface the exact record first, regardless of TF-IDF noise.
        exact_seen = set()
        for m in self._CVE_RE.findall(query):
            entry = self._entry_dict("cve", m.upper())
            if entry and (not category or category == "cve") and entry["id"] not in exact_seen:
                entry["score"] = 1.0
                exact_seen.add(entry["id"])
                results.append(entry)
        for m in self._TECH_RE.findall(query):
            entry = self._entry_dict("technique", m.upper())
            if entry and (not category or category == "technique") and entry["id"] not in exact_seen:
                entry["score"] = 1.0
                exact_seen.add(entry["id"])
                results.append(entry)
        if _HAS_SKLEARN and self._vectorizer is not None and self._vectors is not None:
            try:
                qvec = self._vectorizer.transform([query])
                sims = cosine_similarity(qvec, self._vectors).flatten()
                order = sims.argsort()[::-1]
                for i in order:
                    if sims[i] < SIMILARITY_THRESHOLD:
                        break
                    key = self._corpus_keys[i]
                    meta = self._corpus_meta[key]
                    if category and meta["type"] != category:
                        continue
                    entry = self._entry_dict(meta["type"], meta["id"])
                    if not entry or entry["id"] in exact_seen:
                        continue
                    entry["score"] = round(float(sims[i]), 4)
                    results.append(entry)
                    if len(results) >= top_k:
                        break
            except Exception as e:
                logger.warning(f"KB similarity search failed: {e}")
        if not results:
            results = self._keyword_search(query, top_k, category)
        return results[:top_k]

    def _keyword_search(self, query: str, top_k: int,
                        category: Optional[str]) -> List[Dict[str, Any]]:
        """Simple token-overlap keyword scoring fallback (offline, no deps)."""
        q_tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        if not q_tokens:
            return []
        scored = []
        for key, meta in self._corpus_meta.items():
            if category and meta["type"] != category:
                continue
            entry = self._entry_dict(meta["type"], meta["id"])
            if not entry:
                continue
            hay = " ".join([
                entry.get("title", ""), entry.get("description", ""),
                entry.get("affected", ""),
                " ".join(str(s) for s in entry.get("signatures", [])),
            ]).lower()
            hits = sum(1 for t in q_tokens if t in hay)
            if hits:
                scored.append((hits / max(1, len(q_tokens)), entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for s, e in scored[:top_k]]

    def _entry_dict(self, etype: str, eid: str) -> Optional[Dict[str, Any]]:
        if etype == "cve":
            cve = self.lookup_cve(eid)
            if cve:
                return {"type": "cve", "id": cve["id"], "title": cve["title"],
                        "cvss": cve.get("cvss", 0), "severity": cve.get("severity", ""),
                        "description": cve.get("description", ""),
                        "affected": cve.get("affected", ""),
                        "techniques": cve.get("techniques", []),
                        "signatures": cve.get("signatures", []),
                        "remediation": cve.get("remediation", []),
                        "commands": cve.get("commands", [])}
        tech = self.lookup_technique(eid)
        if tech:
            return {"type": "technique", "id": eid, "title": tech.get("name", ""),
                    "tactic": tech.get("tactic", ""),
                    "detection": tech.get("detection", ""),
                    "mitigation": tech.get("mitigation", "")}
        return None

    # ── Signature grounding ──
    def signature_match(self, text: str,
                        top_k: int = 8) -> List[Dict[str, Any]]:
        """
        Scan raw tool output / banners / finding evidence for known exploit
        signatures and return matching CVEs (severity-sorted).
        """
        if not text:
            return []
        matches = []
        for pattern, cve_ids in SIGNATURE_PATTERNS:
            if pattern.search(str(text)):
                for cve_id in cve_ids:
                    cve = self.lookup_cve(cve_id)
                    if cve and cve not in matches:
                        matches.append(cve)
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        matches.sort(key=lambda c: sev.get(c.get("severity", "info"), 9))
        return matches[:top_k]

    # ── Finding grounding ──
    def ground_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Attach knowledge-base context to each finding:
          - kb_cves: matched CVEs (via signature_match on title/evidence)
          - kb_techniques: ATT&CK techniques referenced by the finding or
            its matched CVEs
          - kb_remediation: deduped remediation steps + commands
        Returns a NEW list; input findings are not mutated.
        """
        grounded = []
        for f in findings or []:
            f2 = dict(f)
            blob = " ".join(str(f2.get(k, "")) for k in
                            ("title", "description", "evidence", "raw_output",
                             "stdout_preview"))
            cves = self.signature_match(blob, top_k=5)
            f2["kb_cves"] = [{"id": c["id"], "title": c["title"],
                              "severity": c.get("severity", ""),
                              "cvss": c.get("cvss", 0)} for c in cves]
            # Techniques: from finding + matched CVEs
            tech_ids = set()
            for t in (f2.get("attack_techniques") or []):
                if isinstance(t, dict) and t.get("id"):
                    tech_ids.add(t["id"])
            for c in cves:
                tech_ids.update(c.get("techniques", []))
            f2["kb_techniques"] = [
                {"id": tid, "name": self._techniques.get(tid, {}).get("name", ""),
                 "tactic": self._techniques.get(tid, {}).get("tactic", "")}
                for tid in sorted(tech_ids)]
            # Remediation (deduped)
            seen = set()
            remediation, commands = [], []
            for c in cves:
                for step in c.get("remediation", []):
                    if step not in seen:
                        seen.add(step)
                        remediation.append(step)
                for cmd in c.get("commands", []):
                    if cmd not in commands:
                        commands.append(cmd)
            f2["kb_remediation"] = {"steps": remediation, "commands": commands}
            f2["kb_grounded"] = bool(cves or tech_ids)
            grounded.append(f2)
        return grounded

    def remediation_for(self, cve_id: str) -> Dict[str, Any]:
        """Full remediation playbook for a CVE: steps + commands + severity."""
        cve = self.lookup_cve(cve_id)
        if not cve:
            return {"cve_id": cve_id, "found": False, "steps": [], "commands": []}
        return {"cve_id": cve["id"], "title": cve["title"], "found": True,
                "severity": cve.get("severity", ""), "cvss": cve.get("cvss", 0),
                "steps": cve.get("remediation", []),
                "commands": cve.get("commands", []),
                "techniques": cve.get("techniques", [])}

    # ── LLM context ──
    def get_context_block(self, query: str = "", findings: Optional[List[dict]] = None,
                          max_chars: int = CONTEXT_MAX_CHARS,
                          max_entries: int = CONTEXT_MAX_ENTRIES) -> str:
        """
        Build a sanitized, LLM-ready grounding block. Pulls the most relevant
        CVE + technique entries for the query/findings and renders them as a
        compact knowledge block. All content is passed through
        sanitize_for_llm (defense-in-depth against injection via findings).
        """
        parts = []
        # 1. Signature-grounded CVEs from findings
        cve_ids = set()
        for f in (findings or []):
            blob = " ".join(str(f.get(k, "")) for k in
                            ("title", "description", "evidence", "raw_output"))
            for c in self.signature_match(blob, top_k=3):
                cve_ids.add(c["id"])
        # 2. Semantic matches for the query
        if query:
            for e in self.search(query, top_k=max_entries, category="cve"):
                cve_ids.add(e["id"])
        for cve_id in sorted(cve_ids):
            cve = self.lookup_cve(cve_id)
            if not cve:
                continue
            parts.append(
                f"[CVE] {cve['id']} ({cve.get('severity', '').upper()}, "
                f"CVSS {cve.get('cvss', 0)}): {cve.get('title', '')} — "
                f"{cve.get('description', '')[:200]} "
                f"Remediation: {'; '.join(cve.get('remediation', [])[:3])}")
            if len(parts) >= max_entries:
                break
        # 3. Techniques (from matched CVEs + explicit finding techniques)
        tech_ids = set()
        for cve_id in list(cve_ids):
            cve = self.lookup_cve(cve_id)
            if cve:
                tech_ids.update(cve.get("techniques", []))
        for f in (findings or []):
            for t in (f.get("attack_techniques") or []):
                if isinstance(t, dict) and t.get("id"):
                    tech_ids.add(t["id"])
        for tid in sorted(tech_ids):
            tech = self.lookup_technique(tid)
            if tech:
                parts.append(
                    f"[ATT&CK] {tid} {tech.get('name', '')} "
                    f"({tech.get('tactic', '')}) — detection: "
                    f"{tech.get('detection', '')[:160]} | mitigation: "
                    f"{tech.get('mitigation', '')[:160]}")
        if not parts:
            return ""
        block = "\n".join(parts)
        if len(block) > max_chars:
            block = block[:max_chars] + "\n…(truncated)"
        return sanitize_for_llm(block, max_len=len(block) + 8)

    # ── Stats ──
    def get_stats(self) -> Dict[str, Any]:
        """Knowledge base statistics for the dashboard / status endpoint."""
        return {
            "cves": len(self._cves),
            "techniques": len(self._techniques),
            "signatures": len(SIGNATURE_INDEX),
            "index_ready": self._vectorizer is not None,
            "corpus_entries": len(self._corpus_keys),
            "severity_counts": self._severity_counts(),
            "external_loaded": self._external_loaded,
            "external_error": self._external_error,
        }

    def _severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for cve in self._cves.values():
            sev = (cve.get("severity") or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
