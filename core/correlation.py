"""
RedTeam Harness — Finding Correlation & Auto-Remediation (v5.0)
Links auto-extracted findings into coherent attack paths, scores them using
kill-chain progression, maps to MITRE ATT&CK techniques, and generates
concrete remediation steps.

v5.0 enhancements over v4.0:
  - Multi-step kill chain detection (recon → vuln → exploit → postex chains)
  - MITRE ATT&CK technique mapping (T-numbers) for each finding/path
  - Confidence scoring based on evidence strength and chain completeness
  - Cross-workflow correlation (link findings across different workflows)
  - 20+ new correlation rules for modern attack vectors
  - Attack path graph data structure for dashboard visualization
  - Kill chain progression scoring (how far along the kill chain)
  - Cross-session correlation via vector memory integration
  - Severity boosting based on chain depth and exploitability
"""
import re
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger("redteam.correlation")

# ── Severity weights ──
SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# ── Kill chain phases (simplified MITRE-inspired) ──
KILL_CHAIN_PHASES = {
    "recon":          0,
    "weaponization":  1,
    "delivery":       2,
    "exploitation":   3,
    "installation":   4,
    "command_control": 5,
    "actions_objectives": 6,
}

# ── MITRE ATT&CK technique mappings ──
ATTACK_TECHNIQUES = {
    # Reconnaissance
    "port_scan":          {"id": "T1046", "name": "Network Service Discovery"},
    "dns_enum":           {"id": "T1596", "name": "Search Open Technical Databases"},
    "subdomain_enum":     {"id": "T1596.001", "name": "DNS/Passive DNS"},
    "osint":              {"id": "T1593", "name": "Search Open Websites/Domains"},
    "email_harvest":      {"id": "T1589", "name": "Gather Victim Identity Information"},
    # Initial Access
    "sql_injection":      {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "xss":                {"id": "T1189", "name": "Drive-by Compromise"},
    "ssrf":               {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "auth_bypass":        {"id": "T1133", "name": "External Remote Services"},
    "file_upload":        {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "xxe":                {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "deserialization":    {"id": "T1190", "name": "Exploit Public-Facing Application"},
    # Execution
    "command_injection":  {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "code_execution":     {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "powershell":         {"id": "T1059.001", "name": "PowerShell"},
    "python_script":      {"id": "T1059.006", "name": "Python"},
    # Persistence
    "scheduled_task":     {"id": "T1053", "name": "Scheduled Task/Job"},
    "registry_mod":       {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
    "web_shell":          {"id": "T1505.003", "name": "Web Shell"},
    # Privilege Escalation
    "kernel_exploit":     {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "suid_abuse":         {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
    "sudo_abuse":         {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "token_manipulation": {"id": "T1134", "name": "Access Token Manipulation"},
    # Defense Evasion
    "process_injection":  {"id": "T1055", "name": "Process Injection"},
    "obfuscation":        {"id": "T1027", "name": "Obfuscated Files or Information"},
    # Credential Access
    "kerberoasting":      {"id": "T1558.003", "name": "Kerberoasting"},
    "asrep_roasting":     {"id": "T1558.004", "name": "AS-REP Roasting"},
    "dcsync":             {"id": "T1003.006", "name": "DCSync"},
    "mimikatz":           {"id": "T1003.001", "name": "LSASS Memory (Mimikatz)"},
    "password_spray":     {"id": "T1110.003", "name": "Password Spraying"},
    "brute_force":        {"id": "T1110", "name": "Brute Force"},
    "credential_dump":    {"id": "T1003", "name": "OS Credential Dumping"},
    # Lateral Movement
    "pass_the_hash":      {"id": "T1550.002", "name": "Pass the Hash"},
    "pass_the_ticket":    {"id": "T1550.003", "name": "Pass the Ticket"},
    "rdp_lateral":        {"id": "T1021.001", "name": "Remote Desktop Protocol"},
    "smb_lateral":        {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
    "ssh_lateral":        {"id": "T1021.004", "name": "SSH"},
    "wmi_exec":           {"id": "T1047", "name": "Windows Management Instrumentation"},
    # Collection / Exfiltration
    "data_exfil":         {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
    "sensitive_file":     {"id": "T1005", "name": "Data from Local System"},
    # Cloud
    "imds_abuse":         {"id": "T1552.005", "name": "Cloud Instance Metadata API"},
    "iam_esc":            {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
    # Container / K8s
    "container_escape":   {"id": "T1611", "name": "Escape to Host"},
    "k8s_rbac_abuse":     {"id": "T1610", "name": "Deploy Container"},
    "docker_socket":      {"id": "T1611", "name": "Escape to Host"},
}

# ── Correlation rule table ──
# Each rule: trigger keywords, companion keywords, path title, severity,
# kill chain phases involved, MITRE ATT&CK techniques, remediation steps.
CORRELATION_RULES = [
    {
        "id": "smb_compromise",
        "path_title": "SMB / EternalBlue Lateral Movement Path",
        "trigger": ["eternalblue", "ms17-010", "smbv1", "ms17-010-vuln"],
        "companions": ["445/tcp", "anonymous login", "no password", "smb", "netexec", "crackmapexec"],
        "severity": "critical",
        "kill_chain": ["recon", "exploitation", "actions_objectives"],
        "attack_techniques": ["T1210", "T1021.002", "T1550.002"],
        "remediation": [
            "Apply MS17-010 security patch to all Windows hosts",
            "Disable SMBv1 across the domain (registry + GPO)",
            "Restrict SMB traffic (445) at the host firewall / network segmentation",
            "Monitor for suspicious SMB sessions and pass-the-hash activity",
        ],
    },
    {
        "id": "cred_exfil",
        "path_title": "Credential Exfiltration Path (DB → hashes)",
        "trigger": ["sql injection", "is vulnerable", "sqlmap", "union select", "error in your sql"],
        "companions": ["hash", "password", "dump", "credential", "data"],
        "severity": "critical",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190", "T1005", "T1041"],
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
        "trigger": ["kerberos", "krb5tgs", "krb5asrep", "dcsync", "nt hash", "secretsdump", "kerberoast", "asrep"],
        "companions": ["password", "hash", "domain", "ticket", "service account"],
        "severity": "critical",
        "kill_chain": ["exploitation", "installation", "actions_objectives"],
        "attack_techniques": ["T1558.003", "T1558.004", "T1003.006"],
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
        "trigger": ["docker", "/containers/json", "2375/tcp", "privileged", "docker.sock", "container escape"],
        "companions": ["mount", "/etc/", "hostconfig", "hostpid", "hostnetwork", "pid namespace"],
        "severity": "critical",
        "kill_chain": ["exploitation", "installation", "actions_objectives"],
        "attack_techniques": ["T1611", "T1609"],
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
                    "/admin/", "/console", "phpinfo", "backup", "wp-config"],
        "companions": ["200", "version", "server:", "stack trace", "error"],
        "severity": "medium",
        "kill_chain": ["recon", "weaponization"],
        "attack_techniques": ["T1592", "T1593"],
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
        "companions": ["open", "version", "exploit", "vulnerable", "patch"],
        "severity": "high",
        "kill_chain": ["recon", "exploitation"],
        "attack_techniques": ["T1190", "T1203"],
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
                    "accountkey", "clientsecret", "imds", "ssrf"],
        "companions": ["iam", "token", "credential", "role", "sts"],
        "severity": "critical",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1552.005", "T1078.004"],
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
        "trigger": ["wpa", "handshake", "key found", "psk", "aircrack"],
        "companions": ["deauth", "bssid", "eapol", "four-way"],
        "severity": "high",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1557", "T1040"],
        "remediation": [
            "Replace WPA2-PSK with WPA2/WPA3-Enterprise (802.1X)",
            "Enforce a strong PSK policy (16+ random chars) for legacy networks",
            "Deploy Rogue AP detection / wireless intrusion prevention",
        ],
    },
    # ── NEW v5.0 RULES ──
    {
        "id": "oauth_token_abuse",
        "path_title": "OAuth / JWT Token Abuse Path",
        "trigger": ["oauth", "jwt", "bearer", "access_token", "refresh_token", "openid"],
        "companions": ["expired", "invalid", "scope", "redirect", "client_secret"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1550", "T1078"],
        "remediation": [
            "Validate JWT signatures and expiration on every request",
            "Implement token revocation and short-lived access tokens",
            "Enforce OAuth redirect URI whitelisting",
            "Rotate client secrets and use PKCE for public clients",
        ],
    },
    {
        "id": "api_abuse",
        "path_title": "API Security Abuse Path (BOLA/IDOR)",
        "trigger": ["idor", "bola", "object-level authorization", "mass assignment",
                    "api key", "rate limit", "graphql"],
        "companions": ["200", "unauthorized", "forbidden", "admin", "role"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190", "T1133"],
        "remediation": [
            "Implement object-level authorization checks on all API endpoints",
            "Enforce rate limiting and request throttling",
            "Use allow-lists for mass assignment fields",
            "Enable GraphQL introspection only in development",
        ],
    },
    {
        "id": "k8s_rbac_abuse",
        "path_title": "Kubernetes RBAC Escalation Path",
        "trigger": ["kubernetes", "kubectl", "kubelet", "etcd", "6443/tcp", "rbac", "clusterrole"],
        "companions": ["token", "secret", "serviceaccount", "pod", "exec"],
        "severity": "critical",
        "kill_chain": ["exploitation", "installation", "actions_objectives"],
        "attack_techniques": ["T1610", "T1609", "T1059"],
        "remediation": [
            "Restrict RBAC ClusterRole/ClusterRoleBinding to minimum required",
            "Disable anonymous authentication on kube-apiserver",
            "Enable audit logging and monitor API server access",
            "Use Pod Security Standards (PSS) to restrict pod capabilities",
        ],
    },
    {
        "id": "cloud_iam_esc",
        "path_title": "Cloud IAM Privilege Escalation Path",
        "trigger": ["iam:passrole", "sts:assumerole", "iam:createloginprofile",
                    "iam:attachuserpolicy", "iam:attachrolepolicy", "cloudadmin"],
        "companions": ["policy", "role", "admin", "root", "account"],
        "severity": "critical",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1078.004", "T1098"],
        "remediation": [
            "Audit IAM policies for privilege escalation paths",
            "Enforce least-privilege IAM policies with condition keys",
            "Enable CloudTrail and monitor for suspicious IAM API calls",
            "Use AWS SCPs / Azure Policies to restrict dangerous actions",
        ],
    },
    {
        "id": "supply_chain",
        "path_title": "Software Supply Chain Compromise Path",
        "trigger": ["dependency", "package", "npm", "pypi", "malicious", "backdoor",
                    "typosquatting", "compromised"],
        "companions": ["version", "hash", "checksum", "registry", "install"],
        "severity": "critical",
        "kill_chain": ["delivery", "exploitation", "installation"],
        "attack_techniques": ["T1195.002", "T1195.001"],
        "remediation": [
            "Pin dependency versions and verify checksums (lock files)",
            "Use private registries with artifact signing (Sigstore/Cosign)",
            "Run SCA scans (Snyk, Trivy, Grype) in CI/CD pipelines",
            "Monitor for typosquatting and newly published malicious packages",
        ],
    },
    {
        "id": "ssrf_chain",
        "path_title": "SSRF → Internal Service Exploitation Chain",
        "trigger": ["ssrf", "server-side request", "internal", "127.0.0.1", "localhost"],
        "companions": ["metadata", "admin", "database", "redis", "elasticsearch", "vault"],
        "severity": "critical",
        "kill_chain": ["exploitation", "lateral_movement"],
        "attack_techniques": ["T1190", "T1005"],
        "remediation": [
            "Validate and sanitize all user-supplied URLs",
            "Use an allow-list for outbound requests from the application",
            "Block access to internal IP ranges (169.254.x.x, 10.x.x.x, 192.168.x.x)",
            "Deploy egress filtering at the network layer",
        ],
    },
    {
        "id": "nosql_injection",
        "path_title": "NoSQL Injection → Data Exfiltration Path",
        "trigger": ["nosql injection", "$ne", "$gt", "$regex", "$where", "mongodb injection"],
        "companions": ["dump", "data", "password", "credential", "user"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190", "T1005"],
        "remediation": [
            "Use ORM/ODM input validation and type checking",
            "Disable MongoDB JavaScript execution ($where)",
            "Implement field-level access control",
            "Enable audit logging for database queries",
        ],
    },
    {
        "id": "xxe_chain",
        "path_title": "XXE → File Read / SSRF Chain",
        "trigger": ["xxe", "external entity", "doctype.*entity", "xml parser", "xml injection"],
        "companions": ["file", "read", "internal", "/etc/passwd", "ssrf"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190", "T1005"],
        "remediation": [
            "Disable external entity processing in XML parsers",
            "Use JSON or non-XML data formats where possible",
            "Implement input validation for XML payloads",
            "Deploy WAF rules to block XXE patterns",
        ],
    },
    {
        "id": "graphql_abuse",
        "path_title": "GraphQL Introspection & Batch Attack Path",
        "trigger": ["__schema", "__type", "introspection", "queryDepth", "graphql"],
        "companions": ["error", "data", "extensions", "batch", "query"],
        "severity": "medium",
        "kill_chain": ["recon", "exploitation"],
        "attack_techniques": ["T1592", "T1190"],
        "remediation": [
            "Disable introspection in production environments",
            "Implement query depth limiting and query cost analysis",
            "Use persisted queries to prevent arbitrary query execution",
            "Enable query complexity throttling and rate limiting",
        ],
    },
    {
        "id": "deserialization_chain",
        "path_title": "Insecure Deserialization → RCE Path",
        "trigger": ["insecure deserialization", "pickle", "yaml.load", "unserialize",
                    "__reduce__", "objectinputstream", "marshalsec"],
        "companions": ["rce", "command", "exec", "eval", "system"],
        "severity": "critical",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1190", "T1059"],
        "remediation": [
            "Replace native deserialization with safe formats (JSON, MessagePack)",
            "Implement integrity checks (HMAC) on serialized data",
            "Use allow-lists for deserialized object types",
            "Run deserialization in sandboxed environments",
        ],
    },
    {
        "id": "request_smuggling",
        "path_title": "HTTP Request Smuggling → Cache Poisoning Path",
        "trigger": ["request smuggling", "cl.te", "te.cl", "transfer-encoding", "chunked"],
        "companions": ["cache", "poison", "hijack", "request", "response"],
        "severity": "high",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1190"],
        "remediation": [
            "Normalize HTTP requests at the reverse proxy boundary",
            "Reject requests with conflicting Transfer-Encoding headers",
            "Use HTTP/2 end-to-end to eliminate hop-by-hop ambiguities",
            "Keep backend and frontend servers in sync on HTTP parsing",
        ],
    },
    {
        "id": "race_condition",
        "path_title": "Race Condition → Privilege Escalation Path",
        "trigger": ["race condition", "time-of-check", "toc-tou", "concurrent", "double-spending"],
        "companions": ["admin", "root", "escalat", "balance", "payment"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190"],
        "remediation": [
            "Implement atomic operations and database-level locking",
            "Use optimistic concurrency control with version tokens",
            "Add server-side rate limiting for sensitive operations",
            "Design idempotent APIs for financial/state-changing actions",
        ],
    },
    {
        "id": "ldap_injection",
        "path_title": "LDAP Injection → Authentication Bypass Path",
        "trigger": ["ldap injection", "(cn=", "(uid=", "ldapresult", "ldap bind"],
        "companions": ["bypass", "authenticate", "admin", "password"],
        "severity": "high",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1190"],
        "remediation": [
            "Use parameterized LDAP queries with proper escaping",
            "Validate and sanitize all user input before LDAP operations",
            "Implement least-privilege service accounts for LDAP binds",
            "Enable LDAP query logging and anomaly detection",
        ],
    },
    {
        "id": "prototype_pollution",
        "path_title": "Prototype Pollution → RCE Path (Node.js)",
        "trigger": ["__proto__", "constructor[", "prototype pollution", "object.assign"],
        "companions": ["rce", "command", "eval", "process", "child_process"],
        "severity": "high",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1190", "T1059.007"],
        "remediation": [
            "Freeze Object.prototype in sensitive contexts",
            "Use Object.create(null) for dictionaries that hold user data",
            "Update dependencies with prototype pollution patches",
            "Implement input validation for deep-merge/merge operations",
        ],
    },
    {
        "id": "websocket_abuse",
        "path_title": "WebSocket Hijacking / Injection Path",
        "trigger": ["websocket", "ws://", "wss://", "cross-site websocket"],
        "companions": ["hijack", "inject", "xss", "_csrf", "origin"],
        "severity": "medium",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1189", "T1071"],
        "remediation": [
            "Validate Origin header on WebSocket upgrade requests",
            "Use wss:// (TLS) for all WebSocket connections",
            "Implement CSRF tokens for WebSocket authentication",
            "Rate-limit and validate all messages received over WebSocket",
        ],
    },
    {
        "id": "k8s_secret_theft",
        "path_title": "Kubernetes Secret Theft Path",
        "trigger": ["kubernetes secret", "kubectl get secret", "etcd dump", "sealed secret"],
        "companions": ["base64", "token", "password", "key", "credential"],
        "severity": "critical",
        "kill_chain": ["exploitation", "actions_objectives"],
        "attack_techniques": ["T1552.007", "T1610"],
        "remediation": [
            "Use external secret managers (Vault, AWS Secrets Manager) instead of K8s secrets",
            "Enable etcd encryption at rest",
            "Restrict secret access via RBAC (limit get/list on secrets)",
            "Enable audit logging for all secret access events",
        ],
    },
    {
        "id": "social_engineering",
        "path_title": "Social Engineering / Phishing → Credential Theft",
        "trigger": ["phishing", "social engineering", "spear phishing", "credential harvest",
                    "cloned login", "typosquatting domain"],
        "companions": ["email", "link", "login", "password", "credential"],
        "severity": "high",
        "kill_chain": ["delivery", "exploitation"],
        "attack_techniques": ["T1566", "T1598"],
        "remediation": [
            "Deploy email filtering with URL sandboxing",
            "Enforce FIDO2/WebAuthn (phishing-resistant MFA)",
            "Implement DMARC/DKIM/SPF for email authentication",
            "Conduct regular security awareness training",
        ],
    },
    {
        "id": "lfi_to_rce",
        "path_title": "LFI → RCE Chain (Log Poisoning / PHP Wrappers)",
        "trigger": ["lfi", "local file inclusion", "path traversal", "../", "php://filter",
                    "php://input", "expect://"],
        "companions": ["log", "proc/self", "passwd", "shadow", "include", "rce"],
        "severity": "critical",
        "kill_chain": ["exploitation", "installation"],
        "attack_techniques": ["T1190", "T1005", "T1059"],
        "remediation": [
            "Validate and sanitize file paths with an allow-list",
            "Disable dangerous PHP wrappers (php://input, expect://)",
            "Use chroot/jails for file-serving processes",
            "Implement Content-Security-Policy headers",
        ],
    },
]

# ── Per-finding remediation by category/title keyword (fallback) ──
CATEGORY_REMEDIATION = {
    "credential": [
        "Rotate the exposed credential immediately",
        "Revoke and regenerate API keys/tokens",
        "Enable MFA on all accounts",
        "Move secrets to a vault (HashiCorp Vault, AWS Secrets Manager)",
    ],
    "vulnerability": [
        "Apply vendor security patches",
        "Run a follow-up scan to verify remediation",
        "Implement WAF rules for the detected attack vector",
    ],
    "misconfig": [
        "Harden the misconfiguration per CIS benchmarks",
        "Remove default credentials and enforce strong passwords",
        "Disable unnecessary services and features",
    ],
    "wireless": [
        "Change WPA2/WPA3 passphrase to a strong random value",
        "Enable 802.1X enterprise authentication",
        "Deploy wireless intrusion prevention system",
    ],
    "info": ["No action required — informational only"],
}


class FindingCorrelator:
    """
    Enhanced finding correlation engine (v5.0).
    
    Links findings into scored attack paths with:
    - Kill chain progression tracking
    - MITRE ATT&CK technique mapping
    - Confidence scoring based on evidence strength
    - Cross-workflow correlation
    - Attack path graph data for visualization
    """

    def __init__(self):
        # Pre-compile trigger/companion keyword regexes
        self._rules = []
        for rule in CORRELATION_RULES:
            compiled = {
                "id": rule["id"],
                "path_title": rule["path_title"],
                "severity": rule["severity"],
                "remediation": rule["remediation"],
                "kill_chain": rule.get("kill_chain", []),
                "attack_techniques": rule.get("attack_techniques", []),
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
        # IPv4 addresses
        tokens.update(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", evidence))
        # Domains
        tokens.update(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", evidence))
        # Hash prefixes (first 12 hex chars of long hashes)
        for m in re.findall(r"\b([0-9a-fA-F]{32,})\b", evidence):
            tokens.add(m[:12].lower())
        # CVE identifiers
        tokens.update(re.findall(r"CVE-\d{4}-\d{4,7}", evidence, re.IGNORECASE))
        # Port numbers
        tokens.update(re.findall(r"(\d{1,5})/tcp", evidence))
        return sorted(tokens)

    @staticmethod
    def _finding_text(finding: Dict[str, Any]) -> str:
        """Combined searchable text of a finding."""
        return " ".join(filter(None, [
            finding.get("title") or "",
            finding.get("evidence") or "",
            finding.get("dedupe_key") or "",
            finding.get("category") or "",
        ]))

    # ═══════════════════════════════════════════════════════════════
    # MITRE ATT&CK technique mapping
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _map_attack_techniques(finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map a finding to MITRE ATT&CK techniques based on title/category."""
        text = f"{finding.get('title', '')} {finding.get('evidence', '')}".lower()
        techniques = []
        seen = set()

        # Direct keyword matching against ATT&CK table
        # Use specific patterns to avoid false positives
        keyword_map = {
            "port_scan": ["port scan", "nmap scan", "/tcp open"],
            "dns_enum": ["dns enumeration", "dns recon", "dns enum"],
            "subdomain_enum": ["subdomain", "subdomain enum"],
            "osint": ["osint", "open source intelligence"],
            "email_harvest": ["email harvest", "email address"],
            "sql_injection": ["sql injection", "sqli", "union select"],
            "xss": ["cross-site scripting", "xss", "reflected xss"],
            "ssrf": ["ssrf", "server-side request"],
            "auth_bypass": ["auth bypass", "authentication bypass", "unauthenticated"],
            "file_upload": ["file upload", "unrestricted upload"],
            "xxe": ["xxe", "xml external entity"],
            "deserialization": ["deserialization", "insecure deserialization", "pickle", "yaml.load"],
            "command_injection": ["command injection", "os command"],
            "code_execution": ["code execution", "rce", "remote code"],
            "powershell": ["powershell"],
            "python_script": ["python script", "python payload"],
            "scheduled_task": ["scheduled task", "cron job"],
            "registry_mod": ["registry modification", "autorun"],
            "web_shell": ["web shell", "webshell", "php shell"],
            "kernel_exploit": ["kernel exploit", "kernel vulnerability"],
            "suid_abuse": ["suid", "suid binary"],
            "sudo_abuse": ["sudo abuse", "sudo vulnerability"],
            "token_manipulation": ["token manipulation", "access token"],
            "process_injection": ["process injection", "code injection"],
            "obfuscation": ["obfuscation", "obfuscated"],
            "kerberoasting": ["kerberoast", "krb5tgs"],
            "asrep_roasting": ["asrep roast", "krb5asrep"],
            "dcsync": ["dcsync"],
            "mimikatz": ["mimikatz"],
            "password_spray": ["password spray"],
            "brute_force": ["brute force"],
            "credential_dump": ["credential dump", "credential harvesting"],
            "pass_the_hash": ["pass the hash", "pass-the-hash", "pth"],
            "pass_the_ticket": ["pass the ticket", "pass-the-ticket"],
            "rdp_lateral": ["rdp", "remote desktop"],
            "smb_lateral": ["smb lateral", "smb share"],
            "ssh_lateral": ["ssh lateral", "ssh key"],
            "wmi_exec": ["wmi exec", "wmi command"],
            "data_exfil": ["exfiltration", "data exfil"],
            "sensitive_file": ["sensitive file", "private key"],
            "imds_abuse": ["metadata endpoint", "169.254.169.254", "imds"],
            "iam_esc": ["iam privilege escalation", "iam:passrole"],
            "container_escape": ["container escape", "breakout"],
            "k8s_rbac_abuse": ["kubernetes rbac", "clusterrole", "kubelet"],
            "docker_socket": ["docker.sock", "docker socket"],
        }

        for key, keywords in keyword_map.items():
            if key in ATTACK_TECHNIQUES and any(kw in text for kw in keywords):
                tech = ATTACK_TECHNIQUES[key]
                if tech["id"] not in seen:
                    techniques.append(tech)
                    seen.add(tech["id"])

        return techniques[:5]  # Cap at 5 techniques per finding

    # ═══════════════════════════════════════════════════════════════
    # Kill chain progression scoring
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _kill_chain_depth(phases: List[str]) -> int:
        """Calculate kill chain depth (how many distinct phases are covered)."""
        return len(set(phases))

    @staticmethod
    def _kill_chain_progress(phases: List[str]) -> float:
        """Calculate kill chain progress (0.0 to 1.0 based on furthest phase reached)."""
        if not phases:
            return 0.0
        max_phase = max(KILL_CHAIN_PHASES.get(p, 0) for p in phases)
        return max_phase / max(KILL_CHAIN_PHASES.values())

    # ═══════════════════════════════════════════════════════════════
    # Confidence scoring
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _compute_confidence(findings: List[Dict], companions_count: int,
                            trigger_count: int, has_tokens: bool) -> float:
        """
        Compute confidence score (0.0 to 1.0) based on:
        - Number of evidence findings (more = higher confidence)
        - Token overlap (shared IPs/domains = stronger link)
        - Companion count (supporting findings boost confidence)
        """
        score = 0.0

        # Base: trigger findings present
        if trigger_count >= 1:
            score += 0.3
        if trigger_count >= 2:
            score += 0.15

        # Companion findings boost
        if companions_count >= 1:
            score += 0.15
        if companions_count >= 3:
            score += 0.1

        # Token evidence boost
        if has_tokens:
            score += 0.2

        # Total findings in path
        total = trigger_count + companions_count
        if total >= 3:
            score += 0.1
        if total >= 5:
            score += 0.05

        return min(1.0, score)

    # ═══════════════════════════════════════════════════════════════
    # Cross-workflow correlation
    # ═══════════════════════════════════════════════════════════════

    def correlate_cross_workflow(self, workflow_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate findings across multiple workflow results.
        Each workflow_result should have: {workflow_name, target, findings: [...]}
        Enriches each finding with ATT&CK techniques and remediation before
        correlation so that cross-workflow paths are fully annotated.
        """
        all_findings = []
        for wr in workflow_results:
            for f in wr.get("findings", []):
                f = dict(f)
                f["_source_workflow"] = wr.get("workflow_name", "")
                f["_source_target"] = wr.get("target", "")
                all_findings.append(f)

        # Augment findings with remediation and ATT&CK techniques
        all_findings = self.augment_findings(all_findings)

        # Correlate with enriched findings so paths inherit techniques/remediation
        return self.correlate(all_findings)

    # ═══════════════════════════════════════════════════════════════
    # Attack path graph data
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _build_attack_graph(paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build graph data structure for attack path visualization.
        Returns {nodes: [...], edges: [...], metadata: {...}}
        """
        nodes = []
        edges = []
        node_ids = set()

        for path in paths:
            path_id = path["id"]

            # Add path node
            if path_id not in node_ids:
                nodes.append({
                    "id": path_id,
                    "type": "path",
                    "label": path["title"],
                    "severity": path["severity"],
                    "score": path.get("score", 0),
                    "confidence": path.get("confidence", 0),
                })
                node_ids.add(path_id)

            # Add finding nodes and edges
            for i, finding_key in enumerate(path.get("findings", [])):
                fnode_id = f"{path_id}_finding_{i}"
                if fnode_id not in node_ids:
                    nodes.append({
                        "id": fnode_id,
                        "type": "finding",
                        "label": finding_key[:60],
                        "severity": path["severity"],
                    })
                    node_ids.add(fnode_id)

                edges.append({
                    "source": fnode_id,
                    "target": path_id,
                    "type": "belongs_to",
                })

                # Chain edges between consecutive findings
                if i > 0:
                    prev_id = f"{path_id}_finding_{i-1}"
                    edges.append({
                        "source": prev_id,
                        "target": fnode_id,
                        "type": "chain",
                    })

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_paths": len(paths),
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "severity_distribution": {
                    sev: sum(1 for p in paths if p["severity"] == sev)
                    for sev in ["critical", "high", "medium", "low", "info"]
                    if any(p["severity"] == sev for p in paths)
                },
            },
        }

    # ═══════════════════════════════════════════════════════════════
    # Main correlation
    # ═══════════════════════════════════════════════════════════════

    def correlate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate findings into scored attack paths.
        Returns a list of path dicts with:
          {id, title, severity, score, confidence, kill_chain_progress,
           attack_techniques, findings, evidence, remediation, tokens}
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
            # token with a trigger finding
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
                        if not (ft & trigger_tokens):
                            continue
                    elif not trigger_tokens and not ft:
                        pass
                    elif trigger_tokens and not ft:
                        continue
                    companions.append(f)

            members = triggers + companions

            # Severity: rule severity, boosted if many companions
            sev = rule["severity"]
            if len(companions) >= 2 and SEV_WEIGHT.get(sev, 3) >= 4:
                sev = "critical"

            # Score: severity weight + companion count + kill chain depth
            kill_phases = list(set(rule.get("kill_chain", [])))
            chain_depth = self._kill_chain_depth(kill_phases)
            score = SEV_WEIGHT.get(sev, 3) + min(len(companions), 3) + chain_depth

            # Confidence
            has_tokens = bool(trigger_tokens)
            confidence = self._compute_confidence(
                members, len(companions), len(triggers), has_tokens)

            # Kill chain progress
            kill_progress = self._kill_chain_progress(kill_phases)

            # ATT&CK techniques (from rule + per-finding mapping)
            attack_techniques = []
            seen_techs = set()
            for tech_id in rule.get("attack_techniques", []):
                if tech_id not in seen_techs:
                    attack_techniques.append({"id": tech_id, "name": ""})
                    seen_techs.add(tech_id)
            # Add per-finding techniques
            for f in members[:5]:
                for tech in self._map_attack_techniques(f):
                    if tech["id"] not in seen_techs:
                        attack_techniques.append(tech)
                        seen_techs.add(tech["id"])

            paths.append({
                "id": rule["id"],
                "title": rule["path_title"],
                "severity": sev,
                "score": score,
                "confidence": round(confidence, 2),
                "kill_chain_progress": round(kill_progress, 2),
                "kill_chain_phases": kill_phases,
                "attack_techniques": attack_techniques[:10],
                "findings": [f.get("dedupe_key") or f.get("title", "") for f in members][:20],
                "finding_details": [
                    {
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "info"),
                        "evidence": f.get("evidence", "")[:200],
                        "source_tool": f.get("source_tool", ""),
                        "category": f.get("category", ""),
                    }
                    for f in members[:10]
                ],
                "evidence": [f.get("evidence", "")[:160] for f in members[:5]],
                "remediation": rule["remediation"],
                "tokens": sorted(trigger_tokens)[:10],
            })

        # Boost paths that share tokens with higher-scored paths
        self._boost_related_paths(paths, token_map)

        # Sort by score desc, then confidence desc (AFTER boosting)
        paths.sort(key=lambda p: (p["score"], p["confidence"]), reverse=True)

        # Build attack graph data for visualization
        graph = self._build_attack_graph(paths)
        for p in paths:
            p["graph"] = graph

        return paths

    def _boost_related_paths(self, paths: List[Dict],
                             token_map: Dict[str, List[Dict]]) -> None:
        """Boost scores of paths that share evidence tokens with other paths."""
        if len(paths) < 2:
            return

        for i, p1 in enumerate(paths):
            tokens1 = set(p1.get("tokens", []))
            boost = 0
            for j, p2 in enumerate(paths):
                if i == j:
                    continue
                tokens2 = set(p2.get("tokens", []))
                overlap = tokens1 & tokens2
                if overlap:
                    # Shared tokens with a higher-severity path = boost
                    if SEV_WEIGHT.get(p2["severity"], 0) > SEV_WEIGHT.get(p1["severity"], 0):
                        boost += len(overlap)

            if boost > 0:
                p1["score"] += boost
                p1.setdefault("boost_reason", "")
                p1["boost_reason"] = f"+{boost} for {boost} shared token(s) with higher-severity paths"

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
        """Return findings with 'remediation' and 'attack_techniques' attached."""
        out = []
        for f in findings:
            f = dict(f)
            f["remediation"] = self.remediation_for(f)
            f["attack_techniques"] = self._map_attack_techniques(f)
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
        lines.append(f"## 🎯 Correlated Attack Paths ({len(paths)} identified)\n")

        # Summary table
        lines.append("| # | Severity | Path | Score | Confidence | Kill Chain | ATT&CK |")
        lines.append("|---|----------|------|-------|------------|------------|--------|")
        for i, p in enumerate(paths[:15], 1):
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                         "low": "🔵", "info": "⚪"}.get(p["severity"], "⚪")
            kill_pct = f"{p.get('kill_chain_progress', 0)*100:.0f}%"
            techs = ", ".join(t["id"] for t in p.get("attack_techniques", [])[:3])
            lines.append(
                f"| {i} | {sev_emoji} {p['severity'].upper()} | {p['title']} | "
                f"{p['score']} | {p.get('confidence', 0)*100:.0f}% | {kill_pct} | {techs} |"
            )
        lines.append("")

        # Detailed paths
        for p in paths[:15]:
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                         "low": "🔵", "info": "⚪"}.get(p["severity"], "⚪")

            lines.append(f"### {sev_emoji} {p['severity'].upper()}: {p['title']}")
            lines.append(f"- **Score**: {p['score']} | **Confidence**: {p.get('confidence', 0)*100:.0f}%")
            lines.append(f"- **Kill Chain Progress**: {p.get('kill_chain_progress', 0)*100:.0f}% "
                         f"(phases: {', '.join(p.get('kill_chain_phases', []))})")

            if p.get("attack_techniques"):
                tech_str = ", ".join(
                    f"`{t['id']}` {t.get('name', '')}" for t in p["attack_techniques"][:5])
                lines.append(f"- **MITRE ATT&CK**: {tech_str}")

            if p.get("finding_details"):
                lines.append("- **Linked Findings**:")
                for fd in p["finding_details"][:5]:
                    lines.append(f"  - [{fd['severity'].upper()}] {fd['title']} "
                                 f"(`{fd.get('source_tool', '')}`)")

            lines.append("- **Remediation:**")
            for r in p["remediation"]:
                lines.append(f"  - {r}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def summary_to_markdown(paths: List[Dict[str, Any]],
                            findings: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive correlation summary for the report."""
        lines = []

        # Overall stats
        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f.get("severity", "info")] += 1

        lines.append("## 📊 Findings Correlation Summary\n")
        lines.append(f"- **Total Findings**: {len(findings)}")
        lines.append(f"- **Correlated Attack Paths**: {len(paths)}")

        crit_paths = [p for p in paths if p["severity"] == "critical"]
        high_paths = [p for p in paths if p["severity"] == "high"]
        lines.append(f"- **Critical Paths**: {len(crit_paths)}")
        lines.append(f"- **High Paths**: {len(high_paths)}")

        if crit_paths:
            avg_conf = sum(p.get("confidence", 0) for p in crit_paths) / len(crit_paths)
            lines.append(f"- **Average Confidence (Critical)**: {avg_conf*100:.0f}%")

        # Kill chain coverage
        all_phases = set()
        for p in paths:
            all_phases.update(p.get("kill_chain_phases", []))
        if all_phases:
            lines.append(f"- **Kill Chain Coverage**: {', '.join(sorted(all_phases))}")

        # ATT&CK coverage
        all_techs = set()
        for p in paths:
            for t in p.get("attack_techniques", []):
                all_techs.add(t["id"])
        if all_techs:
            lines.append(f"- **MITRE ATT&CK Techniques Mapped**: {len(all_techs)}")
            lines.append(f"  - {', '.join(sorted(all_techs)[:15])}")
            if len(all_techs) > 15:
                lines.append(f"  - ... and {len(all_techs) - 15} more")

        lines.append("")

        # Severity breakdown
        lines.append("### Findings by Severity\n")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                         "low": "🔵", "info": "⚪"}.get(sev, "⚪")
                lines.append(f"- {emoji} **{sev.upper()}**: {count}")

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
