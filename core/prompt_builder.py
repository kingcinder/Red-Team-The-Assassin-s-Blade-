"""
RedTeam Harness - Deep PromptBuilder module.

Owns ALL prompt-construction logic for the LLM engagement loop: the static
base system prompt, the phase-aware dynamic system prompt (installed tools,
reliability hints), vector-memory context blocks, few-shot examples, and
findings auto-ingestion into memory.

Extracted from core/orchestrator.py (candidate #2, architecture review):
the orchestrator now delegates to this module, which owns the single
responsibility of turning harness state into model-ready messages.
"""
import os
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("redteam.prompt_builder")

# ── Engagement phases ──
PHASE_TOOLS = {
    "recon": ["recon", "osint", "sniffing", "wireless"],
    "vuln":   ["vuln", "web"],
    "exploit": ["exploit", "password", "wireless", "social"],
    "postex":  ["postex", "forensics", "reversing", "hardware"],
}

_BASE_SYSTEM_PROMPT = """You are an expert penetration tester and red-team operator.
You have access to a comprehensive set of security tools through the RedTeam Harness.
You are fully autonomous: plan, execute, analyze results, and chain into the next action without waiting.

## CRITICAL: Tool Call Format
You MUST use this exact JSON format for tool calls. Do NOT use XML, markdown, or any other format.
Do NOT wrap in <think> tags. Do NOT use ```json fences.
Respond with ONLY the JSON object — no explanation before or after.

Single tool call:
{"tool_call": {"tool": "<tool_name>", "args": {"param": "value"}}}

Multiple independent tools (parallel):
{"tool_calls": [{"tool": "<tool_1>", "args": {...}}, {"tool": "<tool_2>", "args": {...}}]}

Plan:
{"plan": [{"step": 1, "tool": "nmap_scan", "description": "...", "target": "..."}]}

Examples:
{"tool_call": {"tool": "nmap_scan", "args": {"target": "192.168.1.10", "ports": "80,443", "scan_type": "-sT"}}}
{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "192.168.1.0/24"}}, {"tool": "gobuster_dir", "args": {"url": "http://192.168.1.10"}}]}
{"tool_call": {"tool": "interface_discovery", "args": {}}}
{"tool_call": {"tool": "airodump_capture", "args": {"interface": "wlxdcef09d3ad89"}}}
{"tool_call": {"tool": "monitor_mode_enable", "args": {"interface": "wlxdcef09d3ad89"}}}

## Autonomous Agentic Behavior
You are an autonomous agent. For every user request:
1. Analyze the objective and determine which tools to use.
2. Generate a complete plan with ALL steps needed — do not return partial plans.
3. Execute tools and analyze their output.
4. Chain results: use the output of one tool as the input for the next.
5. When a tool fails, diagnose the error and try an alternative approach.
6. Keep going until the objective is fully achieved.
7. Report findings as you go — never stay silent.

## Tool Categories and Names
- RECON: nmap_scan, nmap_vuln_scan, host_discovery, service_enum, banner_grab, masscan_scan, subdomain_enum
- WEB: nikto_scan, sqlmap_scan, gobuster_dir, whatweb_scan, waf_detect, httpx_probe, curl_request
- WIRELESS: airodump_capture, aireplay_attack, reaver_attack, wifite_auto, monitor_mode_enable, monitor_mode_disable
- SNIFFING: tcpdump_capture, tshark_capture, bettercap_mitm, ettercap_mitm, responder_poison, dsniff_suite
- PASSWORD: hydra_brute, john_crack, hashcat_crack, crunch_gen, cewl_gen, rsmangler_gen
- EXPLOIT: msfvenom_payload, msf_resource, msf_auto_exploit, searchsploit_search, crackmapexec_exec, netexec_exec
- OSINT: whois_lookup, dig_dns, theharvester_gather, sherlock_search, holehe_check, dns_enum
- POSTEX: bloodhound_analyze, impacket_tools, mimikatz_dump, evil_winrm, socat_relay, ligolo_proxy
- FORENSICS: binwalk_analyze, foremost_carve, strings_extract, exiftool_read, steghide_extract
- REVERSING: radare2_analysis, gdb_debug, objdump_disasm, readelf_analyze, strace_trace, yara_scan
- UTILITY: interface_discovery, install_tool, list_missing_tools, check_tool_status

## Interface Handling
- Use the operator-selected interface for ALL wireless and capture tools.
- NEVER hardcode eth0, wlan0, or wlan0mon — use the interface the operator selected.
- If no interface is specified, call interface_discovery first.
- For WiFi scanning: use airodump_capture on the monitor-mode interface.
- Monitor mode management: monitor_mode_enable / monitor_mode_disable with interface param.
- Wireless tools need root — the harness handles privilege escalation automatically.

## Methodology
1. ALWAYS plan before executing tools — generate a complete plan with ALL steps
2. Use only the operator-selected interface for wireless or capture tools
3. Start with reconnaissance, then vulnerability assessment, then exploitation
4. Enumerate thoroughly before attacking
5. Document every finding with severity
6. Chain discovered information into next steps — output of tool A feeds tool B
7. If a tool fails, try alternative approaches — never give up after one failure
8. NEVER repeat the exact same tool+args more than twice
9. When you find vulnerabilities, assess and report
10. Run independent tools in parallel to save time — use tool_calls array
11. In autonomous mode, keep executing until the objective is complete

## Output Format for Findings
### Finding: [Title]
- **Severity**: Critical/High/Medium/Low/Info
- **Target**: [IP/URL]
- **Description**: [What was found]
- **Evidence**: [Proof/output]
- **Remediation**: [How to fix]
"""

# ── Few-shot examples (hardcoded successful engagement demos) ──
_FEW_SHOT_EXAMPLES = {
    "recon": [
        {"role": "user", "content": "Scan 192.168.1.0/24 for web servers"},
        {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {"target": "192.168.1.0/24", "ports": "80,443,8080,8443", "scan_type": "-sT"}}}'},
        {"role": "tool_result", "content": "[TOOL: nmap_scan] Exit code: 0\nStdout: Nmap scan report for 192.168.1.10\n80/tcp open http Apache httpd 2.4.41\n443/tcp open ssl/https\nNmap scan report for 192.168.1.20\n80/tcp open http nginx 1.18.0"},
        {"role": "assistant", "content": "Found 2 hosts with web services:\n- 192.168.1.10: Apache 2.4.41 (port 80), HTTPS (443)\n- 192.168.1.20: nginx 1.18.0 (port 80)\n\nNext I'll run service version detection on these hosts."},
    ],
    "web": [
        {"role": "user", "content": "Test http://192.168.1.10 for web vulnerabilities"},
        {"role": "assistant", "content": '{"tool_call": {"tool": "nikto_scan", "args": {"target": "http://192.168.1.10", "port": "80"}}}'},
        {"role": "tool_result", "content": "[TOOL: nikto_scan] Exit code: 0\nStdout: + /phpinfo.php: PHP info page\n+ /admin/: Admin login page\n+ Server: Apache/2.4.41 (Ubuntu)"},
        {"role": "assistant", "content": "Nikto found:\n- INFO: PHP info page at /phpinfo.php\n- MEDIUM: Admin login at /admin/\n- INFO: Server header leaks Apache version\n\nNext I'll enumerate directories with gobuster."},
    ],
}


class PromptBuilder:
    """Builds every prompt variant the engagement loop needs.

    Pure construction logic: given the tool registry, tool scorer, and vector
    memory, it produces base/dynamic system prompts, memory context blocks,
    and few-shot examples. The base prompt is built once and cached for
    KV-cache reuse across calls.
    """

    def __init__(self, tools, scorer, memory, phase_tools: Optional[Dict] = None):
        self._tools = tools
        self._scorer = scorer
        self._memory = memory
        self._phase_tools = phase_tools or PHASE_TOOLS
        self._base = self._build_base()

    # ── Public API ──
    @property
    def base(self) -> str:
        """The static system prompt (cached)."""
        return self._base

    def dynamic(self, phase: str = "recon") -> str:
        """Build the dynamic portion: inject ALL installed tools so the LLM
        always knows the full tool palette regardless of current phase.
        Phase-specific tools are highlighted first, then remaining tools follow.
        Stable format (no timestamps) for KV-cache reuse."""
        prompt = self._base
        # Qwen 3.x specific: prevent thinking from consuming token budget
        prompt += ("\nIMPORTANT: Do NOT use <think> or </think> tags. "
                   "Do NOT use markdown code fences. "
                   "Respond with ONLY the JSON tool_call object — nothing else.\n")
        prompt += f"\n## Current Engagement Phase: {phase.upper()}\n"

        installed = self._tools.get_installed_tools()

        # Phase-specific tools (highlighted first)
        phase_cats = self._phase_tools.get(phase, ["recon"])
        phase_tools = [t for t in installed if t.category in phase_cats]
        other_tools = [t for t in installed if t.category not in phase_cats]

        if phase_tools:
            prompt += f"\n## Available Tools — {phase.upper()} Phase\n"
            for tool in phase_tools:
                prompt += f"- **{tool.name}** [{tool.category}]: {tool.description}\n"
                if tool.parameters:
                    params = []
                    for pname, pinfo in tool.parameters.items():
                        req = " (required)" if pinfo.get("required") else ""
                        params.append(f"  `{pname}`: {pinfo.get('description', '')}{req}")
                    prompt += "\n".join(params) + "\n"

        # Remaining installed tools (for chaining across phases)
        if other_tools:
            prompt += "\n## Also Available (other phases)\n"
            for tool in other_tools:
                prompt += f"- **{tool.name}** [{tool.category}]: {tool.description}\n"

        all_tools = self._tools.get_all_tools()
        missing = [n for n, t in all_tools.items()
                   if not t.installed and t.category in phase_cats]
        if missing:
            prompt += (f"\n*Note: {len(missing)} tools in this category are not "
                       f"installed: {', '.join(missing[:10])}...*\n")

        reliability_hint = self._scorer.get_reliability_hint()
        if reliability_hint:
            prompt += reliability_hint

        return prompt

    def memory_context(self, user_prompt: str) -> str:
        """Query vector memory for relevant prior findings and return a
        context block (target IPs/domains extracted from the user prompt)."""
        targets = set()
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_prompt):
            if not ip.startswith(('0.', '255.')):
                targets.add(ip)
        for domain in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', user_prompt):
            if not any(x in domain for x in ['example.com', 'localhost']):
                targets.add(domain)
        if not targets:
            return ""
        all_context = []
        for t in sorted(targets)[:3]:  # Cap at 3 targets
            block = self._memory.get_context_block(t)
            if block:
                all_context.append(block)
        return "\n".join(all_context)

    def ingest_findings(self, step_data: dict, session_id: str) -> None:
        """Auto-ingest extracted findings into vector memory after each step."""
        from core.findings import extract_findings  # noqa: local import to avoid circular
        for r in step_data.get("results", []):
            stdout = r.get("stdout", "")
            if not stdout or len(stdout) < 20:
                continue
            tool_name = r.get("tool", "unknown")
            tool_findings = extract_findings(tool_name, tool_name, stdout)
            for f in tool_findings:
                f["source_tool"] = tool_name
                self._memory.ingest(f, session_id=session_id)
        mem_stats = self._memory.get_stats()
        if mem_stats["total_findings"] > 0:
            logger.debug(f"Vector memory: {mem_stats['total_findings']} total findings stored")

    def few_shot_messages(self, phase: str) -> List[Dict[str, str]]:
        """Return 2-3 example messages demonstrating successful tool usage
        for this phase."""
        return _FEW_SHOT_EXAMPLES.get(phase, _FEW_SHOT_EXAMPLES["recon"])

    # ── Internal ──
    def _build_base(self) -> str:
        """Base system prompt (no privilege steering — the harness does not
        restrict which scan types the LLM may request)."""
        return _BASE_SYSTEM_PROMPT
