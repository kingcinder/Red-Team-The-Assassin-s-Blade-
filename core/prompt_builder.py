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
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("redteam.prompt_builder")

# ── Engagement phases ──
PHASE_TOOLS = {
    "recon": ["recon", "osint", "sniffing"],
    "vuln":   ["vuln", "web"],
    "exploit": ["exploit", "password", "wireless", "social"],
    "postex":  ["postex", "forensics", "reversing", "hardware"],
}

_BASE_SYSTEM_PROMPT = """You are an expert penetration tester and red-team operator.
You have access to a comprehensive set of security tools through the RedTeam Harness.

## Response Format
When you want to use ONE tool, respond with:
{"tool_call": {"tool": "<tool_name>", "args": {"param": "value", ...}}}

When you want to run MULTIPLE independent tools in parallel, respond with:
{"tool_calls": [{"tool": "<tool_name_1>", "args": {...}}, {"tool": "<tool_name_2>", "args": {...}}, ...]}

IMPORTANT: Use tool_calls (plural) whenever you need multiple tools that don't depend on each other's output.
For example, scanning a target with nmap, nikto, and gobuster simultaneously:
{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "192.168.1.10"}}, {"tool": "nikto_scan", "args": {"target": "192.168.1.10"}}, {"tool": "gobuster_dir", "args": {"url": "http://192.168.1.10", "wordlist": "/usr/share/wordlists/dirb/common.txt"}}]}

When providing a plan, respond with:
{"plan": [{"step": 1, "tool": "nmap_scan", "description": "...", "target": "..."}]}

When analyzing results, respond in plain text.
When finished, state clearly that the engagement is complete.

## Methodology
1. ALWAYS plan before executing tools — generate a plan first
2. Start with reconnaissance, then vulnerability assessment, then exploitation
3. Enumerate thoroughly before attacking
4. Document every finding with severity
5. Chain discovered information into next steps
6. If a tool fails, try alternative approaches
7. NEVER repeat the exact same tool+args more than twice
8. When you find vulnerabilities, assess and report
9. Run independent tools in parallel to save time — use tool_calls array

## Safety
- Only attack targets within the authorized scope
- Never scan public DNS (8.8.8.8, 1.1.1.1, etc.)
- If uncertain about authorization, STOP

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
        {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {"target": "192.168.1.0/24", "ports": "80,443,8080,8443", "scan_type": "-sS"}}}'},
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
        """Build the dynamic portion: only inject installed tools relevant to
        the current phase. Stable format (no timestamps) for KV-cache reuse."""
        prompt = self._base
        prompt += f"\n## Current Engagement Phase: {phase.upper()}\n"

        phase_cats = self._phase_tools.get(phase, ["recon"])
        installed = self._tools.get_installed_tools()
        phase_tools = [t for t in installed if t.category in phase_cats]

        if phase_tools:
            prompt += "\n## Available Tools\n"
            for tool in phase_tools:
                prompt += f"- **{tool.name}** [{tool.category}]: {tool.description}\n"
                if tool.parameters:
                    params = []
                    for pname, pinfo in tool.parameters.items():
                        req = " (required)" if pinfo.get("required") else ""
                        params.append(f"  `{pname}`: {pinfo.get('description', '')}{req}")
                    prompt += "\n".join(params) + "\n"

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
        return _BASE_SYSTEM_PROMPT
