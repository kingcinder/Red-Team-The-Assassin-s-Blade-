"""
RedTeam Harness — Central Orchestrator v4.0 (Assassin's Blade)
Coordinates LLM reasoning, tool execution, and session management.

v4.0: parallel execution, smart caching, context window management,
best-of-N plan voting, reflection/self-evaluation, tactical attack engine,
drift metrics + confidence tagging, target prioritization, multi-target
scheduling, LLM workflow generation, finding correlation + auto-remediation.
"""
import json
import os
import re
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Tuple

from core.llm_backend import LLMBackend
from core.tool_registry import ToolRegistry
from core.session import SessionManager
from core.safety import SafetyEngine
from core.hardening import HardenedToolRunner
from core.task_isolation import TaskSandbox
from core.workflow_engine import WorkflowStateMachine
from core.task_scheduler import MultiTargetScheduler
from core.workflow_generator import WorkflowGenerator
from core.correlation import FindingCorrelator
from core.parallel import ParallelExecutor
from core.context_manager import ContextManager
from core.tactics import TacticalEngine
from core.prioritizer import TargetPrioritizer
from core.tool_installer import ToolInstaller
from core.tool_scorer import ToolScorer
from core.vector_memory import VectorMemory
from core.knowledge_base import KnowledgeBase
from core.injection_defense import sanitize_for_llm, sanitize_tool_output
from core.autonomous import AutonomousAgent

logger = logging.getLogger("redteam.orchestrator")

# ── Iteration limits ──
DEFAULT_MAX_ITERATIONS = 10
AUTONOMOUS_MAX_ITERATIONS = 200
MAX_CONSECUTIVE_SAME_TOOL = 3   # stuck-detection threshold
MAX_SELF_CORRECTIONS = 2        # re-prompts for malformed output

# ── Engagement phases ──
PHASE_TOOLS = {
    "recon": ["recon", "osint", "sniffing"],
    "vuln":   ["vuln", "web"],
    "exploit": ["exploit", "password", "wireless", "social"],
    "postex":  ["postex", "forensics", "reversing", "hardware"],
}

# ── Workflow chaining (v4.3) ──
MAX_CHAIN_LINKS_HARD_CAP = 10
CHAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "continue": {"type": "boolean"},
        "next_objective": {"type": "string"},
        "rationale": {"type": "string"},
        "suggested_variables": {"type": "object"},
    },
    "required": ["continue", "next_objective", "rationale"],
}


class Orchestrator:
    """
    Central orchestrator that drives the pentest engagement loop:
    0. Receive user prompt → determine phase
    1. (Optional) Planning phase — LLM outputs step-by-step plan
    2. Send to LLM with tool definitions for current phase
    3. Parse LLM tool-call response (self-correct on error)
    4. Execute tools via registry, summarize output
    5. Feed summarized results back to LLM
    6. Repeat until LLM decides engagement is complete
    """

    def __init__(self, config: dict):
        self.config = config
        self.llm = LLMBackend(config.get("llm", {}))
        self.tools = ToolRegistry(config.get("tools", {}))
        self.sessions = SessionManager(config.get("harness", {}).get("session_dir", "./sessions"))
        self.safety = SafetyEngine(config.get("safety", {}))
        self.runner = HardenedToolRunner(self.tools)
        self.parallel = ParallelExecutor(self.runner)
        self.context = ContextManager(max_tokens=config.get("assassins_blade", {}).get(
            "context_max_tokens", 32768))
        self.tactics = TacticalEngine()
        self.prioritizer = TargetPrioritizer()
        self._running = False
        self._current_session: Optional[str] = None
        self._autonomous = False
        self._callbacks: Dict[str, List[Callable]] = {
            "on_tool_start": [],
            "on_tool_complete": [],
            "on_llm_thinking": [],
            "on_llm_response": [],
            "on_llm_chunk": [],
            "on_error": [],
            "on_step_complete": [],
            "on_plan_generated": [],
            "on_report_generated": [],
            "on_workflow_start": [],
            "on_workflow_complete": [],
            "multi_target_progress": [],
            "on_chain_start": [],
            "on_chain_link": [],
            "on_chain_complete": [],
        }
        self._system_prompt_base = self._build_base_system_prompt()
        wf_cfg = config.get("workflow", {})
        self.campaign_mgr = None  # set externally by dashboard if needed
        self.scheduler = MultiTargetScheduler(
            self.runner, self.llm,
            templates_dir=wf_cfg.get("templates_dir", "workflows/templates"),
            tasks_dir=wf_cfg.get("tasks_dir", "tasks"),
            max_concurrent=wf_cfg.get("max_concurrent_targets", 3),
            emit=self._emit,
            config=config,  # v5.5: scheduler reads parallel retry/chain knobs
        )
        self.generator = WorkflowGenerator(
            self.llm, self.tools,
            templates_dir=wf_cfg.get("templates_dir", "workflows/templates"),
        )
        self.correlator = FindingCorrelator()
        self.installer = ToolInstaller(self.tools)
        scorer_dir = config.get("harness", {}).get("session_dir", "./sessions")
        self.scorer = ToolScorer(scorer_dir)
        self.memory = VectorMemory(scorer_dir)
        # v5.5: tactical engine can now ground suggestions in prior sessions
        self.tactics.set_memory(self.memory)
        # v5.6: offline knowledge base — CVE / ATT&CK / exploit signatures /
        # remediation playbooks, indexed for fast local retrieval.
        self.kb = KnowledgeBase()
        self.autonomous_agent = None  # Created on demand

    # ═══════════════════════════════════════════════════════════════
    # SYSTEM PROMPT — Dynamic, phase-aware, installed tools only
    # ═══════════════════════════════════════════════════════════════

    # Tools that must execute sequentially (modify shared state / have side effects)
    INTERCEPTED_TOOLS = frozenset({
        "msf_auto_exploit", "install_tool", "list_missing_tools",
        "install_all_missing", "check_tool_status",
    })

    def _build_base_system_prompt(self) -> str:
        """Build the static portion of the system prompt (cache-friendly)."""
        return """You are an expert penetration tester and red-team operator.
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

    def _build_dynamic_system_prompt(self, phase: str = "recon") -> str:
        """
        Build the dynamic portion: only inject installed tools relevant to the current phase.
        Stable format (no timestamps) for KV-cache reuse.
        """
        prompt = self._system_prompt_base
        prompt += f"\n## Current Engagement Phase: {phase.upper()}\n"

        # Get installed tools filtered by phase
        phase_cats = PHASE_TOOLS.get(phase, ["recon"])
        installed = self.tools.get_installed_tools()
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

        # Also add "currently unavailable" note if useful
        all_tools = self.tools.get_all_tools()
        missing = [n for n, t in all_tools.items() if not t.installed and t.category in phase_cats]
        if missing:
            prompt += f"\n*Note: {len(missing)} tools in this category are not installed: {', '.join(missing[:10])}...*\n"

        # Inject tool reliability hints (learned from previous runs)
        reliability_hint = self.scorer.get_reliability_hint()
        if reliability_hint:
            prompt += reliability_hint

        return prompt

    def _build_memory_context(self, user_prompt: str) -> str:
        """Query vector memory for relevant prior findings and return a context block."""
        # Extract target IPs/domains from the user prompt
        targets = set()
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_prompt):
            if not ip.startswith(('0.', '255.')):
                targets.add(ip)
        for domain in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', user_prompt):
            if not any(x in domain for x in ['example.com', 'localhost']):
                targets.add(domain)
        if not targets:
            return ""
        # Query each target and merge
        all_context = []
        for t in sorted(targets)[:3]:  # Cap at 3 targets
            block = self.memory.get_context_block(t)
            if block:
                all_context.append(block)
        return "\n".join(all_context)

    def _ingest_findings_to_memory(self, step_data: dict, session_id: str) -> None:
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
                self.memory.ingest(f, session_id=session_id)
        mem_stats = self.memory.get_stats()
        if mem_stats["total_findings"] > 0:
            logger.debug(f"Vector memory: {mem_stats['total_findings']} total findings stored")

    # ═══════════════════════════════════════════════════════════════
    # FEW-SHOT EXAMPLES (hardcoded successful engagement demos)
    # ═══════════════════════════════════════════════════════════════

    def _get_few_shot_messages(self, phase: str) -> List[Dict[str, str]]:
        """Return 2-3 example messages demonstrating successful tool usage for this phase."""
        examples = {
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
        return examples.get(phase, examples["recon"])

    # ═══════════════════════════════════════════════════════════════
    # EVENT SYSTEM
    # ═══════════════════════════════════════════════════════════════

    def on(self, event: str, callback: Callable):
        """Register an event callback."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def _emit(self, event: str, data: Any):
        """Emit an event to all registered callbacks."""
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception as e:
                logger.error(f"Callback error for {event}: {e}")

    # ═══════════════════════════════════════════════════════════════
    # SESSION MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    def new_session(self, name: Optional[str] = None) -> str:
        """Create a new engagement session with dynamic system prompt."""
        session_id = self.sessions.create(name)
        self._current_session = session_id

        # Start with recon phase and dynamic prompt
        system_prompt = self._build_dynamic_system_prompt("recon")
        self.sessions.add_message(session_id, "system", system_prompt)

        # Inject few-shot examples
        for msg in self._get_few_shot_messages("recon"):
            self.sessions.add_message(session_id, msg["role"], msg["content"])

        logger.info(f"New session created: {session_id}")
        return session_id

    def get_session(self) -> Optional[str]:
        """Get the current active session."""
        return self._current_session

    def set_autonomous(self, enabled: bool):
        """Enable or disable autonomous mode (no iteration limit)."""
        self._autonomous = enabled

    # ═══════════════════════════════════════════════════════════════
    # AUTONOMOUS AGENT API
    # ═══════════════════════════════════════════════════════════════

    def start_autonomous_engagement(self, targets: List[str],
                                    objective: str = "Full penetration test") -> Dict[str, Any]:
        """Start a continuous autonomous engagement against one or more targets.
        Fire-and-forget — the agent runs in a background thread.
        """
        self.autonomous_agent = AutonomousAgent(self)
        # Forward orchestrator events to autonomous agent
        self.autonomous_agent.on("on_status_update", lambda d: self._emit("on_autonomous_status", d))
        self.autonomous_agent.on("on_phase_start", lambda d: self._emit("on_autonomous_phase", d))
        self.autonomous_agent.on("on_phase_complete", lambda d: self._emit("on_autonomous_phase", d))
        self.autonomous_agent.on("on_engagement_complete", lambda d: self._emit("on_autonomous_complete", d))
        self.autonomous_agent.on("on_error", lambda d: self._emit("on_autonomous_error", d))
        self.autonomous_agent.on("on_retry_escalation", lambda d: self._emit("on_autonomous_retry", d))
        self.autonomous_agent.on("on_report_generated", lambda d: self._emit("on_autonomous_report", d))
        self.autonomous_agent.on("on_priority_update", lambda d: self._emit("on_autonomous_priority", d))
        return self.autonomous_agent.start(targets, objective)

    def stop_autonomous_engagement(self) -> Dict[str, Any]:
        """Stop the running autonomous engagement."""
        if self.autonomous_agent:
            return self.autonomous_agent.stop()
        return {"status": "not_running"}

    def pause_autonomous_engagement(self) -> Dict[str, Any]:
        """Pause the running autonomous engagement."""
        if self.autonomous_agent:
            return self.autonomous_agent.pause()
        return {"status": "not_running"}

    def resume_autonomous_engagement(self) -> Dict[str, Any]:
        """Resume a paused autonomous engagement."""
        if self.autonomous_agent:
            return self.autonomous_agent.resume()
        return {"status": "not_paused"}

    def get_autonomous_status(self) -> Dict[str, Any]:
        """Get the status of the autonomous engagement."""
        if self.autonomous_agent:
            return self.autonomous_agent.get_status()
        return {"state": "idle"}

    def get_autonomous_mission_control(self) -> Dict[str, Any]:
        """Get the full Mission Control payload (kill-chain progress, heatmap,
        retry history, phase-transition timeline) for the autonomous agent."""
        if self.autonomous_agent:
            return self.autonomous_agent.mission_control()
        return {"state": "idle", "targets": [], "retry_history": [],
                "timeline": [], "targets_count": 0}

    # ═══════════════════════════════════════════════════════════════
    # MAIN ENGAGEMENT LOOP
    # ═══════════════════════════════════════════════════════════════

    def process_prompt(self, user_prompt: str, session_id: Optional[str] = None,
                       skip_plan: bool = False, stream: bool = False) -> Dict[str, Any]:
        """
        Process a user prompt through the full engagement loop.
        Returns the final response and all intermediate steps.
        """
        sid = session_id or self._current_session
        if not sid:
            sid = self.new_session()

        self.sessions.add_message(sid, "user", user_prompt)

        # ── Vector Memory: inject prior findings for targets in prompt ──
        memory_context = self._build_memory_context(user_prompt)
        if memory_context:
            self.sessions.add_message(sid, "system", memory_context)

        # ── Planning Phase (unless skipped) ──
        if not skip_plan:
            # Phase 4: Best-of-N plan generation (if configured)
            best_n = self.config.get("assassins_blade", {}).get("reasoning_best_of_n", 3)
            if best_n > 1:
                plan = self._generate_best_plan(sid, user_prompt, n=min(best_n, 5))
            else:
                plan = self._generate_plan(sid, user_prompt)
            if plan:
                self._emit("on_plan_generated", {"session_id": sid, "plan": plan})

        # ── Engagement Loop ──
        steps = []
        max_iterations = AUTONOMOUS_MAX_ITERATIONS if self._autonomous else DEFAULT_MAX_ITERATIONS
        iteration = 0
        last_tool_sigs = []  # Track tool+args signatures for stuck detection

        while iteration < max_iterations:
            iteration += 1
            step_result = self._run_iteration(sid, steps, stream=stream)
            steps.append(step_result)

            # Stuck detection: same tool+args 3× in a row?
            for tc in step_result.get("tool_calls", []):
                sig = f"{tc.get('tool', '')}:{json.dumps(tc.get('args', {}), sort_keys=True)}"
                last_tool_sigs.append(sig)
                if len(last_tool_sigs) > MAX_CONSECUTIVE_SAME_TOOL:
                    last_tool_sigs.pop(0)
                if len(last_tool_sigs) >= MAX_CONSECUTIVE_SAME_TOOL and \
                   len(set(last_tool_sigs)) == 1:
                    logger.warning("Stuck detected — same tool repeated")
                    self.sessions.add_message(sid, "system",
                        "[HARNESS] You appear stuck repeating the same action. "
                        "Try a different approach or report findings.")
                    last_tool_sigs.clear()

            if step_result.get("action") in ("complete", "waiting_for_user", "waiting_for_approval"):
                break
            if step_result.get("error"):
                break

            # Auto phase transition
            self._check_phase_transition(sid, steps)

            # Periodic vector memory save (every 10 steps for crash recovery)
            if iteration % 10 == 0:
                self.memory.save()
                logger.debug(f"Periodic vector memory save at step {iteration}")

        # ── Phase 4: Reflection step after engagement ──
        if steps and steps[-1].get("action") == "complete" and \
           self.config.get("assassins_blade", {}).get("reasoning_self_evaluate", True):
            self._run_reflection(sid, user_prompt, steps)

        # ── Auto Report Generation ──
        if steps and steps[-1].get("action") == "complete":
            report = self._generate_report(sid)
            self._emit("on_report_generated", {"session_id": sid, "report": report})

        # ── Persist tool scores + vector memory on session end ──
        self.scorer.save()
        self.memory.save()

        return {
            "session_id": sid,
            "steps": steps,
            "total_steps": len(steps),
            "final_response": steps[-1] if steps else None,
            "token_usage": self.llm.get_usage(),
        }

    # ═══════════════════════════════════════════════════════════════
    # PLANNING PHASE
    # ═══════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: REASONING ACCELERATORS — Best-of-N plans
    # ═══════════════════════════════════════════════════════════════

    def _generate_best_plan(self, session_id: str, user_prompt: str, n: int = 3) -> Optional[List[dict]]:
        """Generate N plans and vote for the best one (Phase 4)."""
        candidates = []
        for i in range(n):
            # Raise temperature for plan diversity in best-of-N mode
            plan = self._generate_plan(session_id, user_prompt,
                                        temperature=0.7 if n > 1 else None)
            if plan:
                candidates.append(plan)

        if not candidates:
            return self._generate_plan(session_id, user_prompt)
        if len(candidates) == 1:
            return candidates[0]

        # Score plans: prefer more steps (thoroughness), tool diversity
        scored = []
        for plan in candidates:
            tools = set(s.get("tool", "") for s in plan)
            score = len(plan) + len(tools) * 2  # tool diversity bonus
            scored.append((score, plan))
        scored.sort(key=lambda x: x[0], reverse=True)

        best = scored[0][1]
        logger.info(f"Best-of-{len(candidates)} plan selected: {len(best)} steps, "
                    f"scores={[s[0] for s in scored]}")
        return best

    def _generate_plan(self, session_id: str, user_prompt: str,
                       temperature: Optional[float] = None) -> Optional[List[dict]]:
        """Force the LLM to output a step-by-step plan before executing tools."""
        try:
            plan_prompt = (
                f"Based on the user's objective: \"{sanitize_for_llm(user_prompt, max_len=500)}\"\n\n"
                "Create a step-by-step penetration testing plan. Output as JSON with "
                "a 'plan' array where each step has: step number, tool name, description, "
                "and target. Only include tools that are available. Be specific and actionable."
            )
            messages = [
                {"role": "system", "content": self._build_dynamic_system_prompt("recon")},
                {"role": "user", "content": plan_prompt},
            ]

            self._emit("on_llm_thinking", {"session_id": session_id, "step": "planning"})
            plan_schema = {
                "type": "object",
                "properties": {
                    "plan": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step": {"type": "integer"},
                                "tool": {"type": "string"},
                                "description": {"type": "string"},
                                "target": {"type": "string"},
                            },
                            "required": ["step", "tool", "description"],
                        }
                    }
                },
                "required": ["plan"],
            }
            response = self.llm.chat_structured(messages, plan_schema,
                                                 max_tokens=1024,
                                                 temperature=temperature or 0.2)

            # Parse plan JSON
            plan = self._parse_json(response)
            if plan and "plan" in plan:
                plan_text = json.dumps(plan["plan"], indent=2)
                self.sessions.add_message(session_id, "system",
                    f"[PLAN] Engagement strategy:\n{plan_text}")
                logger.info(f"Plan generated: {len(plan['plan'])} steps")
                return plan["plan"]
            return None
        except Exception as e:
            logger.warning(f"Planning phase failed (non-fatal): {e}")
            return None

    # ═══════════════════════════════════════════════════════════════
    # SINGLE ITERATION
    # ═══════════════════════════════════════════════════════════════

    def _run_iteration(self, session_id: str, previous_steps: list,
                       stream: bool = False) -> Dict[str, Any]:
        """Run a single iteration of the engagement loop with self-correction."""
        step_data = {
            "step_number": len(previous_steps) + 1,
            "timestamp": datetime.now().isoformat(),
            "tool_calls": [],
            "results": [],
            "llm_response": None,
            "action": None,
            "error": None,
            "parallel_execution": None,
        }

        try:
            # Copy messages to avoid mutating session memory during self-correction
            messages = list(self.sessions.get_messages(session_id))
            # Phase 3: Trim context before LLM call
            trimmed_messages = self.context.trim(messages)
            self._emit("on_llm_thinking", {"session_id": session_id, "step": step_data["step_number"]})

            # ── LLM call with self-correction for malformed output ──
            llm_response, corrections = self._call_llm_with_corrections(trimmed_messages, stream=stream)
            step_data["llm_response"] = llm_response
            step_data["corrections"] = corrections
            self._emit("on_llm_response", {"session_id": session_id, "response": llm_response})

            # Parse tool calls
            tool_calls = self._parse_tool_calls(llm_response)

            if not tool_calls:
                self.sessions.add_message(session_id, "assistant", llm_response)
                step_data["action"] = "complete" if self._is_engagement_complete(llm_response) else "waiting_for_user"
                return step_data

            # ── Validate & execute tool calls ──
            valid_tool_calls = []
            for tc in tool_calls:
                tool_name = tc.get("tool", "")
                tool_args = tc.get("args", {})

                # Validate tool exists
                if tool_name not in self.tools.get_all_tools():
                    self.sessions.add_message(session_id, "system",
                        f"[HARNESS] Unknown tool '{tool_name}'. Available: {', '.join(list(self.tools.get_all_tools().keys())[:20])}...")
                    continue

                # Validate required args
                tool_def = self.tools.get_all_tools().get(tool_name)
                if tool_def:
                    missing = [p for p, pi in tool_def.parameters.items()
                               if pi.get("required") and p not in tool_args]
                    if missing:
                        self.sessions.add_message(session_id, "system",
                            f"[HARNESS] Tool '{tool_name}' missing required params: {missing}. Please correct and retry.")
                        continue

                valid_tool_calls.append(tc)

            if not valid_tool_calls:
                step_data["action"] = "continue"  # Will retry next iteration with error context
                self.sessions.add_message(session_id, "assistant", llm_response)
                return step_data

            # ── Execute validated tools (parallel for independent tools) ──
            #
            # Split into two groups:
            # 1. Intercepted tools — must run sequentially (they modify shared state
            #    or need special Python-level handling)
            # 2. Normal shell tools — can run in parallel via ThreadPoolExecutor
            #
            # Each tuple carries its original index (orig_idx) so results
            # can be sorted back into LLM-requested order after parallel execution.
            intercepted_tcs = []   # [(tc, tool_name, tool_args, orig_idx)]
            parallel_tcs = []      # [(tc, tool_name, tool_args, orig_idx)]
            blocked_results = []

            for tc in valid_tool_calls:
                tool_name = tc["tool"]
                tool_args = tc["args"]

                # Safety check (runs before dispatch)
                safe, reason = self.safety.check_tool(tool_name, tool_args)
                if not safe:
                    blocked_results.append((tc, tool_name, tool_args, reason))
                    continue

                self._emit("on_tool_start", {"session_id": session_id, "tool": tool_name, "args": tool_args})

                if tool_name in self.INTERCEPTED_TOOLS:
                    intercepted_tcs.append((tc, tool_name, tool_args, i))
                else:
                    parallel_tcs.append((tc, tool_name, tool_args, i))

            # Log blocked tools
            for tc, tool_name, tool_args, reason in blocked_results:
                step_data["results"].append({"tool": tool_name, "status": "blocked", "reason": reason})
                self.sessions.add_message(session_id, "system",
                    f"[HARNESS] Tool '{tool_name}' blocked: {reason}")

            # ── Phase A: Execute intercepted tools sequentially ──
            intercepted_results = []  # [(tc, result, elapsed, orig_idx)]
            for tc, tool_name, tool_args, orig_idx in intercepted_tcs:
                start_time = time.time()
                if tool_name == "msf_auto_exploit":
                    result = self._intercept_msf_auto_exploit(tool_args)
                elif tool_name == "install_tool":
                    result = self._intercept_install_tool(tool_args)
                elif tool_name == "list_missing_tools":
                    result = self._intercept_list_missing()
                elif tool_name == "install_all_missing":
                    result = self._intercept_install_all(tool_args)
                elif tool_name == "check_tool_status":
                    result = self._intercept_check_status(tool_args)
                else:
                    result = self.tools.execute(tool_name, tool_args)
                elapsed = time.time() - start_time
                if "command" not in result:
                    result["command"] = tool_name
                intercepted_results.append((tc, result, elapsed, orig_idx))

            # ── Phase B: Execute normal tools in parallel ──
            if parallel_tcs:
                if len(parallel_tcs) == 1:
                    # Single tool — skip thread overhead, run inline
                    tc, tool_name, tool_args, orig_idx = parallel_tcs[0]
                    start_time = time.time()
                    result = self.tools.execute(tool_name, tool_args)
                    elapsed = time.time() - start_time
                    if "command" not in result:
                        result["command"] = tool_name
                    parallel_results = [(tc, result, elapsed, orig_idx)]
                else:
                    logger.info(f"Parallel execution: {len(parallel_tcs)} tools simultaneously")
                    # Build call dicts for ParallelExecutor
                    calls = [{"tool": tn, "args": ta} for _, tn, ta in parallel_tcs]
                    start_time = time.time()
                    raw_results = self.parallel.execute_many(calls)
                    total_elapsed = time.time() - start_time
                    logger.info(f"Parallel batch completed in {total_elapsed:.1f}s")
                    # Map results back to tool_calls (ordered 1:1)
                    parallel_results = []
                    for i, (tc, tool_name, tool_args, orig_idx) in enumerate(parallel_tcs):
                        result = raw_results[i]
                        elapsed = result.get("duration", 0)
                        if "command" not in result:
                            result["command"] = tool_name
                        parallel_results.append((tc, result, elapsed, orig_idx))
            else:
                parallel_results = []

            # ── Phase C: Summarize, log, and emit for ALL results ──
            all_exec_results = intercepted_results + parallel_results
            # Maintain original LLM-requested ordering for step_data
            sorted_exec = sorted(all_exec_results, key=lambda x: x[3])  # sort by orig_idx

            for tc, result, elapsed, _ in sorted_exec:
                tool_name = tc["tool"]
                tool_args = tc["args"]

                raw_stdout = result.get("stdout", "")
                raw_stderr = result.get("stderr", "")
                summary = self.llm.summarize(raw_stdout, context=tool_name)

                tool_result = {
                    "tool": tool_name,
                    "args": tool_args,
                    "status": "success" if result["exit_code"] == 0 else "error",
                    "exit_code": result["exit_code"],
                    "stdout": raw_stdout[:10000],
                    "stderr": raw_stderr[:2000],
                    "summary": summary,
                    "duration_seconds": round(elapsed, 2),
                }
                step_data["tool_calls"].append(tc)
                step_data["results"].append(tool_result)

                self._emit("on_tool_complete", {"session_id": session_id, "result": tool_result})

                # ── Auto-ingest findings into vector memory ──
                self._ingest_findings_to_memory({"results": [tool_result]}, session_id)

                # ── Record outcome for tool scoring ──
                self.scorer.record(
                    tool_name,
                    success=(result["exit_code"] == 0),
                    duration=elapsed,
                    error=raw_stderr[:200] if raw_stderr else "",
                    blocked=result.get("blocked", False),
                    timed_out="Timeout" in raw_stderr or result.get("killed", False),
                    not_installed="not installed" in raw_stderr.lower() if raw_stderr else False,
                )

                result_msg = (f"[TOOL: {tool_name}] Exit code: {result['exit_code']} "
                              f"({elapsed:.1f}s)\n{summary}")
                self.sessions.add_message(session_id, "tool_result", result_msg)
                self.sessions.log_command(session_id, tool_name, tool_args, tool_result)

            # Track parallel execution stats for step metadata
            if len(parallel_tcs) > 1:
                step_data["parallel_execution"] = {
                    "tools_run_parallel": len(parallel_tcs),
                    "tools_run_sequential": len(intercepted_tcs),
                    "total_tool_calls": len(valid_tool_calls),
                }

            self.sessions.add_message(session_id, "assistant", llm_response)
            step_data["action"] = "continue"

            # Phase 5: Tactical engine — suggest auto next steps
            if step_data.get("results"):
                all_findings = []
                for r in step_data["results"]:
                    if r.get("status") == "success":
                        all_findings.append({"description": r.get("summary", ""),
                                             "raw_output": r.get("stdout", "")})
                if all_findings:
                    suggestions = self.tactics.evaluate(all_findings)
                    auto_runs = [s for s in suggestions if s["auto_run"]]
                    step_data["tactical_suggestions"] = suggestions
                    if auto_runs:
                        logger.info(f"Tactical engine suggests {len(auto_runs)} auto-run actions")

        except Exception as e:
            logger.error(f"Orchestrator iteration error: {e}", exc_info=True)
            step_data["error"] = str(e)
            self._emit("on_error", {"session_id": session_id, "error": str(e)})

        self._emit("on_step_complete", {"session_id": session_id, "step": step_data})
        return step_data

    # ═══════════════════════════════════════════════════════════════
    # SELF-CORRECTION LOOP
    # ═══════════════════════════════════════════════════════════════

    def _call_llm_with_corrections(self, messages: List[Dict], stream: bool = False) -> Tuple[str, int]:
        """
        Call LLM, and if response contains no valid tool_call AND no plain analysis,
        re-prompt once to get a valid response. Returns (response_str, correction_count).
        """
        corrections = 0

        for attempt in range(MAX_SELF_CORRECTIONS + 1):
            if stream:
                response = self._accumulate_stream(messages)
            else:
                response = self.llm.chat(messages, cache_prompt=True)

            if attempt >= MAX_SELF_CORRECTIONS:
                return response, corrections

            # Check if response is valid
            has_tool_call = bool(self._parse_tool_calls(response))
            has_content = len(response.strip()) > 50

            if has_tool_call or has_content:
                return response, corrections

            # Empty/malformed — re-prompt
            corrections += 1
            logger.warning(f"LLM returned empty/malformed response (attempt {attempt+1})")
            messages.append({"role": "system",
                "content": "[HARNESS] Your response was empty or invalid. "
                           "Respond with a valid JSON tool_call or analysis."})

        return response, corrections

    def _accumulate_stream(self, messages: List[Dict]) -> str:
        """Accumulate streaming chunks into a single response string."""
        accumulated = ""
        for chunk in self.llm.chat_stream(messages, cache_prompt=True):
            if chunk.startswith("[ERROR]"):
                return chunk
            accumulated += chunk
            # Emit chunks for real-time dashboard updates
            self._emit("on_llm_chunk", {"content": chunk})
        return accumulated

    # ═══════════════════════════════════════════════════════════════
    # PHASE TRANSITION
    # ═══════════════════════════════════════════════════════════════

    def _run_reflection(self, session_id: str, user_prompt: str, steps: list):
        """Phase 4: LLM self-evaluates the engagement and suggests improvements."""
        try:
            step_summaries = []
            for s in steps:
                tools = [tc.get("tool", "") for tc in s.get("tool_calls", [])]
                results = [r.get("status", "?") for r in s.get("results", [])]
                step_summaries.append(f"  Step {s.get('step_number', '?')}: "
                                      f"tools={tools}, results={results}")
            reflection_prompt = (
                f"You completed a penetration test with the objective: \"{sanitize_for_llm(user_prompt, max_len=500)}\"\n\n"
                f"## Steps Taken\n" + "\n".join(step_summaries[:30]) +
                "\n\n## Reflection\n"
                "Please reflect on the engagement:\n"
                "1. What was the most impactful finding?\n"
                "2. What could have been done more efficiently?\n"
                "3. What follow-up actions are still needed?\n"
                "4. Rate the overall confidence in the results (high/medium/low).\n\n"
                "Be concise and actionable."
            )
            # Phase 3: Trim context before reflection LLM call
            reflection_messages = [
                {"role": "system", "content": self._build_dynamic_system_prompt("postex")},
                {"role": "user", "content": reflection_prompt},
            ]
            trimmed = self.context.trim(reflection_messages)
            reflection = self.llm.chat(trimmed, max_tokens=1024, temperature=0.4)
            self.sessions.add_message(session_id, "system",
                f"[REFLECTION] Self-evaluation:\n{reflection}")
            logger.info(f"Reflection generated for session {session_id}")
        except Exception as e:
            logger.warning(f"Reflection step failed (non-fatal): {e}")

    def _check_phase_transition(self, session_id: str, steps: list):
        """
        Automatically transition engagement phases based on progress.
        recon → vuln (after open ports found) → exploit → postex
        """
        # Simple heuristic: if we've run exploitation tools, move to postex
        tools_run = set()
        for step in steps:
            for tc in step.get("tool_calls", []):
                tools_run.add(tc.get("tool", ""))

        # Check what phase we're in
        current_system = ""
        for msg in reversed(self.sessions.get_messages(session_id)):
            if msg["role"] == "system" and "Engagement Phase:" in msg.get("content", ""):
                current_system = msg["content"]
                break

        if "exploit" in tools_run and "## Current Engagement Phase: EXPLOIT" not in current_system:
            new_prompt = self._build_dynamic_system_prompt("exploit")
            self.sessions.add_message(session_id, "system", new_prompt)
            logger.info("Phase transition: → EXPLOIT")

        if any(t in tools_run for t in ["crackmapexec_exec", "impacket_tools", "mimikatz_dump",
                                         "bloodhound_analyze", "evil_winrm"]):
            if "## Current Engagement Phase: POSTEX" not in current_system:
                new_prompt = self._build_dynamic_system_prompt("postex")
                self.sessions.add_message(session_id, "system", new_prompt)
                logger.info("Phase transition: → POSTEX")

    # ═══════════════════════════════════════════════════════════════
    # JSON PARSING
    # ═══════════════════════════════════════════════════════════════

    def _parse_json(self, text: str) -> Optional[dict]:
        """Robust JSON extraction from LLM output."""
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Try ```json blocks
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Try first { ... } pair
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return None

    def _parse_tool_calls(self, llm_response: str) -> list:
        """Parse tool call JSON from the LLM response.

        Handles three formats:
          - {"tool_call": {"tool": "...", "args": {}}}  (single, legacy)
          - {"tool_calls": [{"tool": "...", ...}, ...]}   (batch, preferred)
          - {"tool": "...", "args": {}}                    (bare single)

        If both singular and plural keys appear, the singular is folded into
        the plural list and deduplicated by (tool, args) signature.
        """
        tool_calls = []
        data = self._parse_json(llm_response)
        if not data:
            return tool_calls

        # ── Singular: tool_call or bare tool ──
        if "tool_call" in data and isinstance(data["tool_call"], dict):
            tc = data["tool_call"]
            if "tool" in tc:
                tool_calls.append({"tool": tc["tool"], "args": tc.get("args", {})})
        elif "tool" in data:
            tool_calls.append({"tool": data["tool"], "args": data.get("args", {}) if isinstance(data.get("args"), dict) else {}})

        # ── Plural: tool_calls array ──
        if "tool_calls" in data and isinstance(data["tool_calls"], list):
            for tc in data["tool_calls"]:
                if isinstance(tc, dict) and "tool" in tc:
                    tool_calls.append({"tool": tc["tool"], "args": tc.get("args", {})})

        # ── Deduplicate (preserves order, keeps first occurrence) ──
        seen = set()
        unique = []
        for tc in tool_calls:
            key = (tc["tool"], json.dumps(tc.get("args", {}), sort_keys=True))
            if key not in seen:
                seen.add(key)
                unique.append(tc)

        return unique

    # ═══════════════════════════════════════════════════════════════
    # COMPLETION DETECTION
    # ═══════════════════════════════════════════════════════════════

    def _is_engagement_complete(self, response: str) -> bool:
        """Check if the LLM indicates the engagement is complete."""
        complete_indicators = [
            "engagement complete", "assessment complete", "all tests done",
            "no further actions", "summary of findings", "here is the complete report",
            "testing is complete", "pentest complete", "audit complete",
            "report generated", "final summary",
        ]
        lower = response.lower()
        return any(ind in lower for ind in complete_indicators)

    # ═══════════════════════════════════════════════════════════════
    # AUTO REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════

    def _generate_report(self, session_id: str) -> str:
        """Generate a markdown pentest report from session findings."""
        try:
            session = self.sessions._load(session_id)
            findings = session.get("findings", [])
            tool_log = session.get("tool_log", [])

            if not findings and not tool_log:
                return ""

            # Build findings summary
            findings_text = ""
            for f in findings[-20:]:  # Last 20 findings
                findings_text += f"- [{f.get('severity', 'Info')}] {f.get('title', '')}: {f.get('description', '')}\n"

            report_prompt = (
                f"You conducted a penetration test. Generate a structured markdown report.\n\n"
                f"## Tools Executed\n{', '.join(set(t['tool'] for t in tool_log[-50:]))}\n\n"
                f"## Findings\n{sanitize_tool_output(findings_text or 'No findings recorded.', max_len=4000)}\n\n"
                f"Draft a professional penetration test report with sections: "
                f"Executive Summary, Methodology, Findings, Remediation, Conclusion."
            )
            self._emit("on_llm_thinking", {"session_id": session_id, "step": "report"})
            report = self.llm.chat([{"role": "user", "content": report_prompt}],
                                   max_tokens=2048, temperature=0.3)
            self.sessions.add_message(session_id, "assistant", f"## Penetration Test Report\n\n{report}")
            logger.info(f"Report generated for session {session_id}")
            return report
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return ""

    # ═══════════════════════════════════════════════════════════════
    # WORKFLOW EXECUTION (v3.0)
    # ═══════════════════════════════════════════════════════════════

    def run_workflow(self, workflow_name: str, variables: Dict[str, Any] = None,
                     resume: bool = False) -> Dict[str, Any]:
        """
        Run a YAML workflow template with full hardening and isolation.
        Returns the workflow summary with steps, findings, and chain values.
        """
        variables = variables or {}
        templates_dir = self.config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        tasks_dir = self.config.get("workflow", {}).get(
            "tasks_dir", "tasks")

        # Resolve template path
        if not workflow_name.endswith((".yaml", ".yml")):
            workflow_name += ".yaml"
        template_path = os.path.join(templates_dir, workflow_name)
        if not os.path.exists(template_path):
            # Maybe it's a full path or name without extension
            alt = os.path.join(templates_dir, workflow_name.replace(".yaml", "") + ".yml")
            if os.path.exists(alt):
                template_path = alt
            else:
                return {"error": f"Workflow template not found: {workflow_name} in {templates_dir}",
                        "available": [os.path.basename(p) for p in
                                       WorkflowStateMachine.discover_templates(templates_dir)]}

        # Create sandbox + state machine
        sandbox = TaskSandbox(workflow_name.replace(".yaml", ""), base_dir=tasks_dir)
        sandbox.setup()

        wf = WorkflowStateMachine(template_path, sandbox, self.runner, variables, llm=self.llm)
        try:
            wf.load()
        except Exception as e:
            return {"error": f"Failed to load workflow: {e}"}

        self._emit("on_workflow_start", {
            "workflow": wf.get_summary(),
            "task_id": sandbox.task_id,
            "root": sandbox.root,
        })

        result = wf.start(resume=resume)

        self._emit("on_workflow_complete", {
            "task_id": sandbox.task_id,
            **result,
        })

        return result

    def list_workflows(self) -> List[Dict]:
        """List all available workflow templates with summaries."""
        templates_dir = self.config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        try:
            return WorkflowStateMachine.load_all_summaries(templates_dir)
        except Exception as e:
            logger.error(f"Failed to list workflows: {e}")
            return []

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: LLM-DRIVEN DYNAMIC WORKFLOW GENERATION
    # ═══════════════════════════════════════════════════════════════

    def generate_workflow(self, objective: str) -> Dict[str, Any]:
        """
        Ask the local LLM to design a workflow for a natural-language
        objective, validate it against the tool registry, save it as a
        runnable template, and return the result.
        """
        self._emit("on_llm_thinking", {"session_id": self._current_session,
                                        "step": "workflow-generation"})
        result = self.generator.generate(objective)
        if "error" not in result:
            self._emit("on_plan_generated", {
                "session_id": self._current_session,
                "plan": [{"step": i + 1, "tool": s,
                           "description": f"Generated workflow step",
                           "target": result.get("name", "")}
                          for i, s in enumerate(result.get("steps", []))]})
        return result

    def auto_workflow(self, objective: str,
                      variables: Dict[str, Any] = None,
                      auto_execute: bool = True) -> Dict[str, Any]:
        """
        Full auto-workflow pipeline: generate → validate → save → execute.

        1. LLM generates a workflow from the natural-language objective
        2. Validates against the tool registry (rejects unsafe/invalid steps)
        3. Saves as a reusable YAML template
        4. Optionally executes immediately with full hardening/isolation
        5. Returns combined result with generation metadata + execution results

        Never raises — all errors are returned in the result dict.
        """
        # Phase 1: Generate (with error isolation)
        try:
            self._emit("on_llm_thinking", {
                "session_id": self._current_session,
                "step": "auto-workflow-generation",
            })
            gen_result = self.generator.generate(objective)
        except Exception as e:
            logger.error(f"Auto-workflow generation failed: {e}")
            return {
                "phase": "generation",
                "status": "failed",
                "error": f"Generation failed: {e}",
            }

        if "error" in gen_result:
            return {
                "phase": "generation",
                "status": "failed",
                "error": gen_result["error"],
                "validation_errors": gen_result.get("validation_errors", []),
            }

        workflow_name = gen_result.get("name", "")
        if not workflow_name:
            return {"phase": "generation", "status": "failed",
                    "error": "Generated workflow has no name"}

        # Phase 2-3: Already validated and saved by generator.generate()
        self._emit("on_plan_generated", {
            "session_id": self._current_session,
            "plan": [{"step": i + 1, "tool": s,
                       "description": "Auto-workflow step",
                       "target": workflow_name}
                      for i, s in enumerate(gen_result.get("steps", []))],
        })

        result = {
            "phase": "generated",
            "status": "generated",
            "workflow_name": workflow_name,
            "path": gen_result.get("path", ""),
            "steps_count": gen_result.get("steps_count", 0),
            "steps": gen_result.get("steps", []),
            "variables": gen_result.get("variables", []),
            "objective": objective,
            "created": gen_result.get("created", ""),
        }

        # Phase 4: Auto-execute if requested (with error isolation)
        if auto_execute:
            try:
                self._emit("on_llm_thinking", {
                    "session_id": self._current_session,
                    "step": "auto-workflow-execution",
                })
                exec_result = self.run_workflow(workflow_name, variables or {})
                result["execution"] = exec_result
                result["phase"] = "executed"
                result["status"] = exec_result.get("status", "unknown")

                # Auto-correlate findings if any
                findings = exec_result.get("findings", [])
                if findings:
                    correlation = self.correlate_findings(findings)
                    result["correlation"] = correlation

                # ── Post-execution template self-improvement (v4.2) ──
                # Ask the LLM to analyze the run and improve the saved template
                improve_cfg = self.config.get("workflow", {}).get(
                    "template_self_improve", True)
                if improve_cfg:
                    try:
                        self._emit("on_llm_thinking", {
                            "session_id": self._current_session,
                            "step": "template-improvement",
                        })
                        improvement = self.generator.improve_template(
                            result["path"], exec_result, apply=True)
                        result["template_improvement"] = improvement
                    except Exception as e:
                        logger.error(f"Template improvement pass failed: {e}")
                        result["template_improvement"] = {"error": str(e)}
            except Exception as e:
                logger.error(f"Auto-workflow execution failed: {e}")
                result["phase"] = "execution_failed"
                result["status"] = "failed"
                result["execution_error"] = str(e)

        return result

    # ═══════════════════════════════════════════════════════════════
    # PHASE 8: WORKFLOW CHAINING (v4.3)
    # ═══════════════════════════════════════════════════════════════

    def chain_workflows(self, objective: str,
                        variables: Dict[str, Any] = None,
                        max_links: int = None) -> Dict[str, Any]:
        """
        Chain multiple auto-generated workflows together.

        After each workflow completes, the LLM is asked to decide the next
        logical workflow objective based on the sanitized findings from that
        run. If it recommends continuing, the next workflow is auto-generated,
        saved, and executed with the previous run's chain values + variables
        carried forward. Repeats until the LLM says stop, max_links is reached,
        a loop is detected, or any link fails fatally.

        Returns the full chain record: per-link results, pooled findings,
        correlated attack paths, and a combined markdown report.
        Never raises — failures are recorded in the chain dict.
        """
        max_links = int(max_links or self.config.get("workflow", {}).get(
            "chain_max_links", 3))
        max_links = max(1, min(max_links, MAX_CHAIN_LINKS_HARD_CAP))

        chain = {
            "chain_id": datetime.now().strftime("chain_%Y%m%d_%H%M%S"),
            "objective": objective,
            "status": "running",
            "links": [],
            "used_objectives": [objective],
            "chain_values": dict(variables or {}),
            "findings": [],
            "error": None,
        }
        self._emit("on_chain_start", {"chain_id": chain["chain_id"],
                                       "objective": objective})

        current_objective = objective
        current_vars = dict(variables or {})

        try:
            for link_no in range(1, max_links + 1):
                self._emit("on_llm_thinking", {
                    "session_id": self._current_session,
                    "step": f"chain-link-{link_no}",
                })
                link = self.auto_workflow(current_objective,
                                          variables=current_vars,
                                          auto_execute=True)
                link["link_number"] = link_no
                link["objective"] = current_objective
                chain["links"].append(link)
                self._emit("on_chain_link", {
                    "chain_id": chain["chain_id"],
                    "link_number": link_no,
                    "objective": current_objective,
                    "status": link.get("status"),
                    "workflow": (link.get("execution") or {}).get("workflow", ""),
                })

                # Carry chain values + findings forward from this link
                exec_result = link.get("execution") or {}
                for k, v in (exec_result.get("chain_values") or {}).items():
                    chain["chain_values"][k] = v
                chain["findings"].extend(exec_result.get("findings") or [])

                # A hard execution failure terminates the chain
                if link.get("status") in ("failed", "execution_failed") \
                        or exec_result.get("error"):
                    chain["status"] = "failed"
                    chain["error"] = exec_result.get("error") or "link failed"
                    break

                # Ask the LLM what to do next (only if this link found something)
                if not chain["findings"]:
                    chain["status"] = "complete"
                    break

                decision = self._decide_next_workflow(
                    chain["findings"], chain["chain_values"],
                    chain["used_objectives"])
                if not decision or not decision.get("continue"):
                    chain["status"] = "complete"
                    break

                next_obj = decision.get("next_objective", "")
                if not next_obj:
                    chain["status"] = "complete"
                    break

                # Loop / drift guard: never re-run an objective
                if next_obj in chain["used_objectives"]:
                    chain["status"] = "complete"
                    chain["loop_guard"] = next_obj
                    break

                # Propagate suggested variables from the LLM + prior chain values
                suggested = decision.get("suggested_variables") or {}
                current_vars = {**current_vars, **chain["chain_values"], **suggested}
                chain["used_objectives"].append(next_obj)
                current_objective = next_obj

            if chain["status"] == "running":
                chain["status"] = "complete"
        except Exception as e:
            logger.error(f"Workflow chain failed: {e}", exc_info=True)
            chain["status"] = "failed"
            chain["error"] = str(e)

        # ── Pool + correlate + combined report ──
        chain["links_count"] = len(chain["links"])
        chain["findings_count"] = len(chain["findings"])
        if chain["findings"]:
            chain["correlation"] = self.correlate_findings(chain["findings"])
        chain["report"] = self._build_chain_report(chain)
        self._emit("on_chain_complete", {
            "chain_id": chain["chain_id"],
            "status": chain["status"],
            "links_count": chain["links_count"],
            "findings_count": chain["findings_count"],
        })
        return chain

    def _decide_next_workflow(self, findings: List[Dict],
                              chain_values: Dict[str, Any],
                              used_objectives: List[str]) -> Optional[Dict]:
        """
        Ask the local LLM whether to continue the chain and what the next
        workflow objective should be, based on sanitized findings.
        Returns None on any failure (chain stops safely). Never raises.
        """
        try:
            # Sanitize everything that came from tool output (attacker-controlled)
            # with the AGGRESSIVE tool-output sanitizer — findings titles and chain
            # values originate in service banners/page content. Only used_objectives
            # (operator/system text) uses the narrower operator-text sanitizer.
            findings_brief = []
            for f in findings[-15:]:
                findings_brief.append(
                    f"- [{sanitize_tool_output(str(f.get('severity', 'info')).upper(), max_len=12)}] "
                    f"{sanitize_tool_output(str(f.get('title', ''))[:120], max_len=140)} "
                    f"(tool={sanitize_tool_output(str(f.get('source_tool', '?')), max_len=40)})")
            done = ", ".join(sanitize_for_llm(o, max_len=120) for o in used_objectives)
            cv = sanitize_tool_output(json.dumps(chain_values, default=str)[:500], max_len=500)

            prompt = (
                "You are orchestrating a chained penetration-testing campaign. "
                "A workflow just completed with these findings:\n\n"
                + "\n".join(findings_brief) +
                f"\n\nAlready executed objectives: {done}\n"
                f"Discovered values to propagate: {cv}\n\n"
                "Decide whether to launch the next chained workflow. Return strict JSON:\n"
                "{\"continue\": true/false, \"next_objective\": \"...\", "
                "\"rationale\": \"...\", \"suggested_variables\": {}}\n"
                "- continue=true only if a clearly valuable next step exists "
                "(e.g. pivot recon→exploit on a discovered service, follow up a "
                "critical finding, deepen postex).\n"
                "- continue=false if the engagement is exhausted, findings are "
                "informational only, or the next step would be redundant.\n"
                "- next_objective: a concrete, scoped objective using only "
                "discovered targets/services; NEVER repeat an already-executed "
                "objective.\n"
                "- suggested_variables: optional {key: value} to carry into the "
                "next workflow (e.g. discovered host, port, credentials)."
            )
            response = self.llm.chat_structured(
                [{"role": "system",
                  "content": "You are an expert penetration-testing campaign planner. "
                             "Output strict JSON only."},
                 {"role": "user", "content": prompt}],
                CHAIN_SCHEMA, max_tokens=512, temperature=0.3)
            if response.startswith("[ERROR]"):
                return None
            data = self._parse_json(response)
            if not data:
                return None
            return {
                "continue": bool(data.get("continue", False)),
                "next_objective": str(data.get("next_objective", "")).strip(),
                "rationale": sanitize_for_llm(str(data.get("rationale", ""))[:300], max_len=320),
                "suggested_variables": data.get("suggested_variables")
                if isinstance(data.get("suggested_variables"), dict) else {},
            }
        except Exception as e:
            logger.warning(f"Chain decision failed (non-fatal): {e}")
            return None

    def _build_chain_report(self, chain: Dict[str, Any]) -> str:
        """Build a combined markdown report for a completed workflow chain."""
        lines = [
            f"# Chained Workflow Report — {chain['chain_id']}",
            "",
            f"- **Status**: {chain['status']}",
            f"- **Links executed**: {chain.get('links_count', len(chain.get('links', [])))}",
            f"- **Total findings**: {chain.get('findings_count', len(chain.get('findings', [])))}",
            "",
            "## Chain Objectives",
            "",
        ]
        for i, link in enumerate(chain.get("links", []), 1):
            ex = link.get("execution") or {}
            lines.append(f"{i}. **{link.get('objective', '?')}** → "
                         f"`{ex.get('workflow', '?')}` "
                         f"[{ex.get('status', link.get('status', '?'))}] "
                         f"({ex.get('completed_steps', 0)}/{ex.get('total_steps', 0)} steps)")
            if link.get("template_improvement"):
                ti = link["template_improvement"]
                if not ti.get("error") and ti.get("applied"):
                    lines.append(f"    ↳ template improved: {len(ti.get('applied_changes', {}).get('removed', []))} removed, "
                                 f"{len(ti.get('applied_changes', {}).get('modified', []))} modified, "
                                 f"{len(ti.get('applied_changes', {}).get('added', []))} added")
        if chain.get("loop_guard"):
            lines.append(f"\n*Chain stopped by loop guard: '{chain['loop_guard']}' "
                         f"was already executed.*")

        findings = chain.get("findings", [])
        if findings:
            counts = {}
            for f in findings:
                sev = str(f.get("severity", "info")).lower()
                counts[sev] = counts.get(sev, 0) + 1
            lines.append("")
            lines.append("## Findings Summary")
            lines.append("")
            for sev in ("critical", "high", "medium", "low", "info"):
                if counts.get(sev):
                    lines.append(f"- **{sev.upper()}**: {counts[sev]}")
            lines.append("")
            lines.append("## Findings")
            lines.append("")
            for f in findings:
                lines.append(f"- [{str(f.get('severity', 'info')).upper()}] "
                             f"{f.get('title', '?')} — {f.get('description', '')}")
        if chain.get("correlation") and chain["correlation"].get("paths"):
            lines.append("")
            lines.append("## Correlated Attack Paths")
            lines.append("")
            lines.append(self.correlator.paths_to_markdown(
                chain["correlation"]["paths"]))
        lines.append("")
        lines.append("---")
        lines.append("*Generated automatically by RedTeam Harness.*")
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: CONCURRENT MULTI-TARGET EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def run_parallel_workflows(self, jobs: List[Dict[str, Any]],
                               campaign_id: str = None,
                               max_concurrent: int = None,
                               max_workers: int = None) -> Dict[str, Any]:
        """
        v5.3: run MULTIPLE different workflow jobs concurrently (each job =
        {workflow, targets, variables, per_target_vars}) and merge ALL findings
        across workflows via correlate_cross_workflow into a unified
        campaign-level attack path report.
        """
        return self.scheduler.run_multiple(jobs or [],
                                           campaign_id=campaign_id,
                                           max_concurrent=max_concurrent,
                                           max_workers=max_workers)

    def chain_parallel_waves(self, seed_jobs: List[Dict[str, Any]],
                             max_waves: int = 3,
                             campaign_id: str = None) -> Dict[str, Any]:
        """
        v5.5: chained parallel waves — a campaign of campaigns. After each
        multi-workflow wave completes, feed its unified findings into the
        auto-prioritizer to decide which workflows/targets the NEXT wave
        should hit. Each wave is a run_multiple() over the chosen jobs;
        the chain stops when the LLM/heuristic finds nothing new, max_waves
        is reached, or a wave fails fatally. Fire-and-forget; never raises.
        """
        max_waves = max(1, min(int(max_waves), 5))
        waves = []
        result = {
            "chain_id": datetime.now().strftime("chainwave_%Y%m%d_%H%M%S"),
            "status": "running",
            "waves": waves,
            "findings": [],
            "error": None,
        }
        self._emit("on_chain_start", {"chain_id": result["chain_id"],
                                       "campaign_id": campaign_id,
                                       "waves": max_waves})
        import threading as _threading

        def _run():
            try:
                current_jobs = list(seed_jobs or [])
                wave_no = 0
                while current_jobs and wave_no < max_waves:
                    wave_no += 1
                    self._emit("on_llm_thinking", {
                        "session_id": self._current_session,
                        "step": f"parallel-wave-{wave_no}",
                    })
                    wave = self.run_parallel_workflows(
                        current_jobs, campaign_id=campaign_id)
                    wave["wave_number"] = wave_no
                    waves.append(wave)
                    result["findings"].extend(wave.get("pooled_findings", []) or [])
                    self._emit("on_chain_link", {
                        "chain_id": result["chain_id"],
                        "campaign_id": campaign_id,
                        "wave": wave_no,
                        "status": wave.get("status"),
                        "jobs": len(current_jobs),
                        "findings": len(wave.get("pooled_findings", []) or []),
                    })
                    if wave.get("status") in ("failed", "error") or wave.get("error"):
                        result["status"] = "failed"
                        result["error"] = wave.get("error") or "wave failed"
                        break
                    if not result["findings"]:
                        result["status"] = "complete"
                        break
                    # Decide the next wave from the unified findings
                    decision = self._decide_next_workflow(
                        result["findings"], {}, [])
                    if not decision or not decision.get("continue"):
                        result["status"] = "complete"
                        break
                    next_obj = decision.get("next_objective", "")
                    if not next_obj:
                        result["status"] = "complete"
                        break
                    gen = self.auto_workflow(next_obj, auto_execute=False)
                    next_wf = ((gen.get("execution") or {}).get("workflow")
                               or gen.get("workflow_name") or "")
                    if not next_wf:
                        result["status"] = "complete"
                        break
                    # Re-target: hit the same hosts with the new workflow
                    current_jobs = [{"workflow": next_wf,
                                     "targets": wave.get("targets", [])}]
                if result["status"] == "running":
                    result["status"] = "complete"
            except Exception as e:
                logger.error(f"Chained parallel waves failed: {e}", exc_info=True)
                result["status"] = "failed"
                result["error"] = str(e)
            finally:
                if campaign_id and self.scheduler._campaign_mgr:
                    self.scheduler._campaign_mgr.mark_campaign_complete(campaign_id)
                self._emit("on_chain_complete", {
                    "chain_id": result["chain_id"],
                    "campaign_id": campaign_id,
                    "status": result["status"],
                    "waves": len(waves),
                })

        _threading.Thread(target=_run, daemon=True).start()
        return {"chain_id": result["chain_id"], "campaign_id": campaign_id,
                "status": "started", "max_waves": max_waves}

    def run_multi_workflow(self, workflow_name: str, targets: List[str],
                           variables: Dict[str, Any] = None,
                           max_concurrent: int = None,
                           campaign_id: str = None,
                           priority_plan: List[Dict[str, Any]] = None,
                           auto_prioritize: bool = False,
                           targets_data: List[Dict[str, Any]] = None,
                           findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run a workflow against multiple targets concurrently with per-target
        isolation and combined aggregation.

        v5.2: optional LLM-driven target prioritization. When
        ``auto_prioritize=True`` (and no ``priority_plan`` is supplied), the
        auto-prioritizer ranks the targets by exploitability first — the
        scheduler then processes high-value targets first and with a higher
        retry budget. ``targets_data`` (ports/services per target) and
        ``findings`` feed the ranking when available.
        """
        plan = priority_plan
        if auto_prioritize and not plan:
            td = targets_data or [{"target": t} for t in (targets or [])]
            ranked = self.auto_prioritize_targets(td, findings or [])
            if "error" not in ranked:
                plan = ranked.get("ordered_targets", [])
        return self.scheduler.run(workflow_name, targets or [],
                                  base_variables=variables or {},
                                  max_concurrent=max_concurrent,
                                  campaign_id=campaign_id,
                                  priority_plan=plan)

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: FINDING CORRELATION + AUTO-REMEDIATION
    # ═══════════════════════════════════════════════════════════════

    def correlate_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Correlate findings into scored attack paths with remediation."""
        paths = self.correlator.correlate(findings or [])
        augmented = self.correlator.augment_findings(findings or [])
        # v5.6: ground every finding in the offline KB (CVE / ATT&CK /
        # exploit signature / remediation playbook) before returning.
        try:
            augmented = self.kb.ground_findings(augmented or [])
        except Exception as e:
            logger.warning(f"KB grounding skipped for correlation: {e}")
        return {"paths": paths, "findings": augmented,
                "paths_count": len(paths)}

    def get_task_correlation(self, task_id: str) -> Dict[str, Any]:
        """Correlate the pooled findings of a saved task run."""
        tasks_dir = self.config.get("workflow", {}).get("tasks_dir", "tasks")
        m = re.match(r"^(.*)_(\d{8}_\d{6}(?:_[0-9a-f]{4})?)$", task_id)
        if not m:
            return {"error": "Invalid task_id"}
        wf_dir, ts = m.group(1), m.group(2)
        state_path = os.path.join(tasks_dir, wf_dir, ts, "state.json")
        if not os.path.exists(state_path):
            return {"error": "Task not found"}
        try:
            with open(state_path) as f:
                state = json.load(f)
        except Exception as e:
            return {"error": f"Failed to load task state: {e}"}
        findings = state.get("findings", [])
        if not findings and state.get("pooled_findings"):
            findings = state["pooled_findings"]
        return self.correlate_findings(findings)

    def get_workflow_status(self, workflow_name: str) -> Dict[str, Any]:
        """Get recent task status for a workflow."""
        tasks_dir = self.config.get("workflow", {}).get("tasks_dir", "tasks")
        sandbox = TaskSandbox(workflow_name, base_dir=tasks_dir)
        return {"tasks": sandbox.list_tasks()}

    # ═══════════════════════════════════════════════════════════════
    # DIRECT TOOL EXECUTION
    # ═══════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: TARGET PRIORITIZATION
    # ═══════════════════════════════════════════════════════════════

    def prioritize_targets(self, targets_data: List[Dict],
                           findings: List[Dict] = None) -> List[Dict]:
        """Score and prioritize targets for multi-target campaigns."""
        return self.prioritizer.prioritize(targets_data or [], findings)

    def auto_prioritize_targets(self, targets_data: List[Dict],
                                findings: List[Dict] = None) -> Dict[str, Any]:
        """
        LLM-driven target ranking (v5.2). Ranks discovered targets by
        exploitability using the local LLM, falling back to the heuristic
        scorer when the LLM is unavailable or produces invalid output.

        Returns a plan dict: {ordered_targets, used_llm, fallback_reason,
        llm_rankings} — ordered_targets is [{target, rank, score, tier,
        aggressiveness, rationale, suggested_workflow}].
        """
        from core.auto_prioritizer import AutoTargetPrioritizer
        ap = AutoTargetPrioritizer(llm=self.llm, config=self.config)
        return ap.prioritize(targets_data or [], findings or [])

    # ═══════════════════════════════════════════════════════════════
    # V5.5: LLM ANALYST BRIEF + CAMPAIGN AUTO-START CHAIN
    # ═══════════════════════════════════════════════════════════════

    def llm_campaign_brief(self, compare: Dict[str, Any]) -> str:
        """
        Ask the local LLM to write a 2-paragraph analyst brief on a campaign
        comparison — the risk delta between the two engagements and which
        persistent exposures deserve immediate remediation. Falls back to a
        template-based brief when the LLM is unavailable. Never raises.
        """
        try:
            a = compare.get("campaign_a", {}) or {}
            b = compare.get("campaign_b", {}) or {}
            overlap = compare.get("overlap", []) or []
            uniq_a = compare.get("unique_a", []) or []
            uniq_b = compare.get("unique_b", []) or []
            pto = compare.get("per_target_overlap", []) or []

            def _sev_txt(cam):
                sc = cam.get("severity_counts", {}) or {}
                return (f"{sc.get('critical', 0)} crit / {sc.get('high', 0)} high / "
                        f"{sc.get('medium', 0)} med / {sc.get('low', 0)} low")

            risk_a = (a.get("risk") or {}).get("score", 0)
            risk_b = (b.get("risk") or {}).get("score", 0)
            delta = round(risk_b - risk_a, 1)

            ov_txt = "\n".join(
                f"- {o.get('dedupe_key', '')} (sev {o.get('severity_a', '')}/{o.get('severity_b', '')}, "
                f"persistent={o.get('persistent', False)})"
                for o in overlap[:12])
            ua_txt = "\n".join(f"- {u.get('dedupe_key', '')} [{u.get('severity', '')}]"
                                for u in uniq_a[:10])
            ub_txt = "\n".join(f"- {u.get('dedupe_key', '')} [{u.get('severity', '')}]"
                                for u in uniq_b[:10])
            pto_txt = "\n".join(
                f"- {p.get('target', '')}: {', '.join(v.get('dedupe_key', '') for v in p.get('vulns', []))}"
                for p in pto[:10])

            prompt = (
                "You are a senior penetration-testing analyst. Two campaigns "
                "just completed. Write a 2-paragraph analyst brief: "
                "(1) the risk delta between the two engagements and what it "
                "means; (2) which persistent exposures (vulnerabilities found "
                "in BOTH campaigns, especially on the same host) deserve "
                "immediate remediation, prioritized by severity. Be specific "
                "and cite finding names."
                f"\n\nCampaign A risk={risk_a}, findings: {_sev_txt(a)}"
                f"\nCampaign B risk={risk_b} (delta {delta:+}), findings: {_sev_txt(b)}"
                f"\n\nOverlapping exposures ({len(overlap)}):\n{ov_txt or '(none)'}"
                f"\n\nUnique to A ({len(uniq_a)}):\n{ua_txt or '(none)'}"
                f"\n\nUnique to B ({len(uniq_b)}):\n{ub_txt or '(none)'}"
                f"\n\nSame-host persistent exposures ({len(pto)}):\n{pto_txt or '(none)'}"
            )
            response = self.llm.chat([
                {"role": "system",
                 "content": "You are a concise penetration-testing analyst. "
                            "Output plain text only, 2 paragraphs."},
                {"role": "user", "content": sanitize_for_llm(prompt, max_len=6000)},
            ], max_tokens=700, temperature=0.4)
            response = (response or "").strip()
            if response and not response.startswith("[ERROR]"):
                return response
        except Exception as e:
            logger.warning(f"LLM campaign brief failed (fallback): {e}")
        return (f"Risk delta between engagements: {delta:+} points "
                f"(A={risk_a}, B={risk_b}). {len(overlap)} overlapping "
                f"exposure(s) identified. Prioritize remediation of "
                f"persistent findings on shared hosts: "
                f"{', '.join((o.get('dedupe_key', '') for o in overlap[:5])) or 'none'}.")

    def start_campaign_chain(self, campaign_id: str, workflow: str,
                             targets: List[str],
                             variables: Optional[Dict[str, Any]] = None,
                             max_links: Optional[int] = None) -> Dict[str, Any]:
        """
        v5.5: live campaign auto-start flow. Picks a workflow + target list,
        runs it through the scheduler (tracking in the campaign), then asks
        the LLM to decide the next workflow objective for the campaign based
        on the findings — generates + executes the next workflow, all tracked
        live in the same dashboard campaign. Fire-and-forget; never raises.
        """
        max_links = int(max_links or self.config.get("workflow", {}).get(
            "chain_max_links", 3))
        max_links = max(1, min(max_links, MAX_CHAIN_LINKS_HARD_CAP))
        chain = {
            "chain_id": datetime.now().strftime("chain_%Y%m%d_%H%M%S"),
            "campaign_id": campaign_id,
            "status": "running",
            "links": [],
            "used_objectives": [],
            "chain_values": dict(variables or {}),
            "findings": [],
            "error": None,
        }
        self._emit("on_chain_start", {"chain_id": chain["chain_id"],
                                       "campaign_id": campaign_id,
                                       "workflow": workflow})
        import threading as _threading

        def _run():
            try:
                current_workflow = workflow
                current_vars = dict(variables or {})
                for link_no in range(1, max_links + 1):
                    link_result = self.run_multi_workflow(
                        current_workflow, targets, current_vars,
                        campaign_id=campaign_id)
                    chain["links"].append({
                        "link_number": link_no,
                        "workflow": current_workflow,
                        "status": link_result.get("status", "unknown"),
                        "combined_id": link_result.get("combined_id"),
                    })
                    self._emit("on_chain_link", {
                        "chain_id": chain["chain_id"],
                        "campaign_id": campaign_id,
                        "link_number": link_no,
                        "workflow": current_workflow,
                        "status": link_result.get("status"),
                    })
                    link_findings = link_result.get("pooled_findings", []) or []
                    chain["findings"].extend(link_findings)
                    for k, v in (link_result.get("chain_values") or {}).items():
                        chain["chain_values"][k] = v
                    if link_result.get("status") in ("failed", "error") or \
                            link_result.get("error"):
                        chain["status"] = "failed"
                        chain["error"] = link_result.get("error") or "link failed"
                        break
                    if not chain["findings"]:
                        chain["status"] = "complete"
                        break
                    decision = self._decide_next_workflow(
                        chain["findings"], chain["chain_values"],
                        chain["used_objectives"])
                    if not decision or not decision.get("continue"):
                        chain["status"] = "complete"
                        break
                    next_obj = decision.get("next_objective", "")
                    if not next_obj or next_obj in chain["used_objectives"]:
                        chain["status"] = "complete"
                        break
                    # Auto-generate the next workflow from the LLM objective
                    gen = self.auto_workflow(next_obj,
                                             variables=current_vars,
                                             auto_execute=False)
                    next_wf = ((gen.get("execution") or {}).get("workflow")
                               or gen.get("workflow_name") or "")
                    if not next_wf:
                        chain["status"] = "complete"
                        chain["error"] = gen.get("error") or "next workflow generation failed"
                        break
                    suggested = decision.get("suggested_variables") or {}
                    current_vars = {**current_vars, **chain["chain_values"],
                                    **suggested}
                    chain["used_objectives"].append(next_obj)
                    current_workflow = next_wf
                if chain["status"] == "running":
                    chain["status"] = "complete"
            except Exception as e:
                logger.error(f"Campaign chain failed: {e}", exc_info=True)
                chain["status"] = "failed"
                chain["error"] = str(e)
            finally:
                if campaign_id and self.scheduler._campaign_mgr:
                    self.scheduler._campaign_mgr.mark_campaign_complete(campaign_id)
                self._emit("on_chain_complete", {
                    "chain_id": chain["chain_id"],
                    "campaign_id": campaign_id,
                    "status": chain["status"],
                    "links": len(chain["links"]),
                })

        _threading.Thread(target=_run, daemon=True).start()
        return {"chain_id": chain["chain_id"], "campaign_id": campaign_id,
                "status": "started"}

    # ═══════════════════════════════════════════════════════════════
    # DIRECT TOOL EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def _intercept_install_tool(self, args: dict) -> Dict[str, Any]:
        """Intercept install_tool calls — route to the ToolInstaller."""
        tool_name = args.get("tool_name", "")
        if not tool_name:
            return {"stdout": "", "stderr": "No tool_name specified", "exit_code": 1, "duration": 0, "command": "install_tool(?)"}
        result = self.installer.install_tool(tool_name)
        status = result.get("status", "error")
        msg = result.get("message", "")
        method = result.get("method", "")
        path = result.get("path", "")
        stdout = f"Status: {status}\nMethod: {method}\nMessage: {msg}"
        if path:
            stdout += f"\nPath: {path}"
        # Re-detect so the registry picks up the new tool
        self.tools._detect_installed()
        ret = {"stdout": stdout, "stderr": "", "exit_code": 0 if status in ("installed", "already_installed") else 1, "duration": 0, "command": f"install_tool({tool_name})"}
        return ret

    def _intercept_list_missing(self) -> Dict[str, Any]:
        """Intercept list_missing_tools — return all tools not yet installed."""
        missing = self.installer.list_missing_tools()
        installable = [m for m in missing if m["installable"]]
        lines = [f"Missing tools: {len(missing)} total, {len(installable)} installable\n"]
        for m in missing[:30]:
            flag = "✓" if m["installable"] else "✗"
            lines.append(f"  {flag} {m['binary']} [{m['category']}] — {m['install_method']}")
        if len(missing) > 30:
            lines.append(f"  ... and {len(missing) - 30} more")
        return {"stdout": "\n".join(lines), "stderr": "", "exit_code": 0, "duration": 0, "command": "list_missing_tools()"}

    def _intercept_install_all(self, args: dict) -> Dict[str, Any]:
        """Intercept install_all_missing — batch install up to N tools (capped at 50)."""
        max_tools = min(int(args.get("max_tools", 20)), 50)
        result = self.installer.install_all_missing(max_tools=max_tools)
        lines = [
            f"Batch install complete (max {max_tools}):",
            f"  Installed: {result['total_installed']}",
            f"  Failed: {result['total_failed']}",
            f"  Skipped: {result['total_skipped']}",
        ]
        for item in result["details"]["installed"]:
            lines.append(f"  ✓ {item['tool']} ({item.get('method', '?')})")
        for item in result["details"]["failed"][:10]:
            lines.append(f"  ✗ {item['tool']}: {item.get('error', '')[:80]}")
        self.tools._detect_installed()
        return {"stdout": "\n".join(lines), "stderr": "", "exit_code": 0, "duration": 0, "command": f"install_all_missing(max={max_tools})"}

    def _intercept_check_status(self, args: dict) -> Dict[str, Any]:
        """Intercept check_tool_status — return install status for a tool."""
        tool_name = args.get("tool_name", "")
        if not tool_name:
            return {"stdout": "", "stderr": "No tool_name specified", "exit_code": 1, "duration": 0, "command": "check_tool_status(?)"}
        status = self.installer.check_tool_status(tool_name)
        lines = [
            f"Tool: {status['tool_name']}",
            f"Binary: {status['binary']}",
            f"Installed: {status['installed']}",
            f"Path: {status['path'] or 'N/A'}",
            f"Installable: {status['installable']}",
            f"Install method: {status['install_method'] or 'N/A'}",
            f"Category: {status['category']}",
            f"Description: {status['description']}",
        ]
        return {"stdout": "\n".join(lines), "stderr": "", "exit_code": 0, "duration": 0, "command": f"check_tool_status({tool_name})"}

    def _intercept_msf_auto_exploit(self, args: dict) -> Dict[str, Any]:
        """Run the full MSF auto-exploit pipeline (Python-level, not shell).
        Returns a normalized tool result dict compatible with the orchestrator loop."""
        from core.msf_generator import MetasploitScriptGenerator
        msf = MetasploitScriptGenerator(llm=self.llm, tools=self.tools, config=self.config)
        result = msf.auto_exploit(
            nmap_output=args.get("nmap_output", ""),
            lhost=args.get("lhost", "0.0.0.0"),
            lport=int(args.get("lport", 4444)),
            payload=args.get("payload", ""),
            objective=args.get("objective", ""),
            execute=bool(args.get("execute", False)),
        )
        # Normalize to orchestrator tool-result format
        stdout_lines = []
        if result.get("services"):
            stdout_lines.append(f"Parsed {len(result['services'])} services")
        if result.get("exploits_found"):
            stdout_lines.append(f"Found {result['exploits_found']} matching exploits")
        if result.get("validation"):
            v = result["validation"]
            stdout_lines.append(f"Validation: {'PASS' if v.get('valid') else 'WARN'} — {v.get('warnings', [])}")
        if result.get("rc_path"):
            stdout_lines.append(f"RC script saved: {result['rc_path']}")
        if result.get("execution"):
            ex = result["execution"]
            stdout_lines.append(f"Execution: exit_code={ex.get('exit_code')}, duration={ex.get('duration')}s")
            if ex.get("stdout"):
                stdout_lines.append(f"MSF Output (first 2000 chars):\n{ex['stdout'][:2000]}")
        if result.get("error"):
            return {"stdout": "", "stderr": result["error"], "exit_code": -1, "duration": 0}
        return {
            "stdout": "\n".join(stdout_lines) + (f"\n\nRC Content:\n{result.get('rc_content', '')[:3000]}" if result.get('rc_content') else ""),
            "stderr": "",
            "exit_code": 0,
            "duration": 0,
        }

    def execute_direct(self, tool_name: str, args: dict, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute a tool directly without LLM reasoning."""
        sid = session_id or self._current_session
        safe, reason = self.safety.check_tool(tool_name, args)
        if not safe:
            return {"status": "blocked", "reason": reason}

        # Intercept Python-level tools that bypass the shell command builder
        if tool_name == "msf_auto_exploit":
            return self._intercept_msf_auto_exploit(args)

        result = self.tools.execute(tool_name, args)
        if sid:
            self.sessions.log_command(sid, tool_name, args, result)
        return result

    # ═══════════════════════════════════════════════════════════════
    # STATUS (v4.0 — includes Assassin's Blade stats)
    # ═══════════════════════════════════════════════════════════════

    def get_status(self) -> Dict[str, Any]:
        """Get current harness status with all phase stats."""
        return {
            "running": self._running,
            "session": self._current_session,
            "llm_connected": self.llm.is_connected(),
            "tools_available": self.tools.get_available_count(),
            "tools_total": self.tools.get_total_count(),
            "token_usage": self.llm.get_usage(),
            "autonomous": self._autonomous,
            "cache": self.runner.cache.get_stats(),
            "context": self.context.get_stats(),
            "tactics": self.tactics.get_stats(),
            "prioritizer": self.prioritizer.get_stats(),
            "parallel": self.parallel.get_stats(),
            "tool_scorer": self.scorer.get_stats(),
            "vector_memory": self.memory.get_stats(),
            "knowledge_base": self.kb.get_stats(),
        }