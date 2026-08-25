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
import threading
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
        }
        self._system_prompt_base = self._build_base_system_prompt()
        wf_cfg = config.get("workflow", {})
        self.scheduler = MultiTargetScheduler(
            self.runner, self.llm,
            templates_dir=wf_cfg.get("templates_dir", "workflows/templates"),
            tasks_dir=wf_cfg.get("tasks_dir", "tasks"),
            max_concurrent=wf_cfg.get("max_concurrent_targets", 3),
            emit=self._emit,
        )
        self.generator = WorkflowGenerator(
            self.llm, self.tools,
            templates_dir=wf_cfg.get("templates_dir", "workflows/templates"),
        )
        self.correlator = FindingCorrelator()

    # ═══════════════════════════════════════════════════════════════
    # SYSTEM PROMPT — Dynamic, phase-aware, installed tools only
    # ═══════════════════════════════════════════════════════════════

    def _build_base_system_prompt(self) -> str:
        """Build the static portion of the system prompt (cache-friendly)."""
        return """You are an expert penetration tester and red-team operator.
You have access to a comprehensive set of security tools through the RedTeam Harness.

## Response Format
When you want to use a tool, respond with EXACTLY this JSON:
{"tool_call": {"tool": "<tool_name>", "args": {"param": "value", ...}}}

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

        return prompt

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

        # ── Phase 4: Reflection step after engagement ──
        if steps and steps[-1].get("action") == "complete" and \
           self.config.get("assassins_blade", {}).get("reasoning_self_evaluate", True):
            self._run_reflection(sid, user_prompt, steps)

        # ── Auto Report Generation ──
        if steps and steps[-1].get("action") == "complete":
            report = self._generate_report(sid)
            self._emit("on_report_generated", {"session_id": sid, "report": report})

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
                f"Based on the user's objective: \"{user_prompt}\"\n\n"
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

            # ── Execute validated tools ──
            for tc in valid_tool_calls:
                tool_name = tc["tool"]
                tool_args = tc["args"]

                # Safety check
                safe, reason = self.safety.check_tool(tool_name, tool_args)
                if not safe:
                    step_data["results"].append({"tool": tool_name, "status": "blocked", "reason": reason})
                    self.sessions.add_message(session_id, "system",
                        f"[HARNESS] Tool '{tool_name}' blocked: {reason}")
                    continue

                self._emit("on_tool_start", {"session_id": session_id, "tool": tool_name, "args": tool_args})

                # Execute
                start_time = time.time()
                result = self.tools.execute(tool_name, tool_args)
                elapsed = time.time() - start_time

                # ── Summarize output before adding to context ──
                raw_stdout = result.get("stdout", "")
                raw_stderr = result.get("stderr", "")
                summary = self.llm.summarize(raw_stdout, context=tool_name)
                short_stderr = raw_stderr[:500] if len(raw_stderr) > 500 else raw_stderr

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

                # Feed summarized output to LLM context
                result_msg = (f"[TOOL: {tool_name}] Exit code: {result['exit_code']} "
                              f"({elapsed:.1f}s)\n{summary}")
                self.sessions.add_message(session_id, "tool_result", result_msg)
                self.sessions.log_command(session_id, tool_name, tool_args, tool_result)

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
                f"You completed a penetration test with the objective: \"{user_prompt}\"\n\n"
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
        """Parse tool call JSON from the LLM response using GBNF-safe parsing."""
        tool_calls = []
        data = self._parse_json(llm_response)
        if not data:
            return tool_calls

        if "tool_call" in data:
            tc = data["tool_call"]
            if isinstance(tc, dict) and "tool" in tc:
                tool_calls.append({"tool": tc.get("tool", ""), "args": tc.get("args", {})})
        elif "tool" in data:
            tool_calls.append({"tool": data.get("tool", ""), "args": data.get("args", {})})

        # Also handle array of tool_calls
        if "tool_calls" in data and isinstance(data["tool_calls"], list):
            for tc in data["tool_calls"]:
                if isinstance(tc, dict) and "tool" in tc:
                    tool_calls.append({"tool": tc.get("tool", ""), "args": tc.get("args", {})})

        return tool_calls

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
                f"## Findings\n{findings_text or 'No findings recorded.'}\n\n"
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

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: CONCURRENT MULTI-TARGET EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def run_multi_workflow(self, workflow_name: str, targets: List[str],
                           variables: Dict[str, Any] = None,
                           max_concurrent: int = None) -> Dict[str, Any]:
        """
        Run a workflow against multiple targets concurrently with per-target
        isolation and combined aggregation.
        """
        return self.scheduler.run(workflow_name, targets or [],
                                  base_variables=variables or {},
                                  max_concurrent=max_concurrent)

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: FINDING CORRELATION + AUTO-REMEDIATION
    # ═══════════════════════════════════════════════════════════════

    def correlate_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Correlate findings into scored attack paths with remediation."""
        paths = self.correlator.correlate(findings or [])
        augmented = self.correlator.augment_findings(findings or [])
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

    # ═══════════════════════════════════════════════════════════════
    # DIRECT TOOL EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def execute_direct(self, tool_name: str, args: dict, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute a tool directly without LLM reasoning."""
        sid = session_id or self._current_session
        safe, reason = self.safety.check_tool(tool_name, args)
        if not safe:
            return {"status": "blocked", "reason": reason}

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
            "cache": self.runner.cache.get_stats(),
            "context": self.context.get_stats(),
            "tactics": self.tactics.get_stats(),
            "prioritizer": self.prioritizer.get_stats(),
            "parallel": self.parallel.get_stats(),
        }