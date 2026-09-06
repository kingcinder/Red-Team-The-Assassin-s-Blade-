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
from core.capture_state import CaptureStateStore, default_sniff_args, needs_interface
from core.injection_defense import sanitize_for_llm, sanitize_tool_output
from core.autonomous import AutonomousAgent
from core.prompt_builder import PromptBuilder
from core.tool_interceptor import ToolInterceptor, INTERCEPTED_TOOLS as PB_INTERCEPTED_TOOLS

logger = logging.getLogger("redteam.orchestrator")

# ── Iteration limits ──
DEFAULT_MAX_ITERATIONS = 10
AUTONOMOUS_MAX_ITERATIONS = 500  # Truly autonomous: let the LLM run until done
MAX_CONSECUTIVE_SAME_TOOL = 3   # stuck-detection threshold
MAX_SELF_CORRECTIONS = 2        # re-prompts for malformed output
# Autonomous mode: how many consecutive prose-only (no tool_call) responses to
# tolerate before telling the model to wrap up. Autonomous mode must keep making
# turns, but a model that refuses to act forever would burn the whole budget on
# empty chat, so cap the streak.
AUTONOMOUS_PROSE_NUDGE_LIMIT = 3

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

# ── Allowed-tool enforcement (v6.3.4) ──
# Curated map of common unregistered / LLM-mangled tool names to the nearest
# REGISTERED tool(s). These are SUGGESTIONS offered when an unregistered tool
# is refused — the invalid call is never silently executed.
TOOL_ALIASES = {
    "arp_spoof": ["ettercap_mitm", "bettercap_mitm"],
    "arp_poison": ["ettercap_mitm", "bettercap_mitm"],
    "arp_poisoning": ["ettercap_mitm", "bettercap_mitm"],
    "arpspoof": ["ettercap_mitm", "bettercap_mitm"],
    "dns_spoof": ["ettercap_mitm", "bettercap_mitm"],
    "dns_spoofing": ["ettercap_mitm", "bettercap_mitm"],
    "sniff": ["tshark_capture", "tcpdump_capture"],
    "packet_capture": ["tcpdump_capture", "tshark_capture"],
    "deauth_attack": ["aireplay_attack"],
    "wifi_deauth": ["aireplay_attack"],
    "wps_attack": ["reaver_attack"],
    "wps_pin": ["reaver_attack"],
    "wpa_crack": ["wifite_auto", "aircrack_crack"],
    "start_monitor": ["monitor_mode_enable"],
    "stop_monitor": ["monitor_mode_disable"],
    "set_monitor": ["monitor_mode_enable"],
}

# Keyword → nearest registered tools, matched when a wholly-unregistered name
# isn't in TOOL_ALIASES but clearly relates to a known category.
TOOL_ALIAS_KEYWORDS = {
    ("arp", "spoof", "poison", "mitm"): ["ettercap_mitm", "bettercap_mitm"],
    ("packet", "sniff", "capture"): ["tshark_capture", "tcpdump_capture"],
    ("deauth",): ["aireplay_attack"],
    ("wps",): ["reaver_attack"],
    ("wifi", "wpa", "wireless"): ["wifite_auto", "aircrack_crack"],
    # NOTE: NO loose "monitor" keyword — any name containing "monitor" would
    # get BOTH enable+disable as suggestions (e.g. "monitor_status"), which is
    # misleading. Exact aliases cover start_monitor/stop_monitor/set_monitor.
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
        scorer_dir = config.get("harness", {}).get("session_dir", "./sessions")
        self.scorer = ToolScorer(scorer_dir)
        self.memory = VectorMemory(scorer_dir)
        # v6.3: backend mirror of the cockpit's capture-interface selection.
        # API/CLI/autonomous paths that omit the interface get it defaulted
        # here from the last-used adapter, so the cockpit isn't the only path
        # that remembers which adapter is the engagement's capture interface.
        self.capture_state = CaptureStateStore(scorer_dir)
        self.installer = ToolInstaller(self.tools)
        self.prompts = PromptBuilder(self.tools, self.scorer, self.memory)
        self.interceptor = ToolInterceptor(self.tools, self.installer, config,
                                            llm=self.llm)
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
        # v5.5: tactical engine can now ground suggestions in prior sessions
        self.tactics.set_memory(self.memory)
        # v5.6: offline knowledge base — CVE / ATT&CK / exploit signatures /
        # remediation playbooks, indexed for fast local retrieval.
        self.kb = KnowledgeBase()
        self.autonomous_agent = None  # Created on demand

    # ═══════════════════════════════════════════════════════════════
    # PROMPT BUILDING
    # Delegate to core.prompt_builder (candidate #2).
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
        system_prompt = self.prompts.dynamic("recon")
        self.sessions.add_message(session_id, "system", system_prompt)

        # Inject few-shot examples
        for msg in self.prompts.few_shot_messages("recon"):
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
        # Each API call without an explicit session_id gets a fresh session
        # to prevent stale messages from prior engagements polluting the context.
        sid = session_id if session_id else self.new_session()

        self.sessions.add_message(sid, "user", user_prompt)

        # ── Vector Memory: inject prior findings for targets in prompt ──
        memory_context = self.prompts.memory_context(user_prompt)
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
        prose_only_streak = 0  # consecutive prose-only responses in autonomous mode

        while iteration < max_iterations:
            iteration += 1
            step_result = self._run_iteration(sid, steps, stream=stream)
            steps.append(step_result)

            # Any real tool call resets the prose-only guard.
            if step_result.get("tool_calls"):
                prose_only_streak = 0

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

            action = step_result.get("action")

            # Completion: the loop must STOP when the LLM signals done (this was
            # missing entirely — autonomous runs used to burn the full 500-
            # iteration budget even after the model finished). Report generation
            # happens after the loop.
            if action == "complete":
                break

            if action in ("waiting_for_user", "waiting_for_approval"):
                if not self._autonomous:
                    break
                # Autonomous mode: a prose-only response (no tool_call and not a
                # completion) must NOT halt the engagement — that's what made it
                # look like "autonomous does nothing." Nudge the model to keep
                # driving 100+ turns in sequence by emitting its next tool_call.
                # But a model that NEVER acts (pure prose, no tools, past the
                # limit) should be wrapped up, not allowed to burn the whole
                # budget on empty chat.
                prose_only_streak += 1
                if prose_only_streak > AUTONOMOUS_PROSE_NUDGE_LIMIT:
                    self.sessions.add_message(sid, "system",
                        "[HARNESS] Several consecutive responses with no tool call. "
                        "Treating the engagement as complete — emitting final summary.")
                    step_result["action"] = "complete"
                    break
                self.sessions.add_message(sid, "system",
                    "[HARNESS] Continue autonomously — do not wait for user input. "
                    "Produce your next JSON tool_call to keep going.")
                continue
            # In autonomous mode, don't stop on errors — give the LLM a chance
            # to self-correct with the error context in its next turn.
            if step_result.get("error"):
                if not self._autonomous:
                    break
                prose_only_streak = 0
                logger.warning(f"Autonomous mode: continuing after error: {step_result['error'][:120]}")
                # Don't break — let the loop continue so the LLM sees the error
                # and can try a different approach.

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
        logger.info(f"Engagement finished: {len(steps)} steps, action={steps[-1].get('action') if steps else None}")

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
                "Create a complete step-by-step penetration testing plan. Output as JSON with "
                "a 'plan' array, one step per phase of the requested chain, preserving the "
                "user's order. Each step has: step number, tool name, description, and target. "
                "Only include available tools. Do not return a partial plan or repeat the plan."
            )
            messages = [
                {"role": "system", "content": self.prompts.dynamic("recon")},
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
            if plan and isinstance(plan.get("plan"), list):
                valid_plan = [step for step in plan["plan"]
                              if isinstance(step, dict)
                              and isinstance(step.get("tool"), str)
                              and isinstance(step.get("description"), str)]
                if valid_plan:
                    plan_text = json.dumps(valid_plan, indent=2)
                    self.sessions.add_message(session_id, "system",
                        f"[PLAN] Engagement strategy:\n{plan_text}")
                    logger.info(f"Plan generated: {len(valid_plan)} steps")
                    return valid_plan
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

            # ── Backend-failure guard ──
            # A backend error string ("Cannot connect to LLM...", "LLM returned
            # status 400/500...") must NEVER be stored as an assistant message:
            # llama-server rejects requests whose last two messages are both
            # assistant ("Cannot have 2 or more assistant messages at the end of
            # the list"), so one transient failure used to wedge the whole
            # session into a permanent error loop (observed: 67 consecutive
            # 400s in a single engagement). Store it as a system message and
            # fail the step cleanly so the loop can break / retry.
            if llm_response.startswith("[ERROR]"):
                err_text = llm_response[:500]
                self.sessions.add_message(
                    session_id, "system",
                    f"[HARNESS] LLM backend error: {err_text}")
                step_data["action"] = "error"
                step_data["error"] = err_text
                self._emit("on_error", {"session_id": session_id, "error": err_text})
                self._emit("on_step_complete", {"session_id": session_id, "step": step_data})
                return step_data

            # Parse tool calls and bind capture-interface placeholders to the
            # operator's explicit interface when one is present in the session.
            tool_calls = self._parse_tool_calls(llm_response)
            selected_interface = self._selected_interface(session_id)
            for tc in tool_calls:
                if selected_interface and tc["args"].get("interface") in {"eth0", "wlan0", "wlan0mon", "{{interface}}"}:
                    tc["args"]["interface"] = selected_interface

            if not tool_calls:
                self.sessions.add_message(session_id, "assistant", llm_response)
                step_data["action"] = "complete" if self._is_engagement_complete(llm_response) else "waiting_for_user"
                return step_data

            # ── Validate & execute tool calls ──
            valid_tool_calls = []
            for tc in tool_calls:
                tool_name = tc.get("tool", "")
                tool_args = tc.get("args", {})

                # ── Allowed-tool enforcement (v6.3.4) ──
                # An UNREGISTERED tool is REFUSED immediately — never silently
                # auto-corrected to a guessed binary and executed (that previously
                # produced broken calls like an unimplemented `arp_spoof`). The
                # nearest registered alternative(s) are surfaced as guidance so
                # the LLM/operator can retry with a valid tool.
                if tool_name not in self.tools.get_all_tools():
                    recs = self._recommend_tool(tool_name)
                    if recs:
                        suggested = ", ".join(f"'{r}'" for r in recs)
                        logger.info(f"Refused unregistered tool '{tool_name}', suggested {suggested}")
                        self.sessions.add_message(session_id, "system",
                            f"[HARNESS] Tool '{tool_name}' is not a registered tool and was REFUSED. "
                            f"Nearest alternative(s): {suggested}. Retry with one of those.")
                        step_data["results"].append({
                            "tool": tool_name, "status": "refused",
                            "reason": f"Unregistered tool; suggested {suggested}",
                        })
                    else:
                        available = ', '.join(sorted(self.tools.get_all_tools().keys())[:30])
                        self.sessions.add_message(session_id, "system",
                            f"[HARNESS] Tool '{tool_name}' is not a registered tool and was REFUSED. "
                            f"Available tools: {available}")
                        step_data["results"].append({
                            "tool": tool_name, "status": "refused",
                            "reason": "Unregistered tool",
                        })
                    continue

                # Validate required args — inject defaults when possible
                tool_def = self.tools.get_all_tools().get(tool_name)
                if tool_def:
                    missing = [p for p, pi in tool_def.parameters.items()
                               if pi.get("required") and p not in tool_args]
                    if missing:
                        # Try to fill 'interface' from selected interface
                        if "interface" in missing and selected_interface:
                            tool_args["interface"] = selected_interface
                            missing.remove("interface")
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

            for i, tc in enumerate(valid_tool_calls):
                tool_name = tc["tool"]
                tool_args = tc["args"]

                # Safety check (runs before dispatch)
                safe, reason = self.safety.check_tool(tool_name, tool_args)
                if not safe:
                    blocked_results.append((tc, tool_name, tool_args, reason))
                    continue

                self._emit("on_tool_start", {"session_id": session_id, "tool": tool_name, "args": tool_args})

                if tool_name in PB_INTERCEPTED_TOOLS:
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
                result = self.interceptor.dispatch(tool_name, tool_args)
                elapsed = time.time() - start_time
                if "command" not in result:
                    result["command"] = tool_name
                intercepted_results.append((tc, result, elapsed, orig_idx))

            # ── Phase B: Execute normal tools in parallel ──
            if parallel_tcs:
                if len(parallel_tcs) == 1:
                    # Single tool — still route through HardenedToolRunner for
                    # injection rejection, arg validation, and audit trail (#3 fix)
                    tc, tool_name, tool_args, orig_idx = parallel_tcs[0]
                    start_time = time.time()
                    result = self.runner.execute(tool_name, tool_args)
                    elapsed = time.time() - start_time
                    if "command" not in result:
                        result["command"] = tool_name
                    parallel_results = [(tc, result, elapsed, orig_idx)]
                else:
                    logger.info(f"Parallel execution: {len(parallel_tcs)} tools simultaneously")
                    # Build call dicts for ParallelExecutor
                    # entries are (tc, tool_name, tool_args, orig_idx)
                    calls = [{"tool": tn, "args": ta} for _, tn, ta, _ in parallel_tcs]
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
                self.prompts.ingest_findings({"results": [tool_result]}, session_id)

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
                # On failure, include stderr so the LLM can diagnose and self-correct
                if result['exit_code'] != 0 and raw_stderr:
                    result_msg += f"\nStderr: {raw_stderr[:1000]}"
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
        re-prompt to get a valid response. Returns (response_str, correction_count).

        In autonomous mode, retries up to 5 times (vs 2 in normal mode) because
        the LLM has more context to self-correct.
        """
        corrections = 0
        max_attempts = 5 if self._autonomous else (MAX_SELF_CORRECTIONS + 1)

        for attempt in range(max_attempts):
            if stream:
                response = self._accumulate_stream(messages)
            else:
                response = self.llm.chat(messages, cache_prompt=True)

            if attempt >= max_attempts - 1:
                return response, corrections

            # Check if response is valid
            has_tool_call = bool(self._parse_tool_calls(response))
            has_content = len(response.strip()) > 20

            if has_tool_call or has_content:
                return response, corrections

            # Backend error — don't re-prompt (will be handled by caller)
            if response.startswith("[ERROR]"):
                return response, corrections

            # Empty/malformed — re-prompt with escalating guidance
            corrections += 1
            logger.warning(f"LLM returned empty/malformed response (attempt {attempt+1})")
            if attempt == 0:
                messages.append({"role": "system",
                    "content": "[HARNESS] Your response was empty or invalid. "
                               "Respond with a JSON tool_call or your analysis text."})
            else:
                # After first retry, provide the tool list as concrete guidance
                available = ', '.join(sorted(self.tools.get_all_tools().keys())[:25])
                messages.append({"role": "system",
                    "content": f"[HARNESS] Your last response was invalid. "
                               f"Choose ONE tool and respond with: {{\"tool_call\": {{\"tool\": \"<name>\", \"args\": {{}}}}}} "
                               f"Available tools: {available}"})

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
        logger.info(f"Stream accumulated: {len(accumulated)} chars")
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
                {"role": "system", "content": self.prompts.dynamic("postex")},
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
            new_prompt = self.prompts.dynamic("exploit")
            self.sessions.add_message(session_id, "system", new_prompt)
            logger.info("Phase transition: → EXPLOIT")

        if any(t in tools_run for t in ["crackmapexec_exec", "impacket_tools", "mimikatz_dump",
                                         "bloodhound_analyze", "evil_winrm"]):
            if "## Current Engagement Phase: POSTEX" not in current_system:
                new_prompt = self.prompts.dynamic("postex")
                self.sessions.add_message(session_id, "system", new_prompt)
                logger.info("Phase transition: → POSTEX")

    # ═══════════════════════════════════════════════════════════════
    # JSON PARSING
    # ═══════════════════════════════════════════════════════════════

    def _selected_interface(self, session_id: str) -> Optional[str]:
        """Return the explicit capture interface recorded for this session.

        Searches backwards through session messages AND the tool log for a
        real (non-generic) interface name.  Checks the most recent successful
        tool result first (the LLM often calls interface_discovery early),
        then falls back to operator-injected interface instructions.
        """
        _GENERIC = {"eth0", "wlan0", "wlan0mon", "lo", "{{interface}}"}
        # 1. Check recent tool results for a discovered interface
        session = self.sessions._load(session_id) if session_id else None
        if session:
            for entry in reversed(session.get("tool_log", [])):
                stdout = (entry.get("result", {}) or {}).get("stdout", "")
                # interface_discovery returns JSON with interface names
                if "wlx" in stdout or "wlp" in stdout or "wlan" in stdout:
                    # Extract the first wireless interface name
                    m = re.search(r'"ifname"\s*:\s*"(wl[xp]\S+)"', stdout)
                    if m:
                        return m.group(1)
                    m = re.search(r'(wl[xp]\S+)', stdout)
                    if m:
                        return m.group(1)
        # 2. Search messages backwards for an operator-selected interface
        for message in reversed(self.sessions.get_messages(session_id)):
            content = message.get("content", "")
            match = re.search(r"(?:Selected capture interface|interface)\s*[:=]\s*([A-Za-z0-9_.:-]+)", content, re.IGNORECASE)
            if match and match.group(1) not in _GENERIC:
                return match.group(1)
        return None

    def _parse_json(self, text: str) -> Optional[dict]:
        """Robust JSON extraction from LLM output.
        Tolerates trailing commas (Qwen3.x emits ``{"tool": "x",}``)."""
        for candidate in [text]:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
        # Try ```json blocks
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            for candidate in [m.group(1), self._clean_json(m.group(1))]:
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass
        # Try first { ... } pair
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            for candidate in [m.group(0), self._clean_json(m.group(0))]:
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass
        return None

    def _parse_tool_calls(self, llm_response: str) -> list:
        """Parse tool call JSON from the LLM response.

        Handles concatenated and multi-object responses: the LLM often emits
        ``{"tool_calls":[...]}{"plan":[...]}`` or multiple JSON blocks.
        This parser extracts ALL JSON objects from the full response text,
        then pulls tool calls from each.

        Formats recognized (order of extraction):
          1. XML <tool_call>...</tool_call> blocks (Qwen native format)
          2. JSON inside ```json fences
          3. Raw JSON objects (brace-depth tracked)

        Per-object formats:
          - {"tool_call": {"tool": "...", "args": {}}}  (single)
          - {"tool_calls": [{"tool": "...", ...}, ...]}   (batch)
          - {"tool": "...", "args": {}}                    (bare single)
        """
        tool_calls = []

        # ── Strip <think>...</think> wrapping (Qwen thinking tokens) ──
        clean = re.sub(r'<think>.*?</think>', '', llm_response, flags=re.DOTALL).strip()

        # ── 1. XML <tool_call> format (Qwen native) ──
        for xml_match in re.finditer(r'<tool_call>(.*?)</tool_call>', clean, re.DOTALL):
            xml_block = xml_match.group(1)
            # Extract <name> and <arguments> tags
            name_m = re.search(r'<name>(.*?)</name>', xml_block, re.DOTALL)
            args_m = re.search(r'<arguments>(.*?)</arguments>', xml_block, re.DOTALL)
            if name_m:
                tool_name = name_m.group(1).strip()
                tool_args = {}
                if args_m:
                    try:
                        tool_args = json.loads(args_m.group(1).strip())
                    except json.JSONDecodeError:
                        # Try extracting JSON from inside arguments block
                        for obj in self._extract_all_json_objects(args_m.group(1)):
                            if isinstance(obj, dict):
                                tool_args = obj
                                break
                tool_calls.append({"tool": tool_name, "args": tool_args})

        # ── 2. Extract ALL JSON objects from the full response ──
        # This handles concatenated output like {"tool_calls":[...]}{"plan":[...]}
        for data in self._extract_all_json_objects(clean):
            if not isinstance(data, dict):
                continue
            # Singular: tool_call or bare tool
            if "tool_call" in data and isinstance(data["tool_call"], dict):
                tc = data["tool_call"]
                if isinstance(tc.get("tool"), str) and isinstance(tc.get("args", {}), dict):
                    tool_calls.append({"tool": tc["tool"], "args": tc.get("args", {})})
            elif isinstance(data.get("tool"), str) and isinstance(data.get("args", {}), dict):
                tool_calls.append({"tool": data["tool"], "args": data.get("args", {})})
            # Plural: tool_calls array
            if "tool_calls" in data and isinstance(data["tool_calls"], list):
                for tc in data["tool_calls"]:
                    if (isinstance(tc, dict) and isinstance(tc.get("tool"), str)
                            and isinstance(tc.get("args", {}), dict)):
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

    @staticmethod
    def _clean_json(s: str) -> str:
        """Strip trailing commas before } or ] — Qwen models emit these."""
        return re.sub(r',\s*([}\]])', r'\1', s)

    def _extract_all_json_objects(self, text: str) -> list:
        """Extract every top-level JSON object from text.

        Handles concatenated JSON like ``{...}{...}``, JSON inside markdown
        fences, and mixed prose + JSON.  Uses brace-depth tracking to find
        balanced objects so nested objects don't get split.
        Tolerates trailing commas (Qwen3.x emits ``{"tool": "x",}``).
        """
        results = []
        i = 0
        n = len(text)
        while i < n:
            if text[i] == '{':
                depth = 0
                start = i
                in_string = False
                escape_next = False
                for j in range(i, n):
                    c = text[j]
                    if escape_next:
                        escape_next = False
                        continue
                    if c == '\\' and in_string:
                        escape_next = True
                        continue
                    if c == '"' and not escape_next:
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            raw = text[start:j + 1]
                            try:
                                obj = json.loads(raw)
                            except json.JSONDecodeError:
                                try:
                                    obj = json.loads(self._clean_json(raw))
                                except json.JSONDecodeError:
                                    obj = None
                            if obj is not None:
                                results.append(obj)
                            i = j + 1
                            break
                else:
                    # Unbalanced braces — try the remaining text
                    raw = text[start:]
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        try:
                            obj = json.loads(self._clean_json(raw))
                        except json.JSONDecodeError:
                            obj = None
                    if obj is not None:
                        results.append(obj)
                    break
            else:
                i += 1
        return results

    def _fuzzy_match_tool(self, name: str) -> Optional[str]:
        """Find the closest registered tool name.

        Uses three strategies in order:
          1. Substring containment (shortest match wins)
          2. Token overlap on underscore-separated parts
          3. Levenshtein edit distance with generous threshold
        Returns the best match or None.
        """
        all_tools = list(self.tools.get_all_tools().keys())
        if not all_tools:
            return None
        lower = name.lower()

        # 1. Exact substring (e.g. "kismet" → "kismet_scan")
        substrings = [t for t in all_tools if lower in t.lower()]
        if substrings:
            return min(substrings, key=len)
        # Reverse: registered name contains the input
        reverse = [t for t in all_tools if t.lower() in lower]
        if reverse:
            return min(reverse, key=len)

        # 2. Token overlap on underscore-split parts
        input_tokens = set(lower.split("_"))
        best_token, best_token_score = None, 0
        for t in all_tools:
            tool_tokens = set(t.lower().split("_"))
            overlap = len(input_tokens & tool_tokens)
            if overlap > best_token_score:
                best_token_score = overlap
                best_token = t
        if best_token and best_token_score >= 1:
            return best_token

        # 3. Levenshtein distance
        best_lev, best_dist = None, len(name)
        for t in all_tools:
            dist = self._levenshtein(lower, t.lower())
            if dist < best_dist:
                best_dist = dist
                best_lev = t
        threshold = max(3, min(len(name), 6) // 2)
        if best_lev and best_dist <= threshold:
            return best_lev
        return None

    def _recommend_tool(self, name: str) -> List[str]:
        """Return nearest REGISTERED alternative(s) for an unregistered tool name.

        Used exclusively for *refusal guidance*: the invalid tool call is never
        executed; instead the operator/LLM is told which registered tools to
        retry with. Priority:
          1. Exact curated alias (e.g. ``arp_spoof`` → bettercap_mitm/ettercap_mitm)
          2. Keyword-category match on the name (e.g. any name containing "arp"
             resolves to the MITM/ARP-spoof tools)
          3. Fuzzy match (never empty-backed when a confident one exists)
        Returns an empty list when nothing sensible maps.
        """
        if not name or not isinstance(name, str):
            return []
        lower = name.lower()
        if lower in TOOL_ALIASES:
            return list(TOOL_ALIASES[lower])
        for keywords, suggestions in TOOL_ALIAS_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return list(suggestions)
        # Confident fallback ONLY: substring containment (e.g. "nmap"→"nmap_scan").
        # The loose token-overlap/levenshtein heuristics suggest WRONG tools for
        # genuinely-bogus names (e.g. any name sharing the token "tool"), which is
        # worse than refusing with the full registered list.
        all_tools = list(self.tools.get_all_tools().keys())
        sub = [t for t in all_tools if lower in t.lower()]
        if sub:
            return [min(sub, key=len)]
        return []

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return Orchestrator._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

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

            # Build findings summary — prompt built by core.report (single writer)
            from core.report import report_prompt as build_report_prompt
            report_prompt = build_report_prompt(findings, tool_log)
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

        # Resolve template path — accepts exact filename, filename stem, or
        # display ``name:`` field (e.g. "Evil Twin & WPA2 Handshake Capture
        # Chain" -> evil_twin_chain.yaml). resolve_template is path-traversal
        # safe; the realpath guard below is kept as defense in depth.
        template_path = WorkflowStateMachine.resolve_template(templates_dir, workflow_name)
        if not template_path:
            return {"error": f"Workflow template not found: {workflow_name} in {templates_dir}",
                    "available": [os.path.basename(p) for p in
                                   WorkflowStateMachine.discover_templates(templates_dir)]}
        real_tpl = os.path.realpath(template_path)
        real_dir = os.path.realpath(templates_dir)
        if not real_tpl.startswith(real_dir + os.sep) and real_tpl != real_dir:
            return {"error": f"Path traversal blocked: {workflow_name}"}

        # Create sandbox + state machine — derive the task-dir name from the
        # RESOLVED file stem (not the raw request, which may be a display name
        # with spaces/&) so task dirs stay consistent with filename launches.
        sandbox_name = os.path.basename(template_path).rsplit(".", 1)[0]
        sandbox = TaskSandbox(sandbox_name, base_dir=tasks_dir)
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
        """Build a combined markdown report for a completed workflow chain.
        Formatting delegated to core.report (single report writer)."""
        from core.report import chain_report

        corr = chain.get("correlation") or {}
        corr_paths = corr.get("paths", [])
        paths_md = self.correlator.paths_to_markdown(corr_paths) if corr_paths else ""
        return chain_report(
            chain_id=chain["chain_id"],
            status=chain["status"],
            links=chain.get("links", []),
            links_count=chain.get("links_count"),
            findings=chain.get("findings", []),
            findings_count=chain.get("findings_count"),
            loop_guard=chain.get("loop_guard", ""),
            correlation_paths=corr_paths,
            paths_markdown=paths_md,
        )

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
        templates_dir = self.config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        # Task dirs are named from the resolved file stem (run_workflow does
        # the same), so resolve display names before listing tasks.
        tpl = WorkflowStateMachine.resolve_template(templates_dir, workflow_name)
        name = os.path.basename(tpl).rsplit(".", 1)[0] if tpl \
            else workflow_name.replace(".yaml", "")
        sandbox = TaskSandbox(name, base_dir=tasks_dir)
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
    # Intercepted Python-level tools (installer + msf) are handled by
    # core.tool_interceptor.ToolInterceptor (candidate #2).
    # ═══════════════════════════════════════════════════════════════

    def execute_direct(self, tool_name: str, args: dict, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute a tool directly without LLM reasoning.

        v6.3: interface-defaulting layer. Wireless/sniffing tools (and any
        tool declaring an `interface` param) that arrive with a blank or
        missing interface get it filled from the last-used capture interface
        (server-side store, mirrored from the cockpit), so API/CLI/autonomous
        callers never silently drop the adapter. Explicit picks are persisted
        to the same store so the last-used adapter follows every path.

        v6.3.1: the same defaulting now covers `channel` (hint from the last
        airodump scan) for wireless/sniffing tools, so one-click captures stay
        one-click. An airodump_capture run also persists its channel/bssid as
        scan hints for subsequent steps. bssid is never auto-injected — it is
        an explicit AP-targeting call.
        """
        sid = session_id or self._current_session

        # ── adapter-typed param defaulting (v6.3 / v6.3.1) ──
        # Only wireless/sniffing tools (or tools declaring these params) touch
        # the store — recon/NSE/postex calls never pay the file-read cost, and
        # an arg named "interface" on a tool that doesn't need one is never
        # persisted.
        tool = self.tools.get_tool(tool_name)
        if tool is not None and needs_interface(tool.category, tool.parameters):
            effective, injected = default_sniff_args(
                args, tool.category, tool.parameters,
                self.capture_state.get(),
                self.capture_state.get_scan())
            if injected:
                logger.info("execute_direct: defaulted %s for %s -> %s",
                            ",".join(sorted(injected)), tool_name, injected)
            # Persist an EXPLICIT interface pick (supplied by the caller, not
            # auto-filled) so later calls (and the cockpit on reload) inherit
            # the adapter chosen by any path — independently of whether a
            # channel hint happened to be injected this call.
            if effective.get("interface") and "interface" not in injected:
                self.capture_state.set(effective["interface"])
            args = effective

            # Persist an explicit channel picked by this call so the next
            # hint reflects the operator's/LLM's actual scan channel.
            if effective.get("channel") and tool_name == "airodump_capture":
                self.capture_state.set_scan(
                    channel=effective.get("channel"),
                    bssid=effective.get("bssid"))

        safe, reason = self.safety.check_tool(tool_name, args)
        if not safe:
            return {"status": "blocked", "reason": reason}

        # Intercept Python-level tools that bypass the shell command builder
        if tool_name in PB_INTERCEPTED_TOOLS:
            result = self.interceptor.dispatch(tool_name, args)
            if sid:
                self.sessions.log_command(sid, tool_name, args, result)
            return result

        result = self.runner.execute(tool_name, args)
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
            "llm_backend": self.llm.backend,
            "llm_host": self.llm.host,
            "llm_port": self.llm.port,
            "llm_model": self.llm.get_loaded_model() if self.llm.is_connected() else None,
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