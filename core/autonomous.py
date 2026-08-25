"""
RedTeam Harness — Continuous Autonomous Agent (v4.0 Assassin's Blade)

Fire-and-forget autonomous pentest engine that drives the full kill chain
(recon → vuln → exploit → postex) across discovered targets with:

  - LLM-driven phase transitions (not just tool-name heuristics)
  - Adaptive retry escalation (tool → alternative → LLM-suggested → skip)
  - Per-target state tracking with phase progress
  - Auto-generated reports at campaign completion
  - Pause / resume / stop controls
  - Event emission for dashboard monitoring

Usage:
    agent = AutonomousAgent(orchestrator)
    agent.start(targets=["192.168.1.0/24"], objective="Full compromise")
    # ... agent runs in background thread ...
    agent.pause()
    agent.resume()
    agent.stop()
    status = agent.get_status()
"""
import os
import re
import time
import logging
import threading
from enum import Enum
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("redteam.autonomous")

# ── Kill-chain phases (ordered) ──
KILL_CHAIN = ["recon", "vuln", "exploit", "postex"]

# ── Phase transition criteria ──
# Minimum findings per phase before auto-transitioning
MIN_FINDINGS_PER_PHASE = {
    "recon": 2,    # Need at least ports + services
    "vuln": 1,     # Need at least one vuln indicator
    "exploit": 0,  # Exploit phase runs until success or exhaustion
    "postex": 0,   # Postex runs until done
}

# Max iterations per phase before forced transition
MAX_ITERATIONS_PER_PHASE = {
    "recon": 15,
    "vuln": 20,
    "exploit": 25,
    "postex": 15,
}

# Max consecutive failures before escalating
MAX_CONSECUTIVE_FAILURES = 3

# Adaptive retry escalation levels
RETRY_LEVELS = ["retry", "alternative", "llm_suggest", "skip_phase"]

# Max engagement duration in seconds (1 hour default)
MAX_ENGAGEMENT_DURATION = 3600


class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETE = "complete"
    FAILED = "failed"


class TargetPhase:
    """Tracks the state of a single target through the kill chain."""

    def __init__(self, target: str):
        self.target = target
        self.current_phase = "recon"
        self.phase_index = 0
        self.phase_findings: Dict[str, List[Dict]] = {p: [] for p in KILL_CHAIN}
        self.phase_iterations: Dict[str, int] = {p: 0 for p in KILL_CHAIN}
        self.phase_failures: Dict[str, int] = {p: 0 for p in KILL_CHAIN}
        self.consecutive_failures = 0
        self.retry_level = 0
        self.last_tool = None
        self.last_error = None
        self.completed = False
        self.session_id = None
        self.start_time = None
        self.end_time = None

    def get_phase_findings_count(self) -> int:
        return len(self.phase_findings.get(self.current_phase, []))

    def advance_phase(self) -> Optional[str]:
        """Move to the next kill-chain phase. Returns the new phase or None if done."""
        if self.phase_index < len(KILL_CHAIN) - 1:
            self.phase_index += 1
            self.current_phase = KILL_CHAIN[self.phase_index]
            self.consecutive_failures = 0
            self.retry_level = 0
            logger.info(f"Target {self.target}: phase → {self.current_phase.upper()}")
            return self.current_phase
        else:
            self.completed = True
            self.end_time = datetime.now().isoformat()
            logger.info(f"Target {self.target}: ALL PHASES COMPLETE")
            return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "current_phase": self.current_phase,
            "phase_index": self.phase_index,
            "phase_progress": {
                p: {"findings": len(self.phase_findings.get(p, [])),
                    "iterations": self.phase_iterations.get(p, 0),
                    "failures": self.phase_failures.get(p, 0)}
                for p in KILL_CHAIN
            },
            "completed": self.completed,
            "session_id": self.session_id,
            "consecutive_failures": self.consecutive_failures,
            "retry_level": retry_level_name(self.retry_level),
        }


def retry_level_name(level: int) -> str:
    if 0 <= level < len(RETRY_LEVELS):
        return RETRY_LEVELS[level]
    return "exhausted"


class AutonomousAgent:
    """
    Continuous autonomous pentest engine.

    Drives each target through recon → vuln → exploit → postex, using
    the LLM for planning and the TacticalEngine for rule-based next actions.
    Supports pause/resume/stop and emits events for dashboard monitoring.
    """

    def __init__(self, orchestrator):
        self.orch = orchestrator
        self.state = AgentState.IDLE
        self._targets: List[str] = []
        self._target_phases: Dict[str, TargetPhase] = {}
        self._objective = ""
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused initially

        # Callbacks for events
        self._callbacks: Dict[str, List[Callable]] = {
            "on_phase_start": [],
            "on_phase_complete": [],
            "on_target_complete": [],
            "on_engagement_complete": [],
            "on_retry_escalation": [],
            "on_error": [],
            "on_status_update": [],
            "on_report_generated": [],
        }

        # Check execute_direct availability
        self._has_execute_direct = hasattr(self.orch, 'execute_direct')

        # Stats
        self._start_time = None
        self._total_steps = 0
        self._total_findings = 0
        self._report_path = None

    # ═══════════════════════════════════════════════════════════════
    # PUBLIC API
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
                logger.error(f"Autonomous callback error for {event}: {e}")

    def start(self, targets: List[str], objective: str = "Full penetration test",
              resume: bool = False):
        """
        Start the autonomous engagement against one or more targets.
        Runs in a background thread — fire-and-forget.
        """
        with self._lock:
            if self.state == AgentState.RUNNING:
                logger.warning("Autonomous agent already running")
                return {"status": "already_running"}

            self._targets = list(targets)
            self._objective = objective
            self._start_time = datetime.now().isoformat()
            self._total_steps = 0
            self._total_findings = 0
            self._report_path = None

            # Initialize per-target state
            self._target_phases = {}
            for t in targets:
                tp = TargetPhase(t)
                tp.start_time = self._start_time
                self._target_phases[t] = tp

            self.state = AgentState.RUNNING
            self._pause_event.set()

        logger.info(f"Autonomous agent started: {len(targets)} targets, "
                    f"objective='{objective}'")

        self._thread = threading.Thread(
            target=self._run_loop, daemon=True,
            name="autonomous-agent"
        )
        self._thread.start()

        self._emit("on_status_update", self.get_status())
        return {"status": "started", "targets": targets, "objective": objective}

    def pause(self):
        """Pause the autonomous agent (waits for current step to finish)."""
        with self._lock:
            if self.state != AgentState.RUNNING:
                return {"status": "not_running"}
            self.state = AgentState.PAUSED
            self._pause_event.clear()
        logger.info("Autonomous agent paused")
        self._emit("on_status_update", self.get_status())
        return {"status": "paused"}

    def resume(self):
        """Resume a paused autonomous agent."""
        with self._lock:
            if self.state != AgentState.PAUSED:
                return {"status": "not_paused"}
            self.state = AgentState.RUNNING
            self._pause_event.set()
        logger.info("Autonomous agent resumed")
        self._emit("on_status_update", self.get_status())
        return {"status": "resumed"}

    def stop(self):
        """Stop the autonomous agent gracefully."""
        with self._lock:
            if self.state == AgentState.STOPPING:
                return {"status": "already_stopping"}
            if self.state not in (AgentState.RUNNING, AgentState.PAUSED):
                return {"status": "not_running"}
            self.state = AgentState.STOPPING
            self._pause_event.set()  # Unblock if paused
        logger.info("Autonomous agent stopping...")
        self._emit("on_status_update", self.get_status())
        return {"status": "stopping"}

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status of the autonomous engagement."""
        with self._lock:
            targets_status = {}
            completed = 0
            total_findings = 0
            for t, tp in self._target_phases.items():
                targets_status[t] = tp.to_dict()
                if tp.completed:
                    completed += 1
                total_findings += sum(
                    len(v) for v in tp.phase_findings.values()
                )

            return {
                "state": self.state.value,
                "objective": self._objective,
                "targets": self._targets,
                "targets_count": len(self._targets),
                "targets_completed": completed,
                "total_findings": total_findings,
                "total_steps": self._total_steps,
                "start_time": self._start_time,
                "report_path": self._report_path,
                "targets_detail": targets_status,
            }

    # ═══════════════════════════════════════════════════════════════
    # MAIN ENGAGEMENT LOOP
    # ═══════════════════════════════════════════════════════════════

    def _run_loop(self):
        """Main loop: drives all targets through the kill chain."""
        loop_start = time.time()
        try:
            for target in self._targets:
                if self.state == AgentState.STOPPING:
                    break
                # Engagement timeout check
                elapsed = time.time() - loop_start
                if elapsed > MAX_ENGAGEMENT_DURATION:
                    logger.warning(f"Engagement timeout ({MAX_ENGAGEMENT_DURATION}s) — forcing completion")
                    break

                tp = self._target_phases[target]
                self._drive_target(tp)

            # ── Completion ──
            with self._lock:
                all_done = all(tp.completed for tp in self._target_phases.values())
                if self.state != AgentState.STOPPING:
                    self.state = AgentState.COMPLETE if all_done else AgentState.FAILED

            # ── Fire-and-forget report ──
            self._generate_campaign_report()

            self._emit("on_engagement_complete", self.get_status())
            logger.info(f"Autonomous agent finished: {self.state.value}")

        except Exception as e:
            logger.error(f"Autonomous agent error: {e}", exc_info=True)
            with self._lock:
                self.state = AgentState.FAILED
            self._emit("on_error", {"error": str(e)})
            self._emit("on_status_update", self.get_status())

    def _drive_target(self, tp: TargetPhase):
        """Drive a single target through all kill-chain phases."""
        logger.info(f"═══ Engaging target: {tp.target} ═══")

        # Create a session for this target
        tp.session_id = self.orch.new_session(f"autonomous-{tp.target}")

        # Build the initial objective prompt for this target
        initial_prompt = (
            f"Autonomous penetration test of {tp.target}.\n"
            f"Objective: {self._objective}\n"
            f"Start with reconnaissance — discover hosts, ports, and services."
        )

        # Inject the prompt into the session
        self.orch.sessions.add_message(tp.session_id, "user", initial_prompt)

        # Run through each phase
        while tp.current_phase and not tp.completed:
            if self.state == AgentState.STOPPING:
                break

            # Pause gate with timeout
            self._pause_event.wait(timeout=2.0)
            if self.state == AgentState.STOPPING:
                break

            self._emit("on_phase_start", {
                "target": tp.target,
                "phase": tp.current_phase,
                "phase_index": tp.phase_index,
            })

            self._drive_phase(tp)

            if tp.completed:
                break

            if self.state == AgentState.STOPPING:
                break

            # Check if we should transition
            should_advance = False
            try:
                should_advance = self._should_advance_phase(tp)
                if should_advance:
                    new_phase = tp.advance_phase()
                    if new_phase:
                        # Inject phase-transition system message
                        phase_prompt = self.orch._build_dynamic_system_prompt(new_phase)
                        self.orch.sessions.add_message(
                            tp.session_id, "system",
                            f"[AUTONOMOUS] Phase transition → {new_phase.upper()}\n\n{phase_prompt}"
                        )
                        self._emit("on_phase_complete", {
                            "target": tp.target,
                            "completed_phase": KILL_CHAIN[tp.phase_index - 1] if tp.phase_index > 0 else "recon",
                            "new_phase": new_phase,
                        })
            except Exception as e:
                logger.warning(f"Target {tp.target}: phase transition failed: {e}")
                continue  # Skip nudge on error

            if not should_advance:
                # Stay in current phase — inject a nudge
                self.orch.sessions.add_message(
                    tp.session_id, "system",
                    f"[AUTONOMOUS] Continue {tp.current_phase.upper()} phase. "
                    f"Try a different approach or deepen the current enumeration."
                )

        logger.info(f"═══ Target {tp.target} engagement complete ═══")

    def _drive_phase(self, tp: TargetPhase):
        """Run iterations within a single phase for one target."""
        phase = tp.current_phase
        max_iters = MAX_ITERATIONS_PER_PHASE.get(phase, 15)
        iteration = 0

        phase_start = time.time()
        while iteration < max_iters:
            if self.state == AgentState.STOPPING:
                break
            # Engagement timeout check (per-phase)
            if time.time() - phase_start > MAX_ENGAGEMENT_DURATION / 2:
                logger.warning(f"Target {tp.target}: {phase} phase timeout — advancing")
                break
            # Pause gate with timeout to detect stop requests
            self._pause_event.wait(timeout=2.0)
            if self.state == AgentState.STOPPING:
                break

            iteration += 1
            tp.phase_iterations[phase] = tp.phase_iterations.get(phase, 0) + 1
            self._total_steps += 1

            # Run one engagement iteration (wrapped in try/except for resilience)
            try:
                step_result = self.orch._run_iteration(
                    tp.session_id, [], stream=False
                )
            except Exception as e:
                logger.warning(f"Target {tp.target}: iteration {iteration} crashed: {e}")
                tp.consecutive_failures += 1
                tp.phase_failures[phase] = tp.phase_failures.get(phase, 0) + 1
                tp.last_error = str(e)
                if tp.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self._escalate_retry(tp)
                    tp.consecutive_failures = 0
                self._emit("on_error", {
                    "target": tp.target, "phase": phase,
                    "error": str(e), "retry_level": retry_level_name(tp.retry_level),
                })
                if self.state == AgentState.STOPPING:
                    break
                continue

            # Process results
            if step_result.get("error"):
                tp.consecutive_failures += 1
                tp.phase_failures[phase] = tp.phase_failures.get(phase, 0) + 1
                tp.last_error = step_result["error"]

                # Adaptive retry escalation
                if tp.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self._escalate_retry(tp)
                    tp.consecutive_failures = 0

                self._emit("on_error", {
                    "target": tp.target,
                    "phase": phase,
                    "error": step_result["error"],
                    "retry_level": retry_level_name(tp.retry_level),
                })
                if self.state == AgentState.STOPPING:
                    break
                continue

            # Reset consecutive failures on success
            tp.consecutive_failures = 0

            # Collect findings from results
            for result in step_result.get("results", []):
                if result.get("status") == "success":
                    finding = {
                        "tool": result.get("tool", ""),
                        "summary": result.get("summary", ""),
                        "stdout": result.get("stdout", "")[:2000],
                        "severity": self._classify_finding(result),
                    }
                    tp.phase_findings[phase].append(finding)
                    self._total_findings += 1

            # Get tactical suggestions from findings
            all_findings = []
            for f_list in tp.phase_findings.values():
                all_findings.extend(f_list)

            if all_findings and self._has_execute_direct:
                tactical = self.orch.tactics.get_auto_run_actions(
                    all_findings,
                    context={"host": tp.target}
                )
                for action in tactical[:3]:  # Cap at 3 auto-actions per iteration
                    try:
                        result = self.orch.execute_direct(
                            action["tool"], action["args"], tp.session_id
                        )
                        if result.get("exit_code") == 0:
                            tp.phase_findings[phase].append({
                                "tool": action["tool"],
                                "summary": action.get("reasoning", ""),
                                "severity": "info",
                            })
                            self._total_findings += 1
                    except Exception as e:
                        logger.debug(f"Tactical auto-run failed: {e}")

            if self.state == AgentState.STOPPING:
                break

            # Check if LLM says engagement is complete
            llm_response = step_result.get("llm_response", "")
            if llm_response and self._check_llm_completion_signal(llm_response):
                logger.info(f"Target {tp.target}: LLM signals completion in {phase}")
                break

            # Check completion conditions for the phase
            if self._check_phase_completion(tp, step_result):
                break

    def _should_advance_phase(self, tp: TargetPhase) -> bool:
        """Decide whether to advance to the next phase."""
        phase = tp.current_phase
        findings_count = len(tp.phase_findings.get(phase, []))
        iterations = tp.phase_iterations.get(phase, 0)
        min_findings = MIN_FINDINGS_PER_PHASE.get(phase, 1)
        max_iters = MAX_ITERATIONS_PER_PHASE.get(phase, 15)

        # If we have enough findings, advance
        if findings_count >= min_findings:
            return True

        # If we've hit the iteration limit, advance anyway
        if iterations >= max_iters:
            logger.info(f"Target {tp.target}: {phase} hit iteration limit ({max_iters})")
            return True

        # For postex, advance when iterations run out
        if phase == "postex" and iterations >= max_iters:
            return True

        # For exploit, advance after max iterations (report what we got)
        if phase == "exploit" and iterations >= max_iters:
            return True

        return False

    def _check_phase_completion(self, tp: TargetPhase, step_result: Dict) -> bool:
        """Check if the current phase should terminate early."""
        action = step_result.get("action", "")
        phase = tp.current_phase

        # If the LLM says engagement is complete
        if action == "complete":
            return True

        # For recon: complete when we have open ports + services
        if phase == "recon":
            findings = tp.phase_findings.get("recon", [])
            has_ports = any(
                "open" in f.get("stdout", "").lower() or "open" in f.get("summary", "").lower()
                for f in findings
            )
            if has_ports and len(findings) >= 2:
                return True

        # For exploit: complete if we got shell/root access
        if phase == "exploit":
            for f in tp.phase_findings.get("exploit", []):
                text = f.get("summary", "") + f.get("stdout", "")
                if any(kw in text.lower() for kw in
                       ["meterpreter", "shell", "root", "system", "administrator"]):
                    return True

        return False

    def _classify_finding(self, result: Dict) -> str:
        """Quick severity classification of a tool result."""
        stdout = (result.get("stdout", "") + result.get("summary", "")).lower()
        if any(kw in stdout for kw in ["critical", "rce", "remote code", "meterpreter",
                                        "root shell", "eternalblue", "log4shell"]):
            return "critical"
        if any(kw in stdout for kw in ["high", "sql injection", "vulnerable",
                                        "credential", "password", "hash"]):
            return "high"
        if any(kw in stdout for kw in ["medium", "warning", "directory listing",
                                        "information disclosure"]):
            return "medium"
        if any(kw in stdout for kw in ["open", "port", "service", "banner"]):
            return "info"
        return "info"

    def _check_llm_completion_signal(self, response: str) -> bool:
        """Check if the LLM response indicates the engagement is done."""
        indicators = [
            "engagement complete", "assessment complete", "all tests done",
            "no further actions", "report generated", "final summary",
            "testing is complete", "pentest complete",
        ]
        lower = response.lower()
        return any(ind in lower for ind in indicators)

    # ═══════════════════════════════════════════════════════════════
    # ADAPTIVE RETRY ESCALATION
    # ═══════════════════════════════════════════════════════════════

    def _escalate_retry(self, tp: TargetPhase):
        """Escalate the retry strategy when tools keep failing."""
        tp.retry_level = min(tp.retry_level + 1, len(RETRY_LEVELS) - 1)
        level_name = retry_level_name(tp.retry_level)

        logger.info(f"Target {tp.target}: retry escalation → {level_name}")

        self._emit("on_retry_escalation", {
            "target": tp.target,
            "phase": tp.current_phase,
            "level": level_name,
            "last_tool": tp.last_tool,
            "last_error": tp.last_error,
        })

        if level_name == "skip_phase":
            # Force advance to next phase
            tp.consecutive_failures = 0
            tp.retry_level = 0
            self.orch.sessions.add_message(
                tp.session_id, "system",
                f"[AUTONOMOUS] Phase {tp.current_phase.upper()} has been exhausted. "
                f"Moving to the next phase."
            )

    # ═══════════════════════════════════════════════════════════════
    # FIRE-AND-FORGET REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════

    def _generate_campaign_report(self):
        """Generate a comprehensive campaign report after engagement completes."""
        logger.info("Generating autonomous campaign report...")

        try:
            # Collect all findings across targets
            all_findings = []
            for target, tp in self._target_phases.items():
                for phase, findings in tp.phase_findings.items():
                    for f in findings:
                        f["target"] = target
                        f["phase"] = phase
                        all_findings.append(f)

            if not all_findings:
                logger.info("No findings to report")
                return

            # Build campaign summary
            target_summaries = []
            for target, tp in self._target_phases.items():
                phase_summary = {}
                for phase in KILL_CHAIN:
                    count = len(tp.phase_findings.get(phase, []))
                    phase_summary[phase] = count
                target_summaries.append(
                    f"- **{target}**: " +
                    ", ".join(f"{p}={c}" for p, c in phase_summary.items() if c > 0)
                )

            findings_text = ""
            for f in all_findings[:50]:  # Cap at 50 findings for report
                sev = f.get("severity", "info").upper()
                tool = f.get("tool", "unknown")
                target = f.get("target", "unknown")
                summary = f.get("summary", "")[:120]
                findings_text += f"- [{sev}] {target}: {tool} — {summary}\n"

            # Generate via LLM
            report_prompt = (
                f"Generate a comprehensive penetration test report for an autonomous engagement.\n\n"
                f"## Objective\n{self._objective}\n\n"
                f"## Duration\n{self._start_time} → {datetime.now().isoformat()}\n\n"
                f"## Targets ({len(self._targets)})\n" +
                "\n".join(target_summaries) + "\n\n"
                f"## Total Steps: {self._total_steps}\n"
                f"## Total Findings: {len(all_findings)}\n\n"
                f"## Key Findings\n{findings_text}\n\n"
                f"Write a professional penetration test report with:\n"
                f"1. Executive Summary\n"
                f"2. Methodology\n"
                f"3. Findings by Target\n"
                f"4. Kill Chain Coverage\n"
                f"5. Remediation Recommendations\n"
                f"6. Conclusion"
            )

            try:
                report = self.orch.llm.chat(
                    [{"role": "user", "content": report_prompt}],
                    max_tokens=4096, temperature=0.3
                )
            except Exception as llm_err:
                logger.warning(f"LLM report generation failed: {llm_err}")
                report = None

            if report and not report.startswith("[ERROR]"):
                # Save to file
                report_dir = os.path.join(
                    self.orch.config.get("harness", {}).get("session_dir", "./sessions"),
                    "reports"
                )
                os.makedirs(report_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = os.path.join(report_dir, f"autonomous_report_{timestamp}.md")
                with open(report_path, "w") as f:
                    f.write(report)
                self._report_path = report_path
                logger.info(f"Campaign report saved: {report_path}")

                self._emit("on_status_update", self.get_status())

                self._emit("on_report_generated", {
                    "path": report_path,
                    "findings_count": len(all_findings),
                    "targets_count": len(self._targets),
                })
            else:
                logger.warning("LLM report generation failed — generating fallback report")
                self._generate_fallback_report(all_findings, target_summaries)

        except Exception as e:
            logger.error(f"Campaign report generation failed: {e}", exc_info=True)
            try:
                self._generate_fallback_report(all_findings, target_summaries)
            except Exception as fallback_err:
                logger.error(f"Fallback report also failed: {fallback_err}")

    def _generate_fallback_report(self, all_findings: List[Dict],
                                  target_summaries: List[str]):
        """Generate a basic markdown report without LLM when it's unavailable."""
        report_dir = os.path.join(
            self.orch.config.get("harness", {}).get("session_dir", "./sessions"),
            "reports"
        )
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"autonomous_report_{timestamp}.md")

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build markdown report
        lines = [
            f"# Autonomous Engagement Report",
            f"",
            f"**Generated**: {datetime.now().isoformat()}",
            f"**Objective**: {self._objective}",
            f"**Duration**: {self._start_time} → {datetime.now().isoformat()}",
            f"**State**: {self.state.value}",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Targets | {len(self._targets)} |",
            f"| Total Steps | {self._total_steps} |",
            f"| Total Findings | {len(all_findings)} |",
            f"| Critical | {severity_counts.get('critical', 0)} |",
            f"| High | {severity_counts.get('high', 0)} |",
            f"| Medium | {severity_counts.get('medium', 0)} |",
            f"| Info | {severity_counts.get('info', 0)} |",
            f"",
            f"## Targets",
            f"",
        ] + [s for s in target_summaries] + [
            f"",
            f"## Findings",
            f"",
        ]

        # Group findings by target
        by_target = {}
        for f in all_findings:
            t = f.get("target", "unknown")
            if t not in by_target:
                by_target[t] = []
            by_target[t].append(f)

        for target, findings in by_target.items():
            lines.append(f"### {target}")
            lines.append("")
            for f in findings:
                sev = f.get("severity", "info").upper()
                tool = f.get("tool", "unknown")
                phase = f.get("phase", "unknown")
                summary = f.get("summary", "No summary")[:200]
                lines.append(f"- **[{sev}]** `{tool}` ({phase}): {summary}")
            lines.append("")

        lines.extend([
            f"## Kill Chain Coverage",
            f"",
        ])
        for target, tp in self._target_phases.items():
            for phase in KILL_CHAIN:
                count = len(tp.phase_findings.get(phase, []))
                if count > 0:
                    lines.append(f"- **{target}** → {phase.upper()}: {count} findings")

        report = "\n".join(lines)
        with open(report_path, "w") as f:
            f.write(report)
        self._report_path = report_path
        logger.info(f"Fallback report saved: {report_path}")
        self._emit("on_report_generated", {
            "path": report_path,
            "findings_count": len(all_findings),
            "targets_count": len(self._targets),
            "fallback": True,
        })
