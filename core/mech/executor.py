"""
RedTeam Harness — Mech-Unit Plan Executor (v7.0 P2.1)

Walks a CompiledPlan DAG honoring when/gate/fallbacks/max_wait, calling
tools EXCLUSIVELY through HardenedToolRunner (tool_registry + hardening:
list-mode subprocess, SIGTERM→SIGKILL cascade, audit trail). This module
deliberately owns no subprocess logic — Decision Register #23.

Failure routing (vocabulary pinned in intents.VALID_DIRECTIVES):
    gate failed / tool failed
      → retries left?  → re-run the step (skipped when on_timeout decides)
      → fallbacks?     → run fallback steps (inline tool or use_intent)
      → on_fail == "warn"  → mark FALLBACK/failure, continue plan
      → on_fail == "abort" → fail the plan
      → on_fail == "retry_then_fallback" → retry, then fallbacks, then fail
    timeout (tool killed by hardening):
      → on_timeout == "warn"   → mark failure, continue plan (no retry burn)
      → on_timeout == "abort"  → fail the plan
      → on_timeout absent/"retry_then_fallback" → on_fail routing as above
    gate succeeded → extracts run, findings are collected, plan continues

Every state mutation persists via PlanRunState (atomic state.json) and
every milestone emits on the typed EventBus → SocketIO "mech_*" channels.
"""
import os
import re
import time
import logging
from typing import Any, Callable, Dict, Optional

from core.mech.compiler import CompiledPlan, CompiledStep
from core.mech.state import PlanRunState, PlanState, StepState
from core.mech import events as mech_events

logger = logging.getLogger("redteam.mech.executor")

# Directives (imported so the executor and validator share one vocabulary)
from core.mech.intents import VALID_DIRECTIVES  # noqa: E402


class PlanExecutor:
    """Executes a CompiledPlan against a HardenedToolRunner."""

    def __init__(self, runner, bus: Optional[mech_events.EventBus] = None,
                 clock: Callable[[], float] = time.time):
        """
        runner: core.hardening.HardenedToolRunner (or test double) exposing
                execute(tool_name, args, timeout, sandbox_output_dir).
        """
        self.runner = runner
        self.bus = bus or mech_events.EventBus()
        self._clock = clock

    # ── public API ───────────────────────────────────────────────────

    def run(self, plan: CompiledPlan, run_state: PlanRunState,
            extra_artifacts: Optional[Dict[str, str]] = None) -> PlanRunState:
        """Run the whole plan (resume-aware: completed steps are skipped).

        Raises nothing — terminal state is reflected in run_state
        (DONE / FAILED / ABORTED) and per-step records.
        """
        run_state.set_step_order(plan.step_names())
        # State normalization: fresh compile → start; paused/crashed run →
        # continue in RUNNING (resume-from-persisted-state is the norm here).
        if run_state.state == PlanState.COMPILED.value:
            run_state.start()
        elif run_state.state == PlanState.PAUSED.value:
            run_state.resume()
        run_state.save()
        self._emit_state(run_state, "running")

        artifacts = dict(plan.artifacts)
        artifacts.update(extra_artifacts or {})
        facts: Dict[str, Any] = {}

        for step in plan.steps:
            if run_state.state != PlanState.RUNNING.value:
                break  # paused/aborted mid-plan

            # Resume: steps already terminal from a prior run are skipped.
            rec = run_state.records.get(step.step)
            if rec and rec.state in (StepState.SUCCESS.value,
                                     StepState.FAILED.value,
                                     StepState.SKIPPED.value,
                                     StepState.FALLBACK.value):
                continue

            # when: condition (facts evaluated at execution time)
            if not self._condition_ok(step, facts, run_state):
                run_state.mark_step_skipped(step.step)
                run_state.save()
                self.bus.emit(mech_events.STEP_SKIPPED, {
                    "plan_id": plan.plan_id, "step": step.step})
                continue

            outcome = self._run_step_with_routing(
                plan, run_state, step, artifacts, facts)
            if outcome == "abort":
                run_state.save()
                return run_state

        # Terminal state: reaching here while RUNNING means every failure
        # was either routed through fallbacks or explicitly warned (an
        # un-warned failure aborts immediately inside the routing), so the
        # plan completes — per-step outcomes stay visible in the records.
        if run_state.state == PlanState.RUNNING.value:
            run_state.complete()
            self._emit_state(run_state, "done")
            self.bus.emit(mech_events.PLAN_COMPLETE, {
                "plan_id": plan.plan_id,
                "findings": list(run_state.findings)})
        run_state.save()
        return run_state

    # ── step execution + failure routing ────────────────────────────

    def _run_step_with_routing(self, plan: CompiledPlan, run_state: PlanRunState,
                               step: CompiledStep, artifacts: Dict[str, str],
                               facts: Dict[str, Any]) -> str:
        """Run one step with retry/fallback/on_fail routing.

        Returns "continue" or "abort".
        """
        max_attempts = step.retries + 1
        last_error = ""
        last_timed_out = False

        for attempt in range(1, max_attempts + 1):
            if run_state.state != PlanState.RUNNING.value:
                return "abort"

            run_state.mark_step_started(step.step)
            run_state.save()
            self.bus.emit(mech_events.STEP_STARTED, {
                "plan_id": plan.plan_id, "step": step.step,
                "tool": step.tool, "attempt": attempt})

            result = self._invoke_tool(plan, run_state, step, artifacts)
            if run_state.state != PlanState.RUNNING.value:
                # Aborted/paused mid-invocation — no outcome recorded.
                run_state.mark_step_interrupted(step.step)
                run_state.save()
                return "abort"
            ok, why = self._evaluate_result(step, result, run_state)

            if ok:
                self._on_success(plan, run_state, step, result, artifacts, facts)
                return "continue"

            last_error = why
            last_timed_out = bool(result.get("killed"))
            run_state.mark_step_failed(step.step, why,
                                       exit_code=result.get("exit_code"),
                                       duration=result.get("duration"))
            run_state.save()
            self.bus.emit(mech_events.STEP_FAILED, {
                "plan_id": plan.plan_id, "step": step.step, "error": why,
                "attempt": attempt})

            if attempt < max_attempts:
                if last_timed_out and step.on_timeout in ("warn", "abort"):
                    # A hung tool must not burn the remaining retries — the
                    # operator's timeout directive decides NOW (v7.1). The
                    # STEP_TIMEOUT event is emitted by _route_failure.
                    break
                self.bus.emit(mech_events.STEP_RETRY, {
                    "plan_id": plan.plan_id, "step": step.step,
                    "attempt": attempt + 1})
                continue

        # Retries exhausted → fallbacks, then the timeout/on_fail directive
        return self._route_failure(plan, run_state, step, artifacts, facts,
                                   last_error, timed_out=last_timed_out)

    def _route_failure(self, plan: CompiledPlan, run_state: PlanRunState,
                       step: CompiledStep, artifacts: Dict[str, str],
                       facts: Dict[str, Any], last_error: str,
                       timed_out: bool = False) -> str:
        """Retries exhausted: try fallbacks, then apply the routing directive.

        Order (v7.0 semantics, preserved): fallbacks run BEFORE the directive.
        v7.1 exception — a timeout with an explicit on_timeout of "warn" or
        "abort" applies the directive FIRST and skips fallbacks: a hung tool
        means the environment is stuck, so sibling fallbacks would hang too.
        """
        directive = step.on_fail or "abort"
        timeout_decided = timed_out and step.on_timeout in ("warn", "abort")
        if timeout_decided:
            directive = step.on_timeout
            self.bus.emit(mech_events.STEP_TIMEOUT, {
                "plan_id": plan.plan_id, "step": step.step})

        if not timeout_decided and step.fallbacks:
            for fb in step.fallbacks:
                fb_name = fb.get("step", "")
                if fb.get("use_intent"):
                    # Intent reroute: record it and stop this plan — the
                    # MechUnit facade compiles + runs the referenced intent
                    # as its own plan (deterministic graph edge, not an
                    # in-plan surprise).
                    run_state.mark_step_fallback(step.step)
                    run_state.add_finding({
                        "severity": "info", "title": "fallback_intent",
                        "detail": f"step '{step.step}' failed; reroute via "
                                  f"intent '{fb['use_intent']}'",
                        "intent": fb["use_intent"]})
                    run_state.save()
                    self.bus.emit(mech_events.STEP_FALLBACK, {
                        "plan_id": plan.plan_id, "step": step.step,
                        "use_intent": fb["use_intent"]})
                    return "continue"
                # Inline fallback tool step
                fb_result = self._run_fallback_step(
                    plan, run_state, step, fb, artifacts, facts)
                if fb_result:
                    run_state.mark_step_fallback(step.step)
                    run_state.save()
                    self.bus.emit(mech_events.STEP_FALLBACK, {
                        "plan_id": plan.plan_id, "step": step.step,
                        "fallback": fb_name})
                    return "continue"
            # All fallbacks failed → fall through to the directive (the
            # timeout_decided abort was already returned above).
        elif step.step not in run_state.records or \
                run_state.records[step.step].state != StepState.FALLBACK.value:
            pass  # no fallbacks declared; directive decides below

        if directive == "abort":
            run_state.fail(f"step '{step.step}' "
                           f"{'timed out' if timed_out else 'failed'}: {last_error}")
            self._emit_state(run_state, "failed")
            return "abort"
        # directive here is "warn" or "retry_then_fallback" — both mean:
        # mark the failure, keep the plan alive.
        run_state.save()
        return "continue"

    def _run_fallback_step(self, plan: CompiledPlan, run_state: PlanRunState,
                           step: CompiledStep, fb: Dict[str, Any],
                           artifacts: Dict[str, str], facts: Dict[str, Any]
                           ) -> bool:
        """Run one inline fallback tool step; True on success."""
        fb_name = fb.get("step", f"{step.step}_fallback")
        run_state.add_fallback_record(fb_name)
        run_state.mark_step_started(fb_name)
        run_state.save()
        self.bus.emit(mech_events.STEP_STARTED, {
            "plan_id": plan.plan_id, "step": fb_name,
            "tool": fb.get("tool", ""), "fallback_of": step.step})

        args = dict(fb.get("args", {}))
        result = self._invoke_tool_raw(plan, run_state, fb.get("tool", ""),
                                       args, timeout=fb.get("max_wait"))
        ok, why = self._evaluate_result(
            CompiledStep(step=fb_name, tool=fb.get("tool", ""),
                         gate=fb.get("gate")),
            result, run_state)
        if ok:
            run_state.mark_step_complete(
                fb_name, result.get("exit_code", 0),
                result.get("duration", 0.0),
                finding=self._extract_finding(fb, result))
        else:
            run_state.mark_step_failed(fb_name, why,
                                       exit_code=result.get("exit_code"))
        run_state.save()
        return ok

    # ── tool invocation (single hardened path) ──────────────────────

    def _invoke_tool(self, plan: CompiledPlan, run_state: PlanRunState,
                     step: CompiledStep, artifacts: Dict[str, str]) -> Dict[str, Any]:
        return self._invoke_tool_raw(plan, run_state, step.tool, step.args,
                                     timeout=step.max_wait)

    def _invoke_tool_raw(self, plan: CompiledPlan, run_state: PlanRunState,
                         tool: str, args: Dict[str, Any],
                         timeout: Optional[int]) -> Dict[str, Any]:
        """Invoke through HardenedToolRunner — never subprocess directly.

        The plan sandbox is the process cwd AND the sandbox_output_dir, so
        every capture file the tool writes lands in tasks/mech/<plan_id>/.
        """
        if run_state.state != PlanState.RUNNING.value:
            return {"stdout": "", "stderr": "plan not running",
                    "exit_code": -1, "duration": 0, "blocked": True,
                    "block_reason": "plan_not_running"}
        try:
            return self.runner.execute(
                tool, args,
                timeout=timeout if timeout else 300,
                sandbox_output_dir=plan.plan_dir)
        except Exception as exc:
            logger.error("tool %s crashed via runner: %s", tool, exc)
            return {"stdout": "", "stderr": str(exc), "exit_code": -1,
                    "duration": 0, "blocked": True, "block_reason": "runner_error"}

    # ── gates / evaluation ───────────────────────────────────────────

    def _evaluate_result(self, step: CompiledStep, result: Dict[str, Any],
                         run_state: PlanRunState) -> tuple:
        """True when the step succeeded (gate semantics or exit code)."""
        if result.get("blocked"):
            return False, result.get("block_reason") or result.get("stderr", "blocked")
        if step.gate:
            # A declared gate IS the success criterion: a matched gate means
            # the semantic outcome happened even on a non-zero exit (many
            # cracking tools exit 1 when the wordlist exhausts).
            if not self._gate_matched(step, result):
                return False, f"gate not matched: {step.gate}"
            return True, ""
        # No gate → exit code is the success criterion.
        if result.get("exit_code", 0) != 0:
            return False, (result.get("stderr", "") or "non-zero exit")[:300]
        return True, ""

    @staticmethod
    def _gate_matched(step, result: Dict[str, Any]) -> bool:
        gate = step.gate or {}
        blob = (result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")
        if gate.get("output"):
            if not re.search(gate["output"], blob):
                return False
        for path in gate.get("file", []) or []:
            if not os.path.exists(path):
                return False
        if "exit_code" in gate and result.get("exit_code") != gate["exit_code"]:
            return False
        return True

    # ── when: conditions ─────────────────────────────────────────────

    def _condition_ok(self, step: CompiledStep, facts: Dict[str, Any],
                      run_state: PlanRunState) -> bool:
        """Evaluate a when: expression against execution-time facts.

        Supported: "{{ facts.key }}" (truthy), "!" prefix (negation),
        missing fact → false (skip). Structured expression grammar is a
        documented non-goal for v7.0.
        """
        if not step.when:
            return True
        expr = str(step.when).strip()
        negated = expr.startswith("!")
        if negated:
            expr = expr[1:].strip()
        m = re.match(r"\{\{\s*facts\.([A-Za-z0-9_]+)\s*\}\}", expr)
        if not m:
            logger.warning("step %s: unsupported when: '%s' — treating as false",
                           step.step, step.when)
            return False
        value = facts.get(m.group(1))
        result = bool(value)
        return (not result) if negated else result

    # ── success handling ─────────────────────────────────────────────

    def _on_success(self, plan: CompiledPlan, run_state: PlanRunState,
                    step: CompiledStep, result: Dict[str, Any],
                    artifacts: Dict[str, str], facts: Dict[str, Any]) -> None:
        finding_text = ""
        if step.extracts:
            blob = (result.get("stdout", "") or "") + "\n" + \
                   (result.get("stderr", "") or "")
            for var, regex in step.extracts.items():
                m = re.search(regex, blob)
                if m:
                    facts[var] = m.group(1) if m.groups() else True
                    finding_text = finding_text or f"{var}={facts[var]}"
        output_file = self._first_existing_artifact(step, result, artifacts)
        run_state.mark_step_complete(
            step.step, result.get("exit_code", 0),
            result.get("duration", 0.0), output_file=output_file,
            finding=finding_text)
        if finding_text:
            run_state.add_finding({
                "severity": "info", "title": step.step, "detail": finding_text,
                "source_tool": step.tool})
        run_state.save()
        self.bus.emit(mech_events.STEP_COMPLETE, {
            "plan_id": plan.plan_id, "step": step.step,
            "exit_code": result.get("exit_code", 0),
            "finding": finding_text})

    @staticmethod
    def _first_existing_artifact(step: CompiledStep, result: Dict[str, Any],
                                 artifacts: Dict[str, str]) -> str:
        # 1. Any args value that names an existing file inside the sandbox.
        for value in step.args.values():
            if isinstance(value, str) and value.startswith("/") \
                    and os.path.isfile(value):
                return value
        # 2. Named plan artifacts that exist.
        for path in artifacts.values():
            if os.path.isfile(path):
                return path
        return ""

    @staticmethod
    def _extract_finding(fb: Dict[str, Any], result: Dict[str, Any]) -> str:
        extracts = fb.get("extracts", {})
        blob = (result.get("stdout", "") or "") + "\n" + \
               (result.get("stderr", "") or "")
        for var, regex in extracts.items():
            m = re.search(regex, blob)
            if m:
                return f"{var}={m.group(1) if m.groups() else True}"
        return ""

    # ── events ───────────────────────────────────────────────────────

    def _emit_state(self, run_state: PlanRunState, label: str) -> None:
        self.bus.emit(mech_events.PLAN_STATE, {
            "plan_id": run_state.plan_id,
            "state": run_state.state, "label": label,
            "summary": run_state.summary()})
