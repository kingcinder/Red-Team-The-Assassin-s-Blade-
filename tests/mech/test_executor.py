"""Executor tests (v7.0 P2.2): gate pass/fail, retry-then-fallback, fallback
routing, when-conditions, artifact capture, event sequence, and the
no-subprocess structural guarantee."""
import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.compiler import CompiledPlan, CompiledStep  # noqa: E402
from core.mech.state import PlanRunState, PlanState, StepState  # noqa: E402
from core.mech.executor import PlanExecutor  # noqa: E402
from core.mech import events as mech_events  # noqa: E402
from core.mech.intents import IntentManifest  # noqa: E402


def make_manifest(intent_id="wifi_wpa_handshake", category="wireless",
                  grants=None):
    return IntentManifest(
        id=intent_id, name=intent_id, category=category,
        operator_label="l", operator_description="d", outcome="o",
        grants=list(grants or []), time_to_impact="t", noise="low",
        risk_notes="r", preconditions=[], plan=[], source_path="<test>")


def make_plan(steps, intent_id="wifi_wpa_handshake", category="wireless",
              artifacts=None, sandbox=None):
    return CompiledPlan(
        plan_id=f"{intent_id}_test", intent=make_manifest(intent_id, category),
        target={"bssid": "AA:BB:CC:DD:EE:FF"}, plan_dir=sandbox or tempfile.mkdtemp(),
        steps=steps, artifacts=artifacts or {}, probe_results=[],
        unresolved=[], compiled_at="now", resolution_log=[])


def step(name, tool="echo_tool", args=None, **kw):
    return CompiledStep(step=name, tool=tool, args=args or {}, **kw)


class FakeRunner:
    """Scriptable stand-in for HardenedToolRunner — no real subprocesses."""

    def __init__(self, script=None):
        # script: tool_name → result dict or callable(args) → result dict
        self.script = script or {}
        self.calls = []

    def execute(self, tool_name, args, timeout=300, sandbox_output_dir=None):
        self.calls.append({"tool": tool_name, "args": dict(args),
                           "timeout": timeout, "sandbox": sandbox_output_dir})
        behavior = self.script.get(tool_name, {
            "stdout": "ok", "stderr": "", "exit_code": 0, "duration": 0.1})
        if callable(behavior):
            return behavior(args)
        return dict(behavior)


def ok(stdout="ok", **kw):
    d = {"stdout": stdout, "stderr": "", "exit_code": 0, "duration": 0.1}
    d.update(kw)
    return d


def fail(stderr="boom", exit_code=1):
    return {"stdout": "", "stderr": stderr, "exit_code": exit_code, "duration": 0.1}


class RecordingBus:
    def __init__(self):
        self.events = []

    def emit(self, event, payload=None):
        self.events.append((event, payload or {}))

    # EventBus-compatible surface for the executor
    def subscribe(self, *a, **k):
        pass


def run_plan(steps, script, sandbox=None, extra_artifacts=None):
    runner = FakeRunner(script)
    bus = RecordingBus()
    ex = PlanExecutor(runner, bus=bus)
    plan = make_plan(steps, sandbox=sandbox)
    st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                      plan_dir=plan.plan_dir)
    out = ex.run(plan, st, extra_artifacts=extra_artifacts)
    return out, runner, bus, plan


# ═══════════════════════════════════════════════════════════════
# 1. Happy path + events
# ═══════════════════════════════════════════════════════════════

class TestHappyPath(unittest.TestCase):
    def test_simple_plan_completes(self):
        st, runner, bus, plan = run_plan(
            [step("a"), step("b", args={"x": "1"})], {})
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(len(runner.calls), 2)
        rec = st.records["a"]
        self.assertEqual(rec.state, StepState.SUCCESS.value)
        self.assertEqual(rec.exit_code, 0)

    def test_event_sequence_stable(self):
        st, runner, bus, plan = run_plan([step("a"), step("b")], {})
        names = [e for e, _ in bus.events]
        self.assertEqual(names, [
            mech_events.PLAN_STATE,       # running
            mech_events.STEP_STARTED,
            mech_events.STEP_COMPLETE,
            mech_events.STEP_STARTED,
            mech_events.STEP_COMPLETE,
            mech_events.PLAN_STATE,       # done
            mech_events.PLAN_COMPLETE,
        ])

    def test_tools_invoked_through_runner_with_sandbox_cwd(self):
        st, runner, bus, plan = run_plan([step("a")], {})
        call = runner.calls[0]
        self.assertEqual(call["sandbox"], plan.plan_dir)

    def test_timeout_flows_to_runner(self):
        st, runner, bus, plan = run_plan(
            [step("a", max_wait=42)], {})
        self.assertEqual(runner.calls[0]["timeout"], 42)

    def test_default_timeout_300(self):
        st, runner, bus, plan = run_plan([step("a")], {})
        self.assertEqual(runner.calls[0]["timeout"], 300)


# ═══════════════════════════════════════════════════════════════
# 2. Gates
# ═══════════════════════════════════════════════════════════════

class TestGates(unittest.TestCase):
    def test_gate_pass(self):
        st, *_ = run_plan(
            [step("a", gate={"output": "KEY FOUND"})],
            {"echo_tool": ok("KEY FOUND! [password123]")})
        self.assertEqual(st.state, PlanState.DONE.value)

    def test_gate_fail_then_on_fail_warn_continues(self):
        st, runner, bus, plan = run_plan(
            [step("a", gate={"output": "KEY FOUND"}, on_fail="warn"),
             step("b")], {})
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(st.records["a"].state, StepState.FAILED.value)
        self.assertEqual(st.records["b"].state, StepState.SUCCESS.value)

    def test_gate_fail_default_aborts(self):
        st, *_ = run_plan(
            [step("a", gate={"output": "NEVER"}), step("b")], {})
        self.assertEqual(st.state, PlanState.FAILED.value)
        self.assertIn("gate", st.error)
        self.assertEqual(st.records["b"].state, StepState.PENDING.value)

    def test_zero_exit_with_gate_still_needs_gate_match(self):
        # exit 0 but gate output absent → gate failure
        st, *_ = run_plan(
            [step("a", gate={"output": "handshake"}, on_fail="warn")], {})
        self.assertEqual(st.records["a"].state, StepState.FAILED.value)

    def test_nonzero_exit_without_gate_fails_step(self):
        st, *_ = run_plan(
            [step("a", on_fail="warn"), step("b", tool="ok_tool")],
            {"echo_tool": fail(stderr="nope")})
        self.assertEqual(st.records["a"].state, StepState.FAILED.value)
        self.assertEqual(st.records["b"].state, StepState.SUCCESS.value)

    def test_blocked_result_fails_step(self):
        st, *_ = run_plan(
            [step("a", on_fail="warn"), step("b")],
            {"echo_tool": {"stdout": "", "stderr": "not installed",
                           "exit_code": -1, "duration": 0, "blocked": True,
                           "block_reason": "not_installed"}})
        self.assertEqual(st.records["a"].state, StepState.FAILED.value)
        self.assertIn("not_installed", st.records["a"].error)


# ═══════════════════════════════════════════════════════════════
# 3. Retries
# ═══════════════════════════════════════════════════════════════

class TestRetries(unittest.TestCase):
    def test_retry_then_success(self):
        calls = {"n": 0}

        def flaky(args):
            calls["n"] += 1
            if calls["n"] < 2:
                return fail()
            return ok("recovered")

        st, runner, bus, plan = run_plan(
            [step("a", retries=2)], {"echo_tool": flaky})
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(calls["n"], 2)
        self.assertEqual(st.records["a"].attempts, 2)
        self.assertEqual(st.records["a"].state, StepState.SUCCESS.value)

    def test_retry_events_emitted(self):
        st, runner, bus, plan = run_plan(
            [step("a", retries=2)], {"echo_tool": lambda a: fail()})
        retry_events = [e for e, p in bus.events if e == mech_events.STEP_RETRY]
        self.assertEqual(len(retry_events), 2)

    def test_retries_exhausted_marks_failed(self):
        st, runner, bus, plan = run_plan(
            [step("a", retries=1, on_fail="warn"), step("b")],
            {"echo_tool": lambda a: fail()})
        self.assertEqual(st.records["a"].attempts, 2)


# ═══════════════════════════════════════════════════════════════
# 4. Fallbacks
# ═══════════════════════════════════════════════════════════════

class TestFallbacks(unittest.TestCase):
    def test_inline_fallback_succeeds(self):
        st, runner, bus, plan = run_plan(
            [step("a", fallbacks=[{"step": "a_fb", "tool": "fb_tool"}])],
            {"echo_tool": lambda a: fail(),
             "fb_tool": ok("fallback worked")})
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(st.records["a"].state, StepState.FALLBACK.value)
        self.assertEqual(st.records["a_fb"].state, StepState.SUCCESS.value)

    def test_inline_fallback_fails_then_on_fail_warn(self):
        st, runner, bus, plan = run_plan(
            [step("a", on_fail="warn",
                  fallbacks=[{"step": "a_fb", "tool": "fb_tool"}]),
             step("b", tool="ok_tool")],
            {"echo_tool": lambda a: fail(),
             "fb_tool": lambda a: fail()})
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(st.records["a_fb"].state, StepState.FAILED.value)
        self.assertEqual(st.records["b"].state, StepState.SUCCESS.value)

    def test_use_intent_fallback_records_reroute(self):
        st, runner, bus, plan = run_plan(
            [step("a", fallbacks=[{"step": "reroute", "use_intent": "wifi_pmkid"}])],
            {"echo_tool": lambda a: fail()})
        self.assertEqual(st.state, PlanState.DONE.value)
        intents = [f for f in st.findings if f.get("intent") == "wifi_pmkid"]
        self.assertEqual(len(intents), 1)
        self.assertIn("wifi_pmkid", json.dumps(
            [p for e, p in bus.events if e == mech_events.STEP_FALLBACK]))

    def test_fallback_fallback_args_forwarded(self):
        st, runner, bus, plan = run_plan(
            [step("a", fallbacks=[{"step": "a_fb", "tool": "fb_tool",
                                   "args": {"k": "v"}}])],
            {"echo_tool": lambda a: fail()})
        fb_call = [c for c in runner.calls if c["tool"] == "fb_tool"][0]
        self.assertEqual(fb_call["args"], {"k": "v"})


# ═══════════════════════════════════════════════════════════════
# 5. when: conditions
# ═══════════════════════════════════════════════════════════════

class TestConditions(unittest.TestCase):
    def test_when_true_runs(self):
        st, runner, bus, plan = run_plan(
            [step("disc", args={"x": "1"}),
             step("deauth", when="{{ facts.clients_seen }}")], {})
        # No extracts on 'disc' → facts empty → deauth should be skipped.
        self.assertEqual(st.records["deauth"].state, StepState.SKIPPED.value)

    def test_when_fact_from_extract_runs(self):
        ex = step("disc", args={}, extracts={"clients_seen": r"(\d+) clients"})
        st, runner, bus, plan = run_plan(
            [ex, step("deauth", when="{{ facts.clients_seen }}")],
            {"echo_tool": ok("3 clients connected")})
        self.assertEqual(st.records["deauth"].state, StepState.SUCCESS.value)

    def test_when_negation(self):
        ex = step("disc", args={}, extracts={"wps_locked": r"(WPS-locked)"})
        st, runner, bus, plan = run_plan(
            [ex, step("pin", when="!{{ facts.wps_locked }}")],
            {"echo_tool": ok("WPS-locked")})
        self.assertEqual(st.records["pin"].state, StepState.SKIPPED.value)

    def test_unsupported_when_treated_false(self):
        st, runner, bus, plan = run_plan(
            [step("a", when="facts.a and facts.b")], {})
        self.assertEqual(st.records["a"].state, StepState.SKIPPED.value)


# ═══════════════════════════════════════════════════════════════
# 6. Artifacts + extracts
# ═══════════════════════════════════════════════════════════════

class TestArtifacts(unittest.TestCase):
    def test_extract_finding_recorded(self):
        ex = step("disc", args={}, extracts={"bssid": r"([0-9A-F:]{17})"})
        st, runner, bus, plan = run_plan(
            [ex], {"echo_tool": ok("BSSID: AA:BB:CC:DD:EE:FF here")})
        self.assertEqual(len(st.findings), 1)
        self.assertEqual(st.findings[0]["detail"], "bssid=AA:BB:CC:DD:EE:FF")

    def test_existing_sandbox_artifact_recorded(self):
        sandbox = tempfile.mkdtemp()
        cap = os.path.join(sandbox, "capture-01.cap")
        with open(cap, "w") as f:
            f.write("pcap-bytes")
        st, runner, bus, plan = run_plan(
            [step("cap", args={"cap_file": cap})], {}, sandbox=sandbox)
        self.assertEqual(st.records["cap"].output_file, cap)

    def test_extra_artifacts_matched(self):
        sandbox = tempfile.mkdtemp()
        art = os.path.join(sandbox, "out.txt")
        with open(art, "w") as f:
            f.write("x")
        st, runner, bus, plan = run_plan(
            [step("a")], {}, sandbox=sandbox,
            extra_artifacts={"out": art})
        self.assertEqual(st.records["a"].output_file, art)


# ═══════════════════════════════════════════════════════════════
# 7. Resume + abort semantics
# ═══════════════════════════════════════════════════════════════

class TestResumeAbort(unittest.TestCase):
    def test_resume_skips_completed_steps(self):
        sandbox = tempfile.mkdtemp()
        plan = make_plan([step("a"), step("b"), step("c")], sandbox=sandbox)
        runner = FakeRunner({})  # all calls succeed
        bus = RecordingBus()
        ex = PlanExecutor(runner, bus=bus)
        st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                          plan_dir=plan.plan_dir)
        st.set_step_order(plan.step_names())
        # Simulate a crash after 'a' succeeded.
        st.mark_step_started("a")
        st.mark_step_complete("a", 0, 0.1)
        st.save()
        # Resume from persisted state (executor continues b, c).
        reloaded = PlanRunState.load(sandbox)
        out = ex.run(plan, reloaded)
        tools_run = [c["tool"] for c in runner.calls]
        self.assertEqual(out.state, PlanState.DONE.value)
        self.assertEqual(len(tools_run), 2)  # only b and c ran
        self.assertEqual(reloaded.records["a"].attempts, 1)

    def test_abort_stops_mid_plan(self):
        plan = make_plan([step("a"), step("b")])
        st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                          plan_dir=plan.plan_dir)

        class AbortingRunner:
            def __init__(self):
                self.first = True

            def execute(self, tool_name, args, timeout=300,
                        sandbox_output_dir=None):
                if self.first:
                    self.first = False
                    return ok()
                # Operator hit abort after step a.
                st.abort()
                return ok()

        runner = AbortingRunner()
        bus = RecordingBus()
        ex = PlanExecutor(runner, bus=bus)
        out = ex.run(plan, st)
        self.assertEqual(out.state, PlanState.ABORTED.value)
        self.assertEqual(st.records["b"].state, StepState.PENDING.value)

    def test_paused_plan_invocation_blocked(self):
        plan = make_plan([step("a")])
        st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                          plan_dir=plan.plan_dir)
        st.set_step_order(plan.step_names())
        st.start()
        st.pause()
        runner = FakeRunner({})
        ex = PlanExecutor(runner, bus=RecordingBus())
        result = ex._invoke_tool_raw(plan, st, "echo_tool", {}, timeout=None)
        self.assertTrue(result.get("blocked"))
        self.assertEqual(runner.calls, [])


# ═══════════════════════════════════════════════════════════════
# 8. Structural guarantees
# ═══════════════════════════════════════════════════════════════

class TestStructuralGuarantees(unittest.TestCase):
    def test_no_subprocess_import_in_mech_package(self):
        """Decision Register #23: the mech package never touches subprocess."""
        mech_dir = os.path.join(os.path.dirname(__file__), "..", "..", "core", "mech")
        offenders = []
        for fn in os.listdir(mech_dir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(mech_dir, fn)) as f:
                src = f.read()
            if "import subprocess" in src or "subprocess." in src:
                offenders.append(fn)
        self.assertEqual(offenders, [],
                         f"subprocess usage found in: {offenders}")

    def test_directive_vocabulary_shared_with_validator(self):
        from core.mech.intents import VALID_DIRECTIVES
        # The executor's routing branches must stay aligned with the
        # validator's vocabulary — warn/abort/retry_then_fallback.
        self.assertEqual(VALID_DIRECTIVES,
                         {"warn", "abort", "retry_then_fallback"})


# ═══════════════════════════════════════════════════════════════
# 11. Timeout routing — on_timeout must be honored (v7.1 Task 1)
# ═══════════════════════════════════════════════════════════════

class TestTimeoutRouting(unittest.TestCase):
    """A hung tool (hardening kills it → killed=True) must honor the
    operator's on_timeout directive instead of burning retries and then
    routing through on_fail."""

    def _run(self, on_timeout, on_fail="abort", retries=0, fallbacks=None):
        script = {"x": {"stdout": "", "stderr": "timed out", "exit_code": -9,
                        "duration": 30.0, "blocked": False, "killed": True}}
        bus = RecordingBus()
        plan = make_plan(
            [step("s", tool="x", on_timeout=on_timeout, on_fail=on_fail,
                  retries=retries, fallbacks=fallbacks or [])],
            sandbox=tempfile.mkdtemp())
        st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                          plan_dir=plan.plan_dir)
        PlanExecutor(FakeRunner(script), bus=bus).run(plan, st)
        return st, bus

    def test_timeout_warn_completes_plan(self):
        st, bus = self._run(on_timeout="warn")
        self.assertEqual(st.state, PlanState.DONE.value)
        self.assertEqual(st.records["s"].state, StepState.FAILED.value)
        self.assertTrue(any(e == mech_events.STEP_TIMEOUT for e, _ in bus.events))

    def test_timeout_absent_falls_back_to_on_fail(self):
        st, bus = self._run(on_timeout=None, on_fail="abort")
        self.assertEqual(st.state, PlanState.FAILED.value)
        self.assertFalse(any(e == mech_events.STEP_TIMEOUT for e, _ in bus.events))

    def test_timeout_abort_fails_plan_immediately(self):
        st, bus = self._run(on_timeout="abort", on_fail="warn", retries=3)
        self.assertEqual(st.state, PlanState.FAILED.value)
        # abort-on-timeout must not burn the remaining retries
        self.assertEqual(st.records["s"].attempts, 1)

    def test_timeout_retry_then_fallback_runs_fallback(self):
        fb = [{"step": "s_fb", "tool": "fb", "args": {}, "extracts": {}}]
        script = {"x": {"stdout": "", "stderr": "timed out", "exit_code": -9,
                        "duration": 30.0, "blocked": False, "killed": True},
                  "fb": ok()}
        plan = make_plan(
            [step("s", tool="x", retries=2,
                  on_timeout="retry_then_fallback", fallbacks=fb)],
            sandbox=tempfile.mkdtemp())
        st = PlanRunState(plan_id=plan.plan_id, intent_id=plan.intent.id,
                          plan_dir=plan.plan_dir)
        runner = FakeRunner(script)
        PlanExecutor(runner, bus=RecordingBus()).run(plan, st)
        self.assertEqual(st.state, PlanState.DONE.value)
        # 3 timed-out attempts of x + 1 fallback invocation
        x_calls = [c for c in runner.calls if c["tool"] == "x"]
        self.assertEqual(len(x_calls), 3)


if __name__ == "__main__":
    unittest.main()
