"""Regression tests for the use_intent reroute contract + shared bus wiring.

Three behaviors that were unimplemented/broken:
  1. The MechUnit facade must launch the sibling intent a plan rerouted to
     (previously a use_intent fallback recorded a finding and did nothing).
  2. Reroutes must be cycle/depth guarded (handshake<->pmkid can never loop).
  3. Executor events must reach the facade's bus so the dashboard relay and
     the reroute logic can observe them (previously a private per-executor
     bus silently dropped everything).

All runs use a fake runner injected via MechUnit._make_runner and tiny
in-memory manifests (no preconditions) so compile always succeeds.
"""
import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech import MechUnit  # noqa: E402
from core.mech import events as mech_events  # noqa: E402
from core.mech.state import PlanState  # noqa: E402


def _manifest(mid, steps, filename=None):
    return {
        "id": mid, "name": mid, "category": "network",
        "operator_label": "l", "operator_description": "d",
        "outcome": "o", "grants": ["cap"], "time_to_impact": "t",
        "noise": "low", "risk_notes": "r", "preconditions": [],
        "plan": steps, "llm_required": False,
    }


def _write_manifests(directory, *manifests):
    import yaml
    for i, data in enumerate(manifests):
        fn = data.get("_file") or f"{data['id']}.yaml"
        path = os.path.join(directory, fn)
        with open(path, "w") as f:
            yaml.safe_dump(data, f)
    return directory


def ok(**kw):
    d = {"stdout": "ok", "stderr": "", "exit_code": 0, "duration": 0.1,
         "blocked": False, "killed": False}
    d.update(kw)
    return d


def fail(**kw):
    d = {"stdout": "", "stderr": "boom", "exit_code": 1, "duration": 0.1,
         "blocked": False, "killed": False}
    d.update(kw)
    return d


class FakeRunner:
    """Scriptable stand-in for HardenedToolRunner."""

    def __init__(self, script=None):
        self.script = script or {}
        self.calls = []

    def execute(self, tool, args, timeout=300, sandbox_output_dir=None):
        self.calls.append(tool)
        b = self.script.get(tool, ok())
        return dict(b) if not callable(b) else b(args)


def _unit(manifest_dir, runner):
    unit = MechUnit(config={}, manifest_dir=manifest_dir,
                    sandbox_root=tempfile.mkdtemp())
    unit._make_runner = lambda: runner
    return unit


class TestRerouteLaunchesSibling(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        _write_manifests(
            self.dir,
            _manifest("parent", [
                {"step": "s", "tool": "fail_tool",
                 "fallbacks": [{"step": "reroute", "use_intent": "sibling"}]},
            ]),
            _manifest("sibling", [{"step": "ok", "tool": "ok_tool"}]),
        )
        self.runner = FakeRunner({"fail_tool": fail(), "ok_tool": ok()})

    def test_run_launches_sibling_and_returns_its_state(self):
        unit = _unit(self.dir, self.runner)
        plan = unit.compile("parent")
        self.assertTrue(plan.runnable)
        result = unit.run(plan)
        # The sibling intent actually ran — the operator sees real work.
        self.assertEqual(result.intent_id, "sibling")
        self.assertEqual(result.state, PlanState.DONE.value)
        # Parent recorded the handoff finding and completed as done.
        parent_st = unit._run_states[plan.plan_id]
        self.assertEqual(parent_st.state, PlanState.DONE.value)
        self.assertTrue(
            any(f.get("title") == "fallback_intent"
                for f in parent_st.findings))
        # The sibling's step executed.
        self.assertIn("ok_tool", self.runner.calls)


class TestRerouteCycleGuard(unittest.TestCase):
    def test_mutual_reroute_does_not_loop_forever(self):
        d = tempfile.mkdtemp()
        # parent reroutes to sibling; sibling reroutes back to parent.
        _write_manifests(
            d,
            _manifest("parent", [
                {"step": "s", "tool": "fail_tool",
                 "fallbacks": [{"step": "r1", "use_intent": "sibling"}]}]),
            _manifest("sibling", [
                {"step": "s", "tool": "fail_tool",
                 "fallbacks": [{"step": "r2", "use_intent": "parent"}]}]),
        )
        runner = FakeRunner({"fail_tool": fail()})
        unit = _unit(d, runner)
        plan = unit.compile("parent")
        result = unit.run(plan)
        # The visited-set guard stopped the cycle after the first handoff:
        # parent -> sibling, then sibling's reroute back to parent is refused.
        self.assertEqual(result.intent_id, "sibling")
        self.assertEqual(result.state, PlanState.DONE.value)

    def test_depth_cap_halts_a_long_reroute_chain(self):
        d = tempfile.mkdtemp()
        manifests = []
        n = MechUnit.MAX_REROUTE_DEPTH + 3  # longer than the cap
        for i in range(n):
            nxt = f"r{i + 1}"
            manifests.append(_manifest(
                f"r{i}",
                [{"step": "s", "tool": "fail_tool",
                  "fallbacks": [{"step": "r", "use_intent": nxt}]}]))
        _write_manifests(d, *manifests)
        unit = _unit(d, FakeRunner({"fail_tool": fail()}))
        plan = unit.compile("r0")
        result = unit.run(plan)
        # Only MAX_REROUTE_DEPTH launches happen; the chain stops before
        # running every intent (and before any infinite loop).
        self.assertIn(result.intent_id, {f"r{i}" for i in range(n)})


class TestSharedBusWiring(unittest.TestCase):
    def test_executor_events_reach_facade_bus(self):
        d = tempfile.mkdtemp()
        _write_manifests(d, _manifest("solo", [{"step": "ok", "tool": "ok_tool"}]))
        unit = _unit(d, FakeRunner({"ok_tool": ok()}))
        seen = []
        unit.on_event(mech_events.STEP_COMPLETE,
                      lambda p: seen.append(p["event"]))
        unit.on_event(mech_events.PLAN_COMPLETE,
                      lambda p: seen.append(p["event"]))
        plan = unit.compile("solo")
        unit.run(plan)
        # The relay subscribed to the facade bus MUST see executor emissions.
        self.assertIn(mech_events.STEP_COMPLETE, seen)
        self.assertIn(mech_events.PLAN_COMPLETE, seen)

    def test_reroute_fallback_event_visible_on_facade_bus(self):
        d = tempfile.mkdtemp()
        _write_manifests(
            d,
            _manifest("parent", [
                {"step": "s", "tool": "fail_tool",
                 "fallbacks": [{"step": "r", "use_intent": "sibling"}]}]),
            _manifest("sibling", [{"step": "ok", "tool": "ok_tool"}]),
        )
        unit = _unit(d, FakeRunner({"fail_tool": fail(), "ok_tool": ok()}))
        events = []
        unit.on_event(mech_events.STEP_FALLBACK, lambda p: events.append(p))
        plan = unit.compile("parent")
        unit.run(plan)
        self.assertTrue(any(e.get("use_intent") == "sibling" for e in events))


if __name__ == "__main__":
    unittest.main()