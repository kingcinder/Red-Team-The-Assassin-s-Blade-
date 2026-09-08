"""Route tests for the Mech-Unit blueprint (v7.1 Task 3).

The resume route was a no-op (returned resume_requested, started nothing);
these tests pin the fixed behavior plus the reattach endpoints (plans list,
plan detail) that let the cockpit survive a browser refresh.
"""
import os
import sys
import json
import tempfile
import threading
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from flask import Flask  # noqa: E402


def make_app(unit):
    """Build a minimal Flask app with the mech blueprint registered.

    ctx stubs: app + socketio (emit recorder) + orchestrator (capture_state
    stub) + config. The stub unit is injected via ctx.mech_unit.
    """
    from dashboard.blueprints.mech import register

    class _Sock:
        def __init__(self):
            self.emitted = []

        def emit(self, channel, payload):
            self.emitted.append((channel, payload))

    ctx = SimpleNamespace(
        app=Flask(__name__), socketio=_Sock(),
        orchestrator=SimpleNamespace(capture_state=None, config={}),
        config={}, mech_unit=unit)
    register(ctx)
    return ctx.app


class StubUnit:
    """Records calls; satisfies the routes the tests exercise."""

    def __init__(self):
        self._plans = {}
        self.resumed = []
        self.paused = []
        self.aborted = []

    def on_event(self, event, callback):
        pass  # no live bus in the stub — relay wiring is exercised elsewhere

    # — routes under test —
    def pause(self, plan_id):
        self.paused.append(plan_id)
        return {"status": "pausing", "plan_id": plan_id}

    def resume(self, plan_id):
        self.resumed.append(plan_id)
        return {"plan_id": plan_id, "state": "done"}

    def get_plan_report(self, plan_id):
        if plan_id != "known":
            raise KeyError(plan_id)
        return {"plan_id": plan_id, "intent_id": "wifi_pmkid"}

    def list_plans(self):
        return [{"plan_id": "known", "state": "done"}]


class TestResumeRoute(unittest.TestCase):
    def setUp(self):
        self.unit = StubUnit()
        self.app = make_app(self.unit)
        self.client = self.app.test_client()

    def test_resume_known_persisted_plan_starts_thread(self):
        resp = self.client.post("/api/mech/plan/known/resume")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "started")
        # The thread may not have run yet — join it via the unit's record.
        for _ in range(50):
            if self.unit.resumed:
                break
            threading.Event().wait(0.02)
        self.assertEqual(self.unit.resumed, ["known"])

    def test_resume_unknown_plan_is_404(self):
        resp = self.client.post("/api/mech/plan/nope/resume")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.unit.resumed, [])

    def test_pause_route_still_calls_pause(self):
        resp = self.client.post("/api/mech/plan/known/pause")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.unit.paused, ["known"])


class TestReattachRoutes(unittest.TestCase):
    def setUp(self):
        self.unit = StubUnit()
        self.client = make_app(self.unit).test_client()

    def test_plans_list(self):
        resp = self.client.get("/api/mech/plans")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["plans"][0]["plan_id"], "known")

    def test_plan_detail(self):
        resp = self.client.get("/api/mech/plan/known")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["intent_id"], "wifi_pmkid")

    def test_plan_detail_unknown_is_404(self):
        resp = self.client.get("/api/mech/plan/nope")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
