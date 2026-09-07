"""Legacy/mech bridge tests (v7.0 P5.4): mode default, mech-mode plan
driving, budget mapping, finding feedback. The legacy path must remain
byte-for-byte unchanged when mode is legacy or absent."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.bridge import (  # noqa: E402
    harness_mode, MechCampaignDriver, _extract_bssid)


class TestHarnessMode(unittest.TestCase):
    def test_default_is_legacy_when_key_absent(self):
        self.assertEqual(harness_mode({}), "legacy")
        self.assertEqual(harness_mode(None), "legacy")
        self.assertEqual(harness_mode({"harness": {}}), "legacy")
        self.assertEqual(harness_mode({"harness": {"mode": "legacy"}}), "legacy")

    def test_mech_mode_selected(self):
        self.assertEqual(harness_mode({"harness": {"mode": "mech"}}), "mech")

    def test_non_dict_config_is_legacy(self):
        self.assertEqual(harness_mode("nonsense"), "legacy")


class TestExtractors(unittest.TestCase):
    def test_bssid(self):
        self.assertEqual(_extract_bssid("BSSID AA:BB:CC:DD:EE:FF found"),
                         "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(_extract_bssid("no mac here"))

    def test_bssid_invalid_skipped(self):
        # 4 bytes only → not a BSSID
        self.assertIsNone(_extract_bssid("AA:BB:CC:DD"))


class TestMechModeDrive(unittest.TestCase):
    """End-to-end: mech-mode agent drives intent plans instead of the LLM."""

    def _make_agent(self, mode):
        """A real AutonomousAgent with a stub orchestrator."""
        from unittest.mock import MagicMock
        from core.autonomous import AutonomousAgent

        orch = MagicMock()
        orch.config = {"harness": {"mode": mode, "session_dir": "./sessions"}}
        if mode == "mech":
            # Real MechUnit against the shipped attacks/ dir.
            from core.mech import MechUnit
            unit = MechUnit(config=orch.config)
            driver = MechCampaignDriver(orch, unit)
        else:
            driver = None

        agent = AutonomousAgent.__new__(AutonomousAgent)
        # Mimic __init__ wiring for the fields the drive path touches.
        agent.orch = orch
        agent.state = __import__("core.autonomous", fromlist=["AgentState"]) \
            .AgentState.IDLE
        agent._targets = []
        agent._target_phases = {}
        agent._objective = ""
        agent._lock = __import__("threading").Lock()
        agent._pause_event = __import__("threading").Event()
        agent._pause_event.set()
        agent._priority = MagicMock()
        agent._priority.reorder_targets.side_effect = \
            lambda d: list(d.keys())
        agent._priority.phase_budget.return_value = 1
        agent._priority.score_target.return_value = 0.5
        agent._priority.findings_count.return_value = 0
        agent._priority.tier.return_value = "neutral"
        agent._has_execute_direct = False
        agent._capture_state = None
        agent._start_time = "2026-09-06T00:00:00"
        agent._callbacks = {}
        agent._mode = mode
        agent._mech_driver = driver
        agent._total_steps = 0
        agent._total_findings = 0
        agent._timeline = []
        return agent

    def test_mech_mode_completes_target_without_llm(self):
        from core.autonomous import TargetPhase
        agent = self._make_agent("mech")
        tp = TargetPhase("AA:BB:CC:DD:EE:FF")
        agent._target_phases[tp.target] = tp
        # Drive with a seeded discovery finding (probe pass on this box is
        # not guaranteed for every intent, so the bridge may block — assert
        # the deterministic behavior, not a specific intent).
        tp.phase_findings["recon"].append({
            "title": "BSSID AA:BB:CC:DD:EE:FF", "detail": "AP discovered",
            "severity": "info", "stdout": ""})
        agent._drive_target(tp, sweep_only=False)
        # The mech path marks the target complete without any LLM session.
        self.assertTrue(tp.completed)

    def test_legacy_mode_path_untouched(self):
        """mode=legacy → the bridge must NOT intercept _drive_target."""
        from core.autonomous import TargetPhase
        agent = self._make_agent("legacy")
        self.assertIsNone(agent._mech_driver)
        tp = TargetPhase("10.0.0.9")
        agent._target_phases[tp.target] = tp
        # Legacy drive calls new_session + sessions.* — stub them.
        agent.orch.new_session.return_value = "sess-1"
        agent.orch.sessions.get_messages.return_value = []
        agent.orch.prompts.dynamic.return_value = "phase prompt"
        agent.orch.sessions.add_message = lambda *a, **k: None
        agent.orch._run_iteration.return_value = {
            "results": [], "llm_response": "", "action": "complete",
            "error": None}
        try:
            agent._drive_target(tp, sweep_only=False)
        except Exception:
            self.fail("legacy drive path must execute exactly as before")
        # Legacy path never marks complete by itself here — no mech plan ran.
        self.assertFalse(any(
            "mech round" in str(f.get("summary", ""))
            for flist in tp.phase_findings.values() for f in flist))


if __name__ == "__main__":
    unittest.main()
