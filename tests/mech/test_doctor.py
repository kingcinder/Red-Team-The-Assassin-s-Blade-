"""Tests for the Mech-Unit doctor (v7.1 Task 5).

The doctor is the novice's first-run experience: one call that says what
the host can do and, per intent, what's missing and how to fix it.
"""
import os
import sys
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.probes import host_readiness, ProbeResult  # noqa: E402


def _unit(sandbox):
    from core.mech import MechUnit, DEFAULT_MANIFEST_DIR
    return MechUnit(config={}, manifest_dir=DEFAULT_MANIFEST_DIR,
                    sandbox_root=sandbox)


class TestHostReadiness(unittest.TestCase):
    def test_reports_both_parameterless_probes(self):
        r = host_readiness()
        names = [p["probe"] for p in r["probes"]]
        self.assertIn("wireless_adapter_monitor_capable", names)
        self.assertIn("running_as_root", names)

    def test_ok_reflects_probe_outcomes(self):
        results = [ProbeResult(probe="a", ok=True),
                   ProbeResult(probe="b", ok=False, reason="x", fix="y")]
        with mock.patch("core.mech.probes.run_probe",
                        side_effect=lambda n, p=[]: results[0] if n == "a" else results[1]):
            r = host_readiness()
        self.assertFalse(r["ok"])
        self.assertEqual(r["probes"][1]["fix"], "y")

    def test_never_raises(self):
        with mock.patch("core.mech.probes.run_probe",
                        side_effect=RuntimeError("boom")):
            r = host_readiness()
        self.assertFalse(r["ok"])
        self.assertTrue(all(p["ok"] is False for p in r["probes"]))


class TestDoctor(unittest.TestCase):
    def test_doctor_reports_every_intent(self):
        unit = _unit(tempfile.mkdtemp())
        d = unit.doctor()
        self.assertEqual(len(d["intents"]), len(unit.list_intents()))
        self.assertIn("host", d)
        for entry in d["intents"]:
            self.assertIn("ready", entry)
            self.assertIn("missing", entry)
            self.assertIn("fix", entry)

    def test_intent_entries_reflect_probe_results(self):
        unit = _unit(tempfile.mkdtemp())
        d = unit.doctor()
        # The real probe set on a non-root test host: at least one intent
        # must report missing items with a fix string.
        blocked = [e for e in d["intents"] if not e["ready"]]
        self.assertTrue(blocked, "expected at least one blocked intent in CI")
        self.assertTrue(all(e["fix"] for e in blocked))


class TestDoctorCli(unittest.TestCase):
    def test_cli_doctor_renders_human_report(self):
        from core.mech.cli import run_mech_cli
        out = io.StringIO()
        with redirect_stdout(out):
            code = run_mech_cli({}, ["doctor"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("HOST", text)
        self.assertIn("INTENTS", text)
        self.assertIn("wifi_pmkid", text)
        # The report must be valid JSON too (machine-readable tail).
        json.loads(text[text.index("{"):])
