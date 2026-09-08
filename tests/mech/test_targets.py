"""Tests for the Mech-Unit TARGETS scan bridge (v7.1 Task 6).

Key behavior: after monitor_mode_enable, the scan must rebind to the
monitor vhost when airmon renamed the interface (wlan0 → wlan0mon) —
scanning the dead managed interface was every novice's first failure.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.targets import scan_wireless  # noqa: E402

AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
    "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:FF, 2026-09-08 09:00:00, 2026-09-08 09:01:00, 6, 54, "
    "WPA2, CCMP, PSK, -42, 120, 30, 0.0.0.0, 5, TestNet, \n"
    "\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, "
    "Probed ESSIDs\n")


class CaptureStateStub:
    def __init__(self):
        self.iface = "wlan0"
        self.scan = {}

    def get(self):
        return self.iface

    def set(self, iface):
        self.iface = iface

    def get_scan(self):
        return self.scan

    def set_scan(self, **kw):
        self.scan.update(kw)


class RecordingRunner:
    """Records execute() calls; fakes airodump output to the sandbox."""

    def __init__(self, csv_text):
        self.calls = []
        self.csv_text = csv_text

    def execute(self, tool_name, args, timeout=300, sandbox_output_dir=None):
        self.calls.append({"tool": tool_name, "args": dict(args)})
        if tool_name == "airodump_capture":
            prefix = args.get("capture_file", "")
            for suffix in ("-01.csv", ".csv"):
                path = f"{prefix}{suffix}"
                if os.path.isdir(os.path.dirname(path) or "."):
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(self.csv_text)
                    break
        return {"stdout": "", "stderr": "", "exit_code": 0,
                "duration": 0.1, "blocked": False, "killed": False}


def _orch(cs, runner):
    from types import SimpleNamespace
    return SimpleNamespace(capture_state=cs, runner=runner)


class TestScanRebind(unittest.TestCase):
    def setUp(self):
        self.old_cwd = os.getcwd()
        os.chdir(tempfile.mkdtemp())  # scan writes ./tasks/mech/_scans

    def tearDown(self):
        os.chdir(self.old_cwd)

    def _patch_monitor_probe_ok(self):
        return mock.patch("core.mech.probes.run_probe",
                          return_value=mock.Mock(ok=True, reason="", fix=""))

    def test_rebinds_to_monitor_vhost_after_enable(self):
        cs = CaptureStateStub()
        runner = RecordingRunner(AIRODUMP_CSV)
        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces",
                        return_value=[
                            {"name": "wlan0", "wireless": True, "monitor": False, "up": True},
                            {"name": "wlan0mon", "wireless": True, "monitor": True, "up": True}]):
            result = scan_wireless(_orch(cs, runner), interface="wlan0", duration=10)
        self.assertTrue(result["ok"])
        self.assertEqual(result["interface_used"], "wlan0mon")
        sweep = next(c for c in runner.calls if c["tool"] == "airodump_capture")
        self.assertEqual(sweep["args"]["interface"], "wlan0mon")
        self.assertEqual(cs.iface, "wlan0mon")  # resolvers inherit the vhost

    def test_keeps_name_when_no_vhost_appears(self):
        cs = CaptureStateStub()
        runner = RecordingRunner(AIRODUMP_CSV)
        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces",
                        return_value=[
                            {"name": "wlan1mon", "wireless": True, "monitor": True, "up": True}]):
            result = scan_wireless(_orch(cs, runner), interface="wlan1mon", duration=10)
        self.assertTrue(result["ok"])
        self.assertEqual(result["interface_used"], "wlan1mon")

    def test_response_carries_interface_used(self):
        cs = CaptureStateStub()
        runner = RecordingRunner(AIRODUMP_CSV)
        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces", return_value=[]):
            result = scan_wireless(_orch(cs, runner), interface="wlan0", duration=10)
        self.assertEqual(result["interface_used"], "wlan0")

    def test_parses_aps(self):
        cs = CaptureStateStub()
        runner = RecordingRunner(AIRODUMP_CSV)
        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces", return_value=[]):
            result = scan_wireless(_orch(cs, runner), interface="wlan0", duration=10)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["targets"][0]["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["targets"][0]["essid"], "TestNet")

    def test_blocked_sweep_reports_failure_not_empty_scan(self):
        """A blocked/failed airodump run is a scan error, never a fake
        ok:True with 0 targets — the TARGETS grid must surface it."""
        cs = CaptureStateStub()

        class BlockedRunner:
            def __init__(self):
                self.calls = []

            def execute(self, tool_name, args, timeout=300,
                        sandbox_output_dir=None):
                self.calls.append(tool_name)
                if tool_name == "airodump_capture":
                    return {"stdout": "", "stderr": "airodump-ng not installed",
                            "exit_code": -1, "duration": 0.0, "blocked": True,
                            "block_reason": "not_installed", "killed": False}
                return {"stdout": "", "stderr": "", "exit_code": 0,
                        "duration": 0.1, "blocked": False, "killed": False}

        runner = BlockedRunner()
        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces", return_value=[]):
            result = scan_wireless(_orch(cs, runner), interface="wlan0", duration=10)
        self.assertFalse(result["ok"])
        self.assertIn("not_installed", result["error"])
        self.assertIn("airodump", result["error"])

    def test_nonzero_sweep_reports_failure(self):
        cs = CaptureStateStub()

        class FailRunner:
            def execute(self, tool_name, args, timeout=300,
                        sandbox_output_dir=None):
                if tool_name == "airodump_capture":
                    return {"stdout": "", "stderr": "permission denied",
                            "exit_code": 1, "duration": 0.1, "blocked": False,
                            "killed": False}
                return {"stdout": "", "stderr": "", "exit_code": 0,
                        "duration": 0.1, "blocked": False, "killed": False}

        with self._patch_monitor_probe_ok(), \
             mock.patch("core.mech.targets.list_interfaces", return_value=[]):
            result = scan_wireless(_orch(cs, FailRunner()), interface="wlan0",
                                   duration=10)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
