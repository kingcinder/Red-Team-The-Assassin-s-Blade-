"""Tests for the v6.3 backend capture-interface store + execute_direct defaulting.

Covers:
- CaptureStateStore JSON persistence (set/get/clear, blank no-op, corrupt file)
- Pure default_interface_arg() logic (wireless/sniffing/interface-param tools,
  blank vs explicit, {{placeholder}} handling, non-wireless untouched)
- execute_direct() integration: blank interface filled from the store,
  explicit pick persisted back, non-interface tools untouched.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.capture_state import (  # noqa: E402
    CaptureStateStore, default_interface_arg, default_sniff_args, needs_interface)


class TestCaptureStateStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.store = CaptureStateStore(self._tmp)

    def test_get_empty(self):
        self.assertIsNone(self.store.get())

    def test_set_get_roundtrip(self):
        self.assertTrue(self.store.set("wlan0"))
        self.assertEqual(self.store.get(), "wlan0")

    def test_set_whitespace_trimmed(self):
        self.assertTrue(self.store.set("  wlan1  "))
        self.assertEqual(self.store.get(), "wlan1")

    def test_set_blank_is_noop(self):
        self.assertFalse(self.store.set(""))
        self.assertFalse(self.store.set(None))
        self.assertFalse(self.store.set("   "))
        self.assertIsNone(self.store.get())

    def test_clear(self):
        self.store.set("wlan0")
        self.assertTrue(self.store.clear())
        self.assertIsNone(self.store.get())

    def test_persisted_across_instances(self):
        self.store.set("wlan0mon")
        fresh = CaptureStateStore(self._tmp)
        self.assertEqual(fresh.get(), "wlan0mon")

    def test_corrupt_file_returns_none(self):
        with open(os.path.join(self._tmp, "capture_interface.json"), "w") as fh:
            fh.write("{ not json !!!")
        self.assertIsNone(self.store.get())

    def test_file_has_expected_shape(self):
        self.store.set("wlan0")
        with open(os.path.join(self._tmp, "capture_interface.json")) as fh:
            data = json.load(fh)
        self.assertEqual(data["interface"], "wlan0")
        self.assertIn("updated_at", data)

    # ── scan context (v6.3.1) ────────────────────────────────────────
    def test_get_scan_empty(self):
        self.assertEqual(self.store.get_scan(), {})

    def test_set_scan_roundtrip(self):
        self.assertTrue(self.store.set_scan(channel="6", bssid="AA:BB:CC:DD:EE:FF"))
        scan = self.store.get_scan()
        self.assertEqual(scan["channel"], "6")
        self.assertEqual(scan["bssid"], "AA:BB:CC:DD:EE:FF")

    def test_set_scan_preserves_interface(self):
        self.store.set("wlan0mon")
        self.store.set_scan(channel="11")
        self.assertEqual(self.store.get(), "wlan0mon")
        self.assertEqual(self.store.get_scan()["channel"], "11")

    def test_set_scan_noop_on_blanks(self):
        self.assertFalse(self.store.set_scan(channel="", bssid=""))
        self.assertFalse(self.store.set_scan())
        self.assertEqual(self.store.get_scan(), {})

    def test_get_scan_only_channel(self):
        self.store.set_scan(channel="36")
        scan = self.store.get_scan()
        self.assertEqual(scan.get("channel"), "36")
        self.assertNotIn("bssid", scan)


class TestDefaultInterfaceArg(unittest.TestCase):
    def test_wireless_category_defaults(self):
        args, defaulted = default_interface_arg(
            {}, "wireless", {"interface": {}}, "wlan0")
        self.assertTrue(defaulted)
        self.assertEqual(args["interface"], "wlan0")

    def test_sniffing_category_defaults(self):
        args, defaulted = default_interface_arg(
            {"filter": "tcp"}, "sniffing", {}, "wlan1")
        self.assertTrue(defaulted)
        self.assertEqual(args["interface"], "wlan1")

    def test_interface_param_declared_defaults(self):
        # A non-wireless category that still declares an interface param.
        args, defaulted = default_interface_arg(
            {}, "network", {"interface": {}}, "eth0")
        self.assertTrue(defaulted)
        self.assertEqual(args["interface"], "eth0")

    def test_explicit_pick_untouched(self):
        args, defaulted = default_interface_arg(
            {"interface": "wlan0mon"}, "wireless", {"interface": {}}, "wlan0")
        self.assertFalse(defaulted)
        self.assertEqual(args["interface"], "wlan0mon")

    def test_placeholder_blank(self):
        # An unfilled {{interface}} placeholder counts as blank.
        args, defaulted = default_interface_arg(
            {"interface": "{{interface}}"}, "wireless", {"interface": {}}, "wlan0")
        self.assertTrue(defaulted)
        self.assertEqual(args["interface"], "wlan0")

    def test_no_last_used_no_default(self):
        args, defaulted = default_interface_arg(
            {}, "wireless", {"interface": {}}, None)
        self.assertFalse(defaulted)
        self.assertNotIn("interface", args)

    def test_non_interface_tool_untouched(self):
        args, defaulted = default_interface_arg(
            {"host": "10.0.0.1"}, "recon", {}, "wlan0")
        self.assertFalse(defaulted)
        self.assertEqual(args, {"host": "10.0.0.1"})

    def test_input_args_not_mutated(self):
        original = {"host": "10.0.0.1"}
        result, _ = default_interface_arg(original, "recon", {}, "wlan0")
        self.assertIsNot(result, original)
        self.assertEqual(original, {"host": "10.0.0.1"})


class TestNeedsInterface(unittest.TestCase):
    def test_categories(self):
        self.assertTrue(needs_interface("wireless", None))
        self.assertTrue(needs_interface("sniffing", {}))
        self.assertTrue(needs_interface("network", {"interface": {}}))
        self.assertFalse(needs_interface("recon", {}))
        self.assertFalse(needs_interface("recon", None))


class TestDefaultSniffArgs(unittest.TestCase):
    # ── interface only ────────────────────────────────────────────────
    def test_interface_injected(self):
        args, inj = default_sniff_args(
            {}, "wireless", {"interface": {}}, "wlan0", {})
        self.assertEqual(args["interface"], "wlan0")
        self.assertEqual(inj, {"interface": "wlan0"})

    def test_interface_untouched_when_explicit(self):
        args, inj = default_sniff_args(
            {"interface": "wlan0mon"}, "wireless", {"interface": {}}, "wlan0", {})
        self.assertEqual(args["interface"], "wlan0mon")
        self.assertEqual(inj, {})

    # ── channel hint ─────────────────────────────────────────────────
    def test_channel_injected_for_wireless(self):
        args, inj = default_sniff_args(
            {}, "wireless", {"interface": {}, "channel": {}}, "wlan1",
            {"channel": "6", "bssid": "AA:BB"})
        self.assertEqual(args["channel"], "6")
        self.assertEqual(inj.get("channel"), "6")

    def test_channel_untouched_when_explicit(self):
        args, inj = default_sniff_args(
            {"channel": "11"}, "wireless", {"interface": {}, "channel": {}}, "wlan2",
            {"channel": "6"})
        self.assertEqual(args["channel"], "11")
        self.assertNotIn("channel", inj)

    def test_channel_not_injected_when_no_hint(self):
        args, inj = default_sniff_args(
            {}, "sniffing", {"channel": {}}, "wlan0", {})
        # Interface IS injected (sniffing needs it); channel is NOT because
        # there is no scan hint yet.
        self.assertEqual(args.get("interface"), "wlan0")
        self.assertNotIn("channel", args)
        self.assertNotIn("channel", inj)

    def test_channel_not_injected_for_nonwireless_categories(self):
        # A recon tool with an unexplained "channel" param gets NO scan hint.
        args, inj = default_sniff_args(
            {}, "recon", {"channel": {}}, None, {"channel": "6"})
        self.assertNotIn("channel", args)
        self.assertEqual(inj, {})

    def test_bssid_never_auto_injected(self):
        # bssid is deliberately NEVER auto-injected — explicit AP targeting.
        args, inj = default_sniff_args(
            {}, "wireless", {"interface": {}, "bssid": {}}, "wlan0",
            {"channel": "6", "bssid": "AA:BB:CC:DD:EE:FF"})
        self.assertNotIn("bssid", args)
        self.assertNotIn("bssid", inj)

    def test_input_not_mutated(self):
        original = {"host": "10.0.0.1"}
        result, _ = default_sniff_args(original, "recon", {}, None, {})
        self.assertIsNot(result, original)
        self.assertEqual(original, {"host": "10.0.0.1"})

    # ── placeholder handling ─────────────────────────────────────────-
    def test_placeholder_interface_treated_blank(self):
        args, inj = default_sniff_args(
            {"interface": "{{interface}}"}, "wireless", {"interface": {}}, "wlan0", {})
        self.assertEqual(args["interface"], "wlan0")
        self.assertEqual(inj, {"interface": "wlan0"})


# ── execute_direct integration (no LLM, no real tools) ─────────────────
def _stub_tool(name, category, parameters):
    from types import SimpleNamespace
    return SimpleNamespace(name=name, category=category, parameters=parameters)


class TestExecuteDirectDefaulting(unittest.TestCase):
    def _make_orchestrator(self):
        """Minimal orchestrator stand-in exposing just the execute_direct path."""
        from unittest.mock import MagicMock
        from core.orchestrator import Orchestrator

        # Build a real orchestrator with stubbed internals so execute_direct
        # runs its full defaulting + safety + runner flow without side effects.
        cfg = {"harness": {"session_dir": tempfile.mkdtemp()}}
        inst = Orchestrator.__new__(Orchestrator)
        inst.config = cfg
        inst.capture_state = CaptureStateStore(cfg["harness"]["session_dir"])
        inst.safety = MagicMock()
        inst.safety.check_tool.return_value = (True, "ok")
        inst.runner = MagicMock()
        inst.runner.execute.return_value = {"status": "ok", "output": "done"}
        inst.sessions = MagicMock()
        inst.interceptor = MagicMock()
        inst._current_session = None
        inst.tools = MagicMock()
        def tool_for(name):
            # airodump declares channel + bssid; others just interface.
            if name == "airodump_capture":
                return _stub_tool(name, "wireless", {"interface": {}, "channel": {}, "bssid": {}})
            return _stub_tool(name, "wireless", {"interface": {}})
        inst.tools.get_tool.side_effect = tool_for
        return inst

    def test_blank_interface_filled_from_store(self):
        inst = self._make_orchestrator()
        inst.capture_state.set("wlan0")
        result = inst.execute_direct("airodump_capture", {"channel": "6"})
        self.assertEqual(result["status"], "ok")
        # The defaulted interface must have flowed into the runner call.
        call_args = inst.runner.execute.call_args[0]
        self.assertEqual(call_args[0], "airodump_capture")
        self.assertEqual(call_args[1]["interface"], "wlan0")
        self.assertEqual(call_args[1]["channel"], "6")

    def test_explicit_pick_persisted_to_store(self):
        inst = self._make_orchestrator()
        inst.execute_direct("airodump_capture", {"interface": "wlan0mon"})
        self.assertEqual(inst.capture_state.get(), "wlan0mon")

    def test_blank_with_no_store_value_passes_through(self):
        inst = self._make_orchestrator()
        result = inst.execute_direct("airodump_capture", {"channel": "6"})
        self.assertEqual(result["status"], "ok")
        call_args = inst.runner.execute.call_args[0]
        self.assertNotIn("interface", call_args[1])

    # ── v6.3.1 channel defaulting + scan persistence ─────────────────
    def test_blank_channel_filled_from_last_scan_hint(self):
        inst = self._make_orchestrator()
        inst.capture_state.set("wlan0mon")
        inst.capture_state.set_scan(channel="6", bssid="AA:BB:CC:DD:EE:FF")
        inst.execute_direct("airodump_capture", {})
        call_args = inst.runner.execute.call_args[0]
        self.assertEqual(call_args[1]["interface"], "wlan0mon")
        self.assertEqual(call_args[1]["channel"], "6")

    def test_airodump_explicit_channel_persists_as_scan_hint(self):
        inst = self._make_orchestrator()
        inst.capture_state.set("wlan0mon")
        inst.execute_direct("airodump_capture", {"channel": "11", "bssid": "00:11:22:33:44:55"})
        scan = inst.capture_state.get_scan()
        self.assertEqual(scan["channel"], "11")
        self.assertEqual(scan["bssid"], "00:11:22:33:44:55")

    def test_bssid_never_defaulted_into_runner(self):
        inst = self._make_orchestrator()
        inst.capture_state.set_scan(channel="6", bssid="AA:BB:CC:DD:EE:FF")
        inst.execute_direct("airodump_capture", {"interface": "wlan0mon"})
        call_args = inst.runner.execute.call_args[0]
        # channel is auto-filled; bssid must be ABSENT (explicit targeting).
        self.assertEqual(call_args[1]["channel"], "6")
        self.assertNotIn("bssid", call_args[1])

    def test_non_airodump_wireless_defaults_channel_not_persisting_scan(self):
        # Aireplay declares bssid; its channel is filled but it must NOT
        # overwrite the airodump scan hints.
        inst = self._make_orchestrator()
        inst.capture_state.set_scan(channel="1")
        inst.execute_direct("aireplay_attack", {"bssid": "AA:BB"})
        self.assertEqual(inst.capture_state.get_scan()["channel"], "1")


if __name__ == "__main__":
    unittest.main()
