"""Tests for the v6.3.2 autonomous capture-context injection.

Verifies that the autonomous agent seeds its LLM's tool-selection context with
the operator-selected capture interface (and last airodump scan hints) from the
backend store, so wireless/sniffing steps default to the same adapter the
operator picked — no per-step interface guessing in generated args.

Dives the REAL `_drive_target` (sweep path) and `_transition_phase` methods to
verify wiring, not just the composed string.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.autonomous import AutonomousAgent, AgentState, TargetPhase  # noqa: E402


class _StubState:
    """Minimal stand-in for CaptureStateStore.get()/get_scan()."""

    def __init__(self, iface=None, channel=None, bssid=None):
        self._iface = iface
        self._scan = {}
        if channel:
            self._scan["channel"] = channel
        if bssid:
            self._scan["bssid"] = bssid

    def get(self):
        return self._iface

    def get_scan(self):
        return dict(self._scan)


def _real_agent(state=None, orch=None):
    """Build an AutonomousAgent without running __init__ (heavy), wiring the
    subset of fields the helpers + the two driven methods touch."""
    agent = AutonomousAgent.__new__(AutonomousAgent)
    o = orch or MagicMock()
    o.sessions = MagicMock()
    o.new_session.return_value = "sess-1"
    o.prompts = MagicMock()
    o.prompts.dynamic.return_value = "phase prompt"
    agent.orch = o
    agent._capture_state = state
    agent.state = AgentState.IDLE
    agent._objective = "Test objective"
    agent._pause_event = MagicMock()
    agent._timeline = []
    agent._callbacks = {}
    agent._emit = lambda evt, data: None  # no-op
    agent._drive_phase = MagicMock()       # swept recon uses this
    return agent, o


def _mk_tp(target="192.168.1.50", current="recon"):
    tp = TargetPhase.__new__(TargetPhase)
    tp.target = target
    tp.session_id = None
    tp.current_phase = current
    tp.phase_index = 0
    tp.completed = False
    tp.phase_iterations = {}
    tp.phase_failures = {}
    tp.consecutive_failures = 0
    tp.retry_level = 0
    tp.last_error = None
    tp.advance_phase = MagicMock(return_value="exploit")
    tp.phase_budget = {}
    tp.priority_score = 0
    tp.priority_tier = 0
    return tp


class TestCaptureContext(unittest.TestCase):
    def test_empty_when_no_state(self):
        agent, _ = _real_agent(None)
        agent._capture_state = None
        self.assertEqual(agent._capture_context(), "")

    def test_empty_when_no_interface_stored(self):
        agent, _ = _real_agent(_StubState())  # no interface
        self.assertEqual(agent._capture_context(), "")

    def test_interface_only(self):
        agent, _ = _real_agent(_StubState(iface="wlan0mon"))
        ctx = agent._capture_context()
        self.assertIn("wlan0mon", ctx)
        self.assertIn("[CAPTURE CONTEXT]", ctx)
        # No scan hint line when nothing stored.
        self.assertNotIn("scan hints", ctx)

    def test_interface_plus_channel_and_bssid(self):
        agent, _ = _real_agent(_StubState(
            iface="wlan0mon", channel="6", bssid="AA:BB:CC:DD:EE:FF"))
        ctx = agent._capture_context()
        self.assertIn("wlan0mon", ctx)
        self.assertIn("channel 6", ctx)
        self.assertIn("AA:BB:CC:DD:EE:FF", ctx)

    def test_channel_only_has_no_bssid_value(self):
        agent, _ = _real_agent(_StubState(iface="wlan1", channel="11"))
        ctx = agent._capture_context()
        self.assertIn("channel 11", ctx)
        # The guidance always mentions "bssid" as a word, but no bssid VALUE
        # should be present when only a channel was scanned: the ", bssid "+
        # MAC suffix is only emitted when a bssid was actually stored.
        self.assertNotIn(", bssid", ctx)

    def test_capture_context_handles_store_exception(self):
        agent, _ = _real_agent(None)
        state = MagicMock()
        state.get.side_effect = RuntimeError("boom")
        agent._capture_state = state
        self.assertEqual(agent._capture_context(), "")

    def test_echoes_live_interface_inventory(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon"))
        # v6.3.6: the LLM must see the REAL post-airmon names from /sys/class/net
        # so it plans around wlan0mon instead of guessing wlan0.
        o.tools.get_interface_inventory.return_value = [
            {"name": "wlan0mon", "up": True, "wireless": True, "monitor": True},
            {"name": "eth0", "up": True, "wireless": False, "monitor": False},
            {"name": "wlan0", "up": False, "wireless": True, "monitor": False},
        ]
        ctx = agent._capture_context()
        self.assertIn("Live network interfaces", ctx)
        self.assertIn("wlan0mon: UP wireless MONITOR", ctx)
        self.assertIn("eth0: UP wired", ctx)
        self.assertIn("wlan0: DOWN wireless", ctx)
        self.assertIn("wlan0mon", ctx)  # selected iface still echoed

    def test_inventory_present_without_operator_selection(self):
        agent, o = _real_agent(_StubState())  # no operator iface selected
        o.tools.get_interface_inventory.return_value = [
            {"name": "wlan0mon", "up": True, "wireless": True, "monitor": True},
        ]
        ctx = agent._capture_context()
        # Even with no selection the live list is surfaced so the model trusts
        # the real device names.
        self.assertIn("Live network interfaces", ctx)
        self.assertIn("wlan0mon", ctx)

    def test_inventory_exception_degrades_gracefully(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon"))
        o.tools.get_interface_inventory.side_effect = RuntimeError("boom")
        ctx = agent._capture_context()
        # Falls back to the operator-selected iface only — still returns a block.
        self.assertIn("wlan0mon", ctx)
        self.assertNotIn("Live network interfaces", ctx)

    def test_interface_inventory_empty_dict_list(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon"))
        o.tools.get_interface_inventory.return_value = [
            {"name": "lo", "up": True, "wireless": False, "monitor": False},
        ]
        ctx = agent._capture_context()
        # 'lo' is still reported but the selection is what matters most.
        self.assertIn("wlan0mon", ctx)
        self.assertIn("lo", ctx)


class TestPhaseUsesWireless(unittest.TestCase):
    def test_matrix(self):
        agent, _ = _real_agent()
        self.assertTrue(agent._phase_uses_wireless("recon"))
        self.assertTrue(agent._phase_uses_wireless("exploit"))
        self.assertFalse(agent._phase_uses_wireless("vuln"))
        self.assertFalse(agent._phase_uses_wireless("postex"))
        self.assertFalse(agent._phase_uses_wireless("bogus"))


class TestInitialSeedRealMethod(unittest.TestCase):
    def test_drive_target_seeds_capture_context_on_fresh_session(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon", channel="6"))
        tp = _mk_tp()
        agent._drive_target(tp, sweep_only=True)

        added = [tuple(c.args) for c in o.sessions.add_message.call_args_list]
        roles = [a[1] for a in added if len(a) >= 2]
        # A user objective + a capture system message were both added.
        self.assertEqual(roles.count("user"), 1)
        self.assertEqual(roles.count("system"), 1)
        ctx_msg = next(a[2] for a in added if len(a) >= 3 and a[1] == "system")
        self.assertIn("wlan0mon", ctx_msg)
        self.assertIn("channel 6", ctx_msg)

    def test_drive_target_skips_context_when_no_interface(self):
        agent, o = _real_agent(_StubState())  # no interface
        tp = _mk_tp()
        agent._drive_target(tp, sweep_only=True)
        added = [tuple(c.args) for c in o.sessions.add_message.call_args_list]
        roles = [a[1] for a in added if len(a) >= 2]
        # No system capture message when there is nothing to seed.
        self.assertEqual(roles.count("system"), 0)


class TestPhaseTransitionRealMethod(unittest.TestCase):
    def test_transition_into_wireless_phase_appends_capture(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon"))
        tp = _mk_tp()
        agent._transition_phase(tp)  # advance_phase -> "exploit" (wireless)
        added = [tuple(c.args) for c in o.sessions.add_message.call_args_list]
        self.assertEqual(len(added), 1)
        msg = added[0][2]
        self.assertIn("Phase transition → EXPLOIT", msg)
        self.assertIn("wlan0mon", msg)

    def test_transition_into_nonwireless_phase_skips_capture(self):
        agent, o = _real_agent(_StubState(iface="wlan0mon"))
        tp = _mk_tp()
        tp.advance_phase = MagicMock(return_value="postex")  # not wireless
        agent._transition_phase(tp)
        added = [tuple(c.args) for c in o.sessions.add_message.call_args_list]
        self.assertEqual(len(added), 1)
        msg = added[0][2]
        self.assertIn("Phase transition → POSTEX", msg)
        self.assertNotIn("wlan0mon", msg)


if __name__ == "__main__":
    unittest.main()