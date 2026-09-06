"""v6.3.4 — Allowed-tool enforcement: unregistered tools are REFUSED immediately
with the nearest registered alternative suggested, never silently executed."""

import json
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")

from core.orchestrator import Orchestrator, TOOL_ALIASES, TOOL_ALIAS_KEYWORDS
from core.tool_registry import ToolRegistry


def _real_orch(llm_response="", tool_calls=None, registry_keys=None):
    """Build a real Orchestrator via __new__ with only the deps _run_iteration's
    enforcement branch touches stubbed. The tool-registration check hits the REAL
    ToolRegistry (defaults to the full registered set)."""
    o = Orchestrator.__new__(Orchestrator)
    o.tools = ToolRegistry({})
    keys = set(o.tools.get_all_tools().keys())
    if registry_keys is not None:
        # Simulate a hypothetical registry extra tool for positive-control tests
        real = o.tools.get_all_tools()
        o.tools.get_all_tools = lambda: {**real, **{k: real[next(iter(real))] for k in registry_keys}}
    o.sessions = MagicMock()
    o.sessions.get_messages.return_value = []
    o.context = MagicMock()
    o.context.trim.side_effect = lambda msgs: msgs
    o.llm = MagicMock()
    o.safety = MagicMock()
    o.safety.check_tool.return_value = (True, "")
    o.runner = MagicMock()
    o.runner.execute.return_value = {"exit_code": 0, "stdout": "x", "stderr": ""}
    o.parallel = MagicMock()
    o.interceptor = MagicMock()
    o.scorer = MagicMock()
    o.prompts = MagicMock()
    o.tactics = MagicMock()
    o.tactics.evaluate.return_value = []
    o._emit = lambda *a, **k: None
    o._autonomous = False
    o._selected_interface = lambda session_id: None
    o.config = {}
    o._running = False
    o._current_session = "s"
    o._generate_report = MagicMock(return_value="")
    o._parse_tool_calls = (lambda r: tool_calls) if tool_calls is not None else MagicMock()
    o._call_llm_with_corrections = MagicMock(return_value=(llm_response, 0))
    o._is_engagement_complete = MagicMock(return_value=False)
    o.memory = MagicMock()
    return o


class TestRecommendTool(unittest.TestCase):
    def test_alias_exact(self):
        o = _real_orch()
        self.assertEqual(o._recommend_tool("arp_spoof"),
                         ["ettercap_mitm", "bettercap_mitm"])
        self.assertEqual(o._recommend_tool("wpa_crack"),
                         ["wifite_auto", "aircrack_crack"])

    def test_keyword_category(self):
        o = _real_orch()
        # Name not in exact aliases but clearly relates to a category
        self.assertEqual(o._recommend_tool("arp_poison_v2"),
                         ["ettercap_mitm", "bettercap_mitm"])
        self.assertEqual(o._recommend_tool("bulk_deauth"),
                         ["aireplay_attack"])

    def test_alias_maps_contain_registered_tools(self):
        reg = set(ToolRegistry({}).get_all_tools().keys())
        for name, sugg in TOOL_ALIASES.items():
            self.assertTrue(name not in reg, f"{name} is already registered; alias is dead")
            for s in sugg:
                self.assertIn(s, reg, f"alias target '{s}' not registered")

    def test_fuzzy_fallback(self):
        o = _real_orch()
        # Confident substring fallback only (never loose token/levenshtein).
        self.assertEqual(o._recommend_tool("nmap"), ["nmap_scan"])
        # A totally unrelated name must NOT produce a wrong suggestion.
        self.assertEqual(o._recommend_tool("totally_bogus_tool_x"), [])

    def test_empty_and_unknown(self):
        o = _real_orch()
        self.assertEqual(o._recommend_tool(""), [])
        self.assertEqual(o._recommend_tool(None), [])
        self.assertEqual(o._recommend_tool(123), [])


class TestRunIterationRefusal(unittest.TestCase):
    def _refused_result(self, tool_name):
        tc = {"tool": tool_name, "args": {"target_ip": "192.168.1.50"}}
        o = _real_orch(llm_response="", tool_calls=[tc])
        step = o._run_iteration("s", [])
        self.assertIsNotNone(o._parse_tool_calls)  # sanity: tool_calls supplied
        o._call_llm_with_corrections.assert_called_once()
        return o, step

    def test_unregistered_tool_refused_and_suggested(self):
        o, step = self._refused_result("arp_spoof")
        # The invalid call never executes.
        self.assertIsNone(o.runner.execute.call_args, "runner.execute should not be called")
        # A REFUSED system message with the nearest alternative is recorded.
        msg_calls = [c for c in o.sessions.add_message.call_args_list]
        refused_msgs = [c[0][2] for c in msg_calls if "REFUSED" in c[0][2]]
        self.assertTrue(refused_msgs, "expected a REFUSED system message")
        self.assertIn("ettercap_mitm", refused_msgs[0])
        self.assertIn("bettercap_mitm", refused_msgs[0])
        # The step records a refused result entry for the dashboard.
        refused_results = [r for r in step.get("results", [])
                           if r.get("status") == "refused" and r.get("tool") == "arp_spoof"]
        self.assertEqual(len(refused_results), 1)
        self.assertIn("ettercap_mitm", refused_results[0]["reason"])

    def test_unknown_tool_no_recommendation_still_refused(self):
        o, step = self._refused_result("totally_bogus_tool_x")
        self.assertIsNone(o.runner.execute.call_args, "runner.execute should not be called")
        refused_msgs = [c[0][2] for c in o.sessions.add_message.call_args_list
                        if "REFUSED" in c[0][2]]
        self.assertTrue(refused_msgs)
        self.assertIn("Available tools", refused_msgs[0])

    def test_registered_tool_not_refused(self):
        # Positive control: a real registered tool must NOT be refused.
        o = _real_orch(llm_response="", tool_calls=[{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}])
        step = o._run_iteration("s", [])
        refused = [r for r in step.get("results", []) if r.get("status") == "refused"]
        self.assertEqual(refused, [])


if __name__ == "__main__":
    unittest.main()