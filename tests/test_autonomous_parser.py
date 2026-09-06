"""
Tests for the orchestrator's robust tool-call parsing, fuzzy matching,
and error-resilient engagement loop.
"""
import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.orchestrator import Orchestrator


def _make_orchestrator():
    """Build a minimal Orchestrator with mocked subsystems."""
    config = {
        "llm": {"backend": "llama-server", "llama-server": {"host": "127.0.0.1", "port": 8080}},
        "harness": {"session_dir": "/tmp/test_sessions"},
    }
    with patch("core.orchestrator.LLMBackend"), \
         patch("core.orchestrator.ToolRegistry") as MockTR, \
         patch("core.orchestrator.SessionManager"), \
         patch("core.orchestrator.SafetyEngine"), \
         patch("core.orchestrator.HardenedToolRunner"), \
         patch("core.orchestrator.ParallelExecutor"), \
         patch("core.orchestrator.ContextManager"), \
         patch("core.orchestrator.TacticalEngine"), \
         patch("core.orchestrator.TargetPrioritizer"), \
         patch("core.orchestrator.ToolScorer"), \
         patch("core.orchestrator.VectorMemory"), \
         patch("core.orchestrator.ToolInstaller"), \
         patch("core.orchestrator.PromptBuilder"), \
         patch("core.orchestrator.ToolInterceptor"), \
         patch("core.orchestrator.MultiTargetScheduler"), \
         patch("core.orchestrator.WorkflowGenerator"), \
         patch("core.orchestrator.FindingCorrelator"), \
         patch("core.orchestrator.KnowledgeBase"):
        orch = Orchestrator(config)
        # Mock tool registry with known tools
        orch.tools.get_all_tools.return_value = {
            "nmap_scan": MagicMock(name="nmap_scan"),
            "airodump_capture": MagicMock(name="airodump_capture"),
            "monitor_mode_enable": MagicMock(name="monitor_mode_enable"),
            "interface_discovery": MagicMock(name="interface_discovery"),
            "tcpdump_capture": MagicMock(name="tcpdump_capture"),
        }
        return orch


class TestConcatenatedJSONParsing:
    """Handle concatenated JSON objects from the LLM."""

    def test_single_tool_call(self):
        orch = _make_orchestrator()
        response = '{"tool_call": {"tool": "nmap_scan", "args": {"target": "192.168.1.1"}}}'
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"
        assert calls[0]["args"]["target"] == "192.168.1.1"

    def test_concatenated_tool_calls_and_plan(self):
        orch = _make_orchestrator()
        response = (
            '{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "192.168.1.1"}}]}'
            '{"plan": [{"step": 1, "tool": "nmap_scan"}]}'
        )
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"

    def test_multiple_json_objects_with_tool_calls(self):
        orch = _make_orchestrator()
        response = (
            '{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "192.168.1.1"}}]}'
            '{"tool_calls": [{"tool": "airodump_capture", "args": {"interface": "wlan0mon"}}]}'
        )
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 2
        assert calls[0]["tool"] == "nmap_scan"
        assert calls[1]["tool"] == "airodump_capture"

    def test_plan_only_response(self):
        orch = _make_orchestrator()
        response = '{"plan": [{"step": 1, "tool": "nmap_scan", "description": "scan"}]}'
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 0  # Plans are not tool calls

    def test_bare_tool_format(self):
        orch = _make_orchestrator()
        response = '{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}'
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"

    def test_deduplication(self):
        orch = _make_orchestrator()
        response = (
            '{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}]}'
            '{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}]}'
        )
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1  # Deduplicated

    def test_mixed_valid_and_invalid_json(self):
        orch = _make_orchestrator()
        response = 'Some text before {"tool_call": {"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}} and after'
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"

    def test_empty_response(self):
        orch = _make_orchestrator()
        assert orch._parse_tool_calls("") == []
        assert orch._parse_tool_calls("No tools needed.") == []

    def test_invalid_json(self):
        orch = _make_orchestrator()
        assert orch._parse_tool_calls("{not valid json}") == []


class TestFuzzyToolMatching:
    """Find closest tool name when LLM hallucinates."""

    def test_exact_match(self):
        orch = _make_orchestrator()
        assert orch._fuzzy_match_tool("nmap_scan") == "nmap_scan"

    def test_substring_match(self):
        orch = _make_orchestrator()
        match = orch._fuzzy_match_tool("nmap")
        assert match == "nmap_scan"

    def test_close_match_airodump(self):
        orch = _make_orchestrator()
        # LLM might say "airodump" instead of "airodump_capture"
        match = orch._fuzzy_match_tool("airodump")
        assert match == "airodump_capture"

    def test_monitor_match(self):
        orch = _make_orchestrator()
        match = orch._fuzzy_match_tool("monitor_mode")
        assert match is not None

    def test_no_match_for_completely_unknown(self):
        orch = _make_orchestrator()
        match = orch._fuzzy_match_tool("xyzzy_nothing")
        assert match is None


class TestExtractAllJsonObjects:
    """Verify the brace-depth JSON extractor."""

    def test_two_sequential_objects(self):
        orch = _make_orchestrator()
        text = '{"a": 1}{"b": 2}'
        objects = orch._extract_all_json_objects(text)
        assert len(objects) == 2
        assert objects[0] == {"a": 1}
        assert objects[1] == {"b": 2}

    def test_nested_objects(self):
        orch = _make_orchestrator()
        text = '{"tool_calls": [{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}]}'
        objects = orch._extract_all_json_objects(text)
        assert len(objects) == 1
        assert objects[0]["tool_calls"][0]["tool"] == "nmap_scan"

    def test_text_surrounding_json(self):
        orch = _make_orchestrator()
        text = 'Here is my tool call: {"tool_call": {"tool": "nmap_scan", "args": {}}}'
        objects = orch._extract_all_json_objects(text)
        assert len(objects) == 1
        assert objects[0]["tool_call"]["tool"] == "nmap_scan"

    def test_empty_string(self):
        orch = _make_orchestrator()
        assert orch._extract_all_json_objects("") == []

    def test_no_json(self):
        orch = _make_orchestrator()
        assert orch._extract_all_json_objects("Just plain text.") == []
