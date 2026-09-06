"""Tests for Qwen 3.8 model compatibility.

Validates:
- XML <tool_call> format parsing
- <think> tag stripping from responses and stored messages
- System prompt contains Qwen-specific guidance
- Repeat penalty applied to llama-server payload
"""
import json
import pytest
import yaml
from unittest.mock import MagicMock, patch

from core.orchestrator import Orchestrator
from core.prompt_builder import PromptBuilder, _BASE_SYSTEM_PROMPT


# ── XML tool_call format ──

class TestXMLToolCallParsing:
    """Parse <tool_call><name>...</name><arguments>...</arguments></tool_call>."""

    @pytest.fixture
    def orch(self):
        cfg = yaml.safe_load(open("config.yaml"))
        return Orchestrator(cfg)

    def test_single_xml_tool_call(self, orch):
        response = "<tool_call>\n<name>nmap_scan</name>\n<arguments>{\"target\": \"192.168.1.1\"}</arguments>\n</tool_call>"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"
        assert calls[0]["args"]["target"] == "192.168.1.1"

    def test_xml_with_thinking_wrapper(self, orch):
        response = "<think>I need to scan the target.</think><tool_call>\n<name>host_discovery</name>\n<arguments>{\"target\": \"10.0.0.0/24\"}</arguments>\n</tool_call>"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "host_discovery"

    def test_xml_with_nested_json_args(self, orch):
        args = {"target": "192.168.1.0/24", "ports": "80,443", "options": {"timing": "T4"}}
        response = f"<tool_call>\n<name>nmap_scan</name>\n<arguments>{json.dumps(args)}</arguments>\n</tool_call>"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["args"] == args

    def test_xml_with_mixed_prose(self, orch):
        response = "I'll scan the network now.\n<tool_call>\n<name>masscan_scan</name>\n<arguments>{\"target\": \"192.168.1.0/24\"}</arguments>\n</tool_call>\nThis will be quick."
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "masscan_scan"

    def test_xml_no_args(self, orch):
        response = "<tool_call>\n<name>interface_discovery</name>\n<arguments>{}</arguments>\n</tool_call>"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "interface_discovery"
        assert calls[0]["args"] == {}

    def test_xml_with_markdown_fence_wrapper(self, orch):
        response = "```<tool_call>\n<name>gobuster_dir</name>\n<arguments>{\"url\": \"http://192.168.1.1\"}</arguments>\n</tool_call>```"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "gobuster_dir"


# ── Thinking tag stripping ──

class TestThinkingTagStripping:
    """Ensure <think> blocks are stripped from responses."""

    @pytest.fixture
    def orch(self):
        cfg = yaml.safe_load(open("config.yaml"))
        return Orchestrator(cfg)

    def test_json_with_thinking(self, orch):
        response = "<think>Let me plan the attack.</think>{\"tool_call\": {\"tool\": \"nmap_scan\", \"args\": {\"target\": \"10.0.0.1\"}}}"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"

    def test_multiple_thinking_blocks(self, orch):
        response = "<think>step 1</think>Analysis...<think>step 2</think>{\"tool_call\": {\"tool\": \"nikto_scan\", \"args\": {\"target\": \"10.0.0.1\"}}}"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1

    def test_thinking_only_no_tool(self, orch):
        response = "<think>I should scan the network</think>I'll scan the network for open ports."
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 0

    def test_thinking_with_xml_tool_call(self, orch):
        response = "<think>Scanning...</think><tool_call>\n<name>nmap_scan</name>\n<arguments>{\"target\": \"10.0.0.1\"}</arguments>\n</tool_call>"
        calls = orch._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0]["tool"] == "nmap_scan"


# ── System prompt ──

class TestPromptBuilderQwen:
    """Validate the system prompt has Qwen 3.8 guidance."""

    @pytest.fixture
    def builder(self):
        cfg = yaml.safe_load(open("config.yaml"))
        from core.tool_registry import ToolRegistry
        from core.tool_scorer import ToolScorer
        from core.vector_memory import VectorMemory
        tr = ToolRegistry(cfg)
        scorer = ToolScorer("/tmp/test_scorer")
        memory = VectorMemory("/tmp/test_memory")
        return PromptBuilder(tr, scorer, memory)

    def test_prompt_forbids_thinking_tags(self, builder):
        prompt = builder.dynamic("recon")
        assert "<think>" in prompt.lower() or "think" in prompt.lower()
        # Must contain explicit instruction to NOT use thinking tags
        assert "Do NOT use <think>" in prompt or "do not use <think>" in prompt.lower()

    def test_prompt_forbids_markdown_fences(self, builder):
        prompt = builder.dynamic("recon")
        assert "Do NOT use markdown" in prompt or "code fences" in prompt

    def test_prompt_requires_json_format(self, builder):
        prompt = builder.dynamic("recon")
        assert "tool_call" in prompt
        assert "tool_calls" in prompt
        assert "{\"tool_call\":" in prompt or '{"tool_call":' in prompt

    def test_prompt_lists_wireless_tools(self, builder):
        prompt = builder.dynamic("recon")
        assert "airodump_capture" in prompt or "interface_discovery" in prompt

    def test_prompt_includes_methodology(self, builder):
        prompt = builder.dynamic("recon")
        assert "Methodology" in prompt or "methodology" in prompt.lower()

    def test_prompt_forbids_hardcoded_interfaces(self, builder):
        prompt = builder.dynamic("recon")
        assert "NEVER hardcode" in prompt or "never hardcode" in prompt.lower()


# ── LLM backend thinking stripping ──

class TestLLMThinkingStripping:
    """Validate the LLM backend strips <think> from stored messages."""

    def test_format_messages_strips_thinking(self):
        from core.llm_backend import LLMBackend
        cfg = yaml.safe_load(open("config.yaml"))
        llm = LLMBackend(cfg.get("llm", {}))
        messages = [
            {"role": "system", "content": "You are a pentester."},
            {"role": "assistant", "content": "<think>Analyzing...</think>{\"tool_call\": {\"tool\": \"nmap\"}}"},
            {"role": "user", "content": "Continue"},
        ]
        formatted = llm._format_messages(messages)
        assert "<think>" not in formatted[1]["content"]
        assert "</think>" not in formatted[1]["content"]

    def test_format_messages_collapses_assistant(self):
        from core.llm_backend import LLMBackend
        cfg = yaml.safe_load(open("config.yaml"))
        llm = LLMBackend(cfg.get("llm", {}))
        messages = [
            {"role": "assistant", "content": "First response"},
            {"role": "assistant", "content": "Second response"},
        ]
        formatted = llm._format_messages(messages)
        # After collapse + trailing user message appended, the assistant
        # messages should be merged into one and a user prompt added.
        assistant_msgs = [m for m in formatted if m["role"] == "assistant"]
        assert len(assistant_msgs) == 1
        assert "First response" in assistant_msgs[0]["content"]
        assert "Second response" in assistant_msgs[0]["content"]


# ── Repeat penalty ──

class TestRepeatPenalty:
    """Validate repeat_penalty is in the llama-server payload."""

    def test_payload_includes_repeat_penalty(self):
        from core.llm_backend import LLMBackend
        cfg = yaml.safe_load(open("config.yaml"))
        llm = LLMBackend(cfg.get("llm", {}))
        with patch("core.llm_backend.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "test"}}],
                "usage": {}
            }
            mock_post.return_value = mock_resp
            llm.chat([{"role": "user", "content": "test"}])
            payload = mock_post.call_args[1]["json"]
            assert "repeat_penalty" in payload
            assert payload["repeat_penalty"] == 1.15
