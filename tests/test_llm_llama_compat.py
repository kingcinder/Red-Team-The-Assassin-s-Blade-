import os
import shutil
import sys
import tempfile
import yaml
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.llm_backend import LLMBackend


def backend(section=None):
    return LLMBackend({"backend": "llama-server", "llama-server": {
        "host": "127.0.0.1", "port": 1, "model": "x", **(section or {})
    }})


def test_format_messages_contract():
    cases = [
        ([{"role": "user", "content": "hi"}], ["user"]),
        ([{"role": "assistant", "content": "a"}, {"role": "assistant", "content": "b"}], ["assistant", "user"]),
        ([{"role": "assistant", "content": "[ERROR] boom"}], ["system", "user"]),
    ]
    for messages, expected_roles in cases:
        assert [m["role"] for m in backend()._format_messages(messages)] == expected_roles


def test_format_merges_assistant_content():
    out = backend()._format_messages([
        {"role": "assistant", "content": "first"},
        {"role": "assistant", "content": "second"},
    ])
    assert out[0]["content"] == "first\nsecond"
    assert out[-1]["content"].startswith("[HARNESS] Continue")


def capture_payload(llm, **kwargs):
    captured = {}
    def post(url, json=None, timeout=None, stream=False, **unused):
        captured.update(payload=json, timeout=timeout)
        raise __import__("requests").ConnectionError("offline")
    with patch("requests.post", side_effect=post):
        llm.chat([{"role": "user", "content": "hi"}], **kwargs)
    return captured


def test_generation_config_and_call_overrides():
    llm = backend({"max_tokens": 512, "temperature": 0.7, "timeout": 42,
                   "reasoning_effort": "high"})
    payload = capture_payload(llm)
    assert {k: payload["payload"][k] for k in ("max_tokens", "temperature", "reasoning_effort")} == {
        "max_tokens": 512, "temperature": 0.7, "reasoning_effort": "high"}
    assert payload["timeout"] == 42
    overridden = capture_payload(llm, max_tokens=128, temperature=0.1, timeout=9,
                                 reasoning_effort="none")
    assert overridden["payload"]["max_tokens"] == 128
    assert overridden["payload"]["temperature"] == 0.1
    assert overridden["payload"]["reasoning_effort"] == "none"
    assert overridden["timeout"] == 9


def test_generation_defaults():
    llm = backend()
    assert (llm.max_tokens, llm.temperature, llm.timeout, llm.reasoning_effort) == (4096, 0.3, 120, "none")


def _orchestrator():
    tmp = tempfile.mkdtemp(prefix="llama-compat-")
    config = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "config.yaml")))
    config["harness"]["session_dir"] = os.path.join(tmp, "sessions")
    config["workflow"]["tasks_dir"] = os.path.join(tmp, "tasks")
    from core.orchestrator import Orchestrator
    return Orchestrator(config), tmp


def test_error_response_is_not_stored_as_assistant():
    orch, tmp = _orchestrator()
    try:
        sid = orch.new_session("error")
        orch.sessions.add_message(sid, "user", "test")
        with patch.object(orch.llm, "chat", return_value="[ERROR] offline"):
            step = orch._run_iteration(sid, [])
        assert step["action"] == "error" and step["error"]
        assert not any(m["role"] == "assistant" and m["content"].startswith("[ERROR]")
                       for m in orch.sessions.get_messages(sid))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_parser_rejects_invalid_call_shapes():
    orch, tmp = _orchestrator()
    try:
        assert orch._parse_tool_calls('{"tool_calls":[{"tool":42,"args":{}},{"tool":"nmap_scan","args":[]}]}' ) == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
