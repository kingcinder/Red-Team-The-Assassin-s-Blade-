import os
import shutil
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.orchestrator import Orchestrator
from tools.wireless import WirelessTools


def make_orchestrator():
    import yaml
    root = os.path.join(os.path.dirname(__file__), "..")
    config = yaml.safe_load(open(os.path.join(root, "config.yaml")))
    tmp = tempfile.mkdtemp(prefix="chain-contract-")
    config["harness"]["session_dir"] = os.path.join(tmp, "sessions")
    config["workflow"]["tasks_dir"] = os.path.join(tmp, "tasks")
    return Orchestrator(config), tmp


def test_wireless_chain_is_exposed_as_four_steps():
    chain = WirelessTools(None).get_preset_attack_chains()[0]
    assert [step["tool"] for step in chain["steps"]] == [
        "monitor_mode_enable", "airodump_capture", "aireplay_attack", "aircrack_crack"
    ]


def test_plan_prompt_requires_complete_chain_and_plan_shape():
    orch, tmp = make_orchestrator()
    try:
        sid = orch.new_session("chain")
        captured = {}
        def fake_chat(messages, schema, **kwargs):
            captured["prompt"] = messages[-1]["content"]
            return '{"plan": [{"step": 1, "tool": "kismet_scan", "description": "scan"}, {"step": 2, "tool": "airodump_capture", "description": "capture"}, {"step": 3, "tool": "aireplay_attack", "description": "deauth"}, {"step": 4, "tool": "aircrack_crack", "description": "crack"}]}'
        with patch.object(orch.llm, "chat_structured", side_effect=fake_chat):
            plan = orch._generate_plan(sid, "Run attack chain WiFi Cracking Pipeline")
        assert len(plan) == 4
        assert "one step per phase" in captured["prompt"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
