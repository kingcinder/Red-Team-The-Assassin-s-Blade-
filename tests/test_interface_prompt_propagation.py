import os
import sys
import tempfile
import yaml
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.orchestrator import Orchestrator


def make_orchestrator():
    root = tempfile.mkdtemp(prefix="interface-propagation-")
    with open(os.path.join(os.path.dirname(__file__), "..", "config.yaml")) as fh:
        config = yaml.safe_load(fh)
    config["harness"]["session_dir"] = os.path.join(root, "sessions")
    config["workflow"]["tasks_dir"] = os.path.join(root, "tasks")
    return Orchestrator(config), root


def test_selected_interface_replaces_llm_placeholder_defaults():
    orchestrator, root = make_orchestrator()
    try:
        sid = orchestrator.new_session("interface")
        orchestrator.sessions.add_message(
            sid, "system", "Selected capture interface: wlxdcef09d3ad89"
        )
        response = '{"tool_call":{"tool":"tcpdump_capture","args":{"interface":"eth0"}}}'
        with patch.object(orchestrator, "_call_llm_with_corrections", return_value=(response, 0)), \
             patch.object(orchestrator.runner, "execute", return_value={
                 "stdout": "", "stderr": "", "exit_code": 0, "duration": 0
             }):
            step = orchestrator._run_iteration(sid, [])
        assert step["tool_calls"][0]["args"]["interface"] == "wlxdcef09d3ad89"
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
