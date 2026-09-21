#!/usr/bin/env python3
"""Regression test: WorkflowStateMachine narrative emit channel (backfill).

Before this backfill, the LLM narrative paths called self._emit(...) but no
_emit existed on the class — a latent AttributeError that fired mid-report
whenever an LLM was attached. This pins the channel it was written expecting:
a constructor-injected callbacks registry with orchestrator-style safe
dispatch, wired through from the orchestrator at construction.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock

from core.workflow_engine import WorkflowStateMachine
from core.orchestrator import Orchestrator

TEMPLATE = """
name: "Emit Channel Probe"
category: recon
steps:
  - name: probe
    tool: system_info
    description: "Trivial probe"
    args: {}
    expected_output: null
    timeout: 30
    gate: false
    retries: 0
"""

# Long enough to clear the >=50-char minimum-length guard.
NARRATIVE = ("Executive Summary: the engagement was scoped, executed, and "
             "reported with professional narrative structure throughout.")


def _make_machine(tmpl_path, sandbox, runner, callbacks=None):
    wf = WorkflowStateMachine(tmpl_path, sandbox, runner, {},
                              llm=MagicMock(), callbacks=callbacks)
    wf.llm.chat.return_value = NARRATIVE
    wf.load()
    return wf


def _make_sandbox(d):
    sandbox = MagicMock()
    sandbox.root = d
    sandbox.task_id = "emit_probe_1"
    sandbox.setup.return_value = d
    sandbox.read_output.return_value = ""
    sandbox.save_state = MagicMock()
    sandbox.write_log = MagicMock()
    sandbox.write_output = MagicMock()
    return sandbox


def _setup_template():
    d = tempfile.mkdtemp(prefix="rt_emit_channel_")
    tmpl = os.path.join(d, "t.yaml")
    with open(tmpl, "w") as f:
        f.write(TEMPLATE)
    return d, tmpl


def test_narrative_path_emits_to_registered_callback():
    """The previously-latent AttributeError site now dispatches on_llm_thinking."""
    d, tmpl = _setup_template()
    sandbox = _make_sandbox(d)
    runner = MagicMock()
    runner.execute.return_value = {"stdout": "ok", "stderr": "",
                                   "exit_code": 0, "duration": 0.01,
                                   "blocked": False}
    received = []
    wf = _make_machine(tmpl, sandbox, runner,
                       callbacks={"on_llm_thinking": [received.append]})
    wf._llm_generate_narrative(
        findings=[{"severity": "high", "title": "t", "category": "c",
                   "evidence": "e", "source_tool": "x", "source_step": "1",
                   "context": ""}],
        completed=[{"step": "probe", "tool": "system_info",
                    "status": "success"}],
        warnings=[])
    steps = [ev.get("step") for ev in received]
    assert "executive-summary" in steps, f"narrative event not received: {received}"
    assert all(ev.get("session_id") == "emit_probe_1" for ev in received)
    print("PASS: narrative path emits on_llm_thinking to registered callback")


def test_raising_listener_cannot_break_narrative():
    """A raising listener is logged and swallowed (orchestrator dispatch contract)."""
    d, tmpl = _setup_template()
    sandbox = _make_sandbox(d)
    runner = MagicMock()
    runner.execute.return_value = {"stdout": "ok", "stderr": "",
                                   "exit_code": 0, "duration": 0.01,
                                   "blocked": False}
    received = []

    def bad(_):
        raise RuntimeError("listener bug")

    wf = _make_machine(tmpl, sandbox, runner,
                       callbacks={"on_llm_thinking": [bad, received.append]})
    out = wf._llm_generate_narrative(
        findings=[], completed=[{"step": "probe", "tool": "system_info",
                                 "status": "success"}], warnings=[])
    assert "executive-summary" in [ev.get("step") for ev in received]
    assert out and out == NARRATIVE and len(out) >= 50
    print("PASS: raising listener swallowed, narrative still returned")


def test_standalone_machine_has_safe_noop_channel():
    """No registry injected -> _emit is a safe no-op (default-constructed machines)."""
    d, tmpl = _setup_template()
    sandbox = _make_sandbox(d)
    runner = MagicMock()
    wf = WorkflowStateMachine(tmpl, sandbox, runner, {})
    wf.load()
    wf._emit("on_llm_thinking", {"session_id": sandbox.task_id, "step": "x"})
    wf._emit("on_unknown_event", {})
    print("PASS: standalone machine _emit is a safe no-op")


def test_orchestrator_passes_own_registry_through():
    """WorkflowStateMachine instances built by the orchestrator share its registry."""
    import tempfile
    tmp = tempfile.mkdtemp(prefix="rt_emit_orch_")
    orch = Orchestrator({"harness": {"session_dir": tmp}})
    wf = WorkflowStateMachine("unused.yaml", MagicMock(), MagicMock(), {},
                              callbacks=orch._callbacks)
    assert wf._callbacks is orch._callbacks
    received = []
    orch.on("on_llm_thinking", received.append)
    wf._emit("on_llm_thinking", {"session_id": "s1", "step": "executive-summary"})
    assert received and received[0]["step"] == "executive-summary"
    print("PASS: orchestrator registry rides the same channel end-to-end")


if __name__ == "__main__":
    test_narrative_path_emits_to_registered_callback()
    test_raising_listener_cannot_break_narrative()
    test_standalone_machine_has_safe_noop_channel()
    test_orchestrator_passes_own_registry_through()
    print("All emit-channel regression tests passed.")
