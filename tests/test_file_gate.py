#!/usr/bin/env python3
"""Regression test for the file-existence gate (file_gate) on workflow steps.

Covers: skip when the gated file is missing, skip when it is empty, run when
it is non-empty, blocked (not silently skipped) when a gate path references a
missing variable, and a full start() run completing with the skipped step
recorded as completed + surfaced as a warning.
"""
import os
import sys
import json
import tempfile
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Compile check
py_compile.compile(os.path.join(os.path.dirname(__file__), "..",
                                "core", "workflow_engine.py"), doraise=True)

from unittest.mock import MagicMock

from core.workflow_engine import WorkflowStateMachine

TEMPLATE = """
name: "FileGate Probe"
category: wireless
steps:
  - name: crack_hash
    tool: hashcat_crack
    description: "Crack PMKID"
    args:
      hash_file: "{{pmkid_capture}}.hc22000"
    expected_output: "Cracked|Recovered"
    timeout: 60
    gate: false
    retries: 0
    file_gate:
      - "{{pmkid_capture}}.hc22000"
  - name: fallback
    tool: wifite_auto
    description: "Fallback"
    args:
      interface: "wlan0"
    expected_output: null
    timeout: 60
    gate: false
    retries: 0
"""


def make_engine(tmpl_path, sandbox):
    runner = MagicMock()
    runner.execute.return_value = {
        "stdout": "Cracked PSK, Recovered passphrase: 12345678",
        "stderr": "",
        "exit_code": 0,
        "duration": 0.05,
        "blocked": False,
    }
    wf = WorkflowStateMachine(tmpl_path, sandbox, runner, {"pmkid_capture": "pmkid_cap"})
    wf.load()
    return wf


def make_sandbox(d):
    sandbox = MagicMock()
    sandbox.root = d
    sandbox.task_id = "probe_1"
    sandbox.setup.return_value = d
    sandbox.read_output.return_value = ""
    sandbox.save_state = MagicMock()
    sandbox.write_log = MagicMock()
    sandbox.write_output = MagicMock()
    return sandbox


def test_skip_on_missing_file():
    d = tempfile.mkdtemp(prefix="rt_filegate_")
    tmpl = os.path.join(d, "t.yaml")
    with open(tmpl, "w") as f:
        f.write(TEMPLATE)
    sandbox = make_sandbox(d)

    # 1) No file -> skipped, tool never invoked
    wf = make_engine(tmpl, sandbox)
    r = wf._run_step(0)
    assert r["status"] == "skipped", f"expected skipped, got {r['status']}"
    assert "file_gate" in r["reason"] and "missing or empty" in r["reason"], r["reason"]
    assert r["attempts"] == 0
    # Complete step record for downstream consumers (report writer, graph)
    for k in ("duration", "stdout_preview", "drift_score", "confidence", "exec_result"):
        assert k in r, f"skipped result missing key {k}"
    assert r["confidence"] == "N/A" and r["stdout_preview"] == ""
    assert sandbox.write_log.called and "SKIPPED" in sandbox.write_log.call_args[0][1]
    print("PASS 1: missing file -> step skipped, tool never invoked, record complete")

    # 2) Empty file -> skipped
    with open(os.path.join(d, "pmkid_cap.hc22000"), "w") as f:
        f.write("")
    wf2 = make_engine(tmpl, sandbox)
    r2 = wf2._run_step(0)
    assert r2["status"] == "skipped", f"expected skipped for empty file, got {r2['status']}"
    print("PASS 2: empty file -> skipped")

    # 3) Non-empty file -> runs and succeeds
    with open(os.path.join(d, "pmkid_cap.hc22000"), "w") as f:
        f.write("WPA*01*PMKIDHASH")
    wf3 = make_engine(tmpl, sandbox)
    r3 = wf3._run_step(0)
    assert r3["status"] == "success", f"expected success, got {r3['status']}"
    print("PASS 3: non-empty file present -> step runs and succeeds")

    # 4) Full start(): gated step skipped, fallback succeeds -> status complete
    os.unlink(os.path.join(d, "pmkid_cap.hc22000"))
    sandbox.write_log = MagicMock()
    sandbox.save_state = MagicMock()
    wf4 = make_engine(tmpl, sandbox)
    summary = wf4.start()
    assert summary["status"] == "complete", f"expected complete, got {summary['status']}"
    assert summary["completed_steps"] == 2, summary["completed_steps"]
    assert summary["steps"][0]["status"] == "skipped"
    assert summary["steps"][1]["status"] == "success"
    assert any(w.get("skipped") and "crack_hash" in w.get("step", "")
               for w in summary["warnings"]), summary["warnings"]
    print("PASS 4: full run -> complete, skipped step recorded + warning surfaced")


def test_unresolved_gate_var_blocks():
    d = tempfile.mkdtemp(prefix="rt_filegate_")
    tmpl = os.path.join(d, "t.yaml")
    # Args resolve cleanly (literal) — only the file_gate path references a
    # missing variable, so the new file_gate unresolved check is exercised
    # (the pre-existing args check must NOT short-circuit first).
    with open(tmpl, "w") as f:
        f.write("""
name: "Unresolved Gate Var"
steps:
  - name: crack_hash
    tool: hashcat_crack
    description: "Crack PMKID"
    args:
      hash_file: "pmkid_cap.hc22000"
    expected_output: "Cracked|Recovered"
    timeout: 60
    gate: false
    retries: 0
    file_gate:
      - "{{missing_artifact}}.hc22000"
""")
    sandbox = make_sandbox(d)
    runner = MagicMock()
    wf = WorkflowStateMachine(tmpl, sandbox, runner, {})
    wf.load()
    r = wf._run_step(0)
    assert r["status"] == "blocked", f"expected blocked, got {r['status']}"
    assert "file_gate" in r["reason"] and "missing variable" in r["reason"].lower(), \
        r["reason"]
    # The tool must never have been invoked on a bogus path
    runner.execute.assert_not_called()
    print("PASS 5: unresolved {{var}} in file_gate only -> blocked (args check did not short-circuit)")


def test_template_validation():
    d = tempfile.mkdtemp(prefix="rt_filegate_")
    bad = os.path.join(d, "bad.yaml")
    with open(bad, "w") as f:
        f.write("""
name: "Bad Gate"
steps:
  - name: s1
    tool: nmap_scan
    args: {}
    file_gate: "just-a-string"
""")
    r = WorkflowStateMachine.validate_template(bad)
    assert not r["valid"], "string file_gate must fail validation"
    assert any("file_gate" in e for e in r["errors"]), r["errors"]
    # Templates without the key still validate
    good = os.path.join(d, "good.yaml")
    with open(good, "w") as f:
        f.write("name: \"No Gate\"\nsteps:\n  - name: s1\n    tool: nmap_scan\n    args: {}\n")
    r2 = WorkflowStateMachine.validate_template(good)
    assert r2["valid"], r2["errors"]
    print("PASS 6: validate_template rejects bad file_gate shape, accepts absent key")


test_skip_on_missing_file()
test_unresolved_gate_var_blocks()
test_template_validation()

print("\n=== ALL FILE_GATE TESTS PASSED ===")
