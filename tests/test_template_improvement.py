#!/usr/bin/env python3
"""Functional test for the post-execution template self-improvement (v4.2)."""
import os
import sys
import json
import shutil
import tempfile
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Compile check
for m in ["core/workflow_generator.py", "core/orchestrator.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.workflow_generator import WorkflowGenerator


class FakeLLM:
    """Records prompts, returns scripted improvement JSON."""
    def __init__(self, response):
        self.response = response
        self.last_prompt = ""

    def chat_structured(self, messages, schema, **kw):
        self.last_prompt = messages[-1]["content"]
        return self.response


class FakeTool:
    def __init__(self, name, params=None):
        self.name = name
        self.category = "recon"
        self.description = f"{name} tool"
        self.parameters = params or {}


class FakeRegistry:
    def __init__(self):
        self._tools = {
            "nmap_scan": FakeTool("nmap_scan", {
                "target": {"description": "target", "required": True}}),
            "nikto_scan": FakeTool("nikto_scan", {
                "target": {"description": "target", "required": True}}),
            "gobuster_dir": FakeTool("gobuster_dir", {
                "url": {"description": "url", "required": True}}),
            "sqlmap_scan": FakeTool("sqlmap_scan", {
                "url": {"description": "url", "required": True}}),
            "curl_request": FakeTool("curl_request", {
                "url": {"description": "url", "required": True}}),
        }

    def get_all_tools(self):
        return self._tools


TEMPLATE = {
    "name": "Web Recon Chain",
    "description": "Basic web recon",
    "category": "web",
    "variables": {"target": {"description": "Target IP", "required": True}},
    "cutting_edge": True,
    "steps": [
        {"name": "port_scan", "tool": "nmap_scan", "args": {"target": "{{target}}"},
         "description": "Port scan"},
        {"name": "dir_enum", "tool": "gobuster_dir", "args": {"url": "http://{{target}}"},
         "description": "Dir enum"},
        {"name": "web_check", "tool": "curl_request", "args": {"url": "http://{{target}}"},
         "description": "Fetch homepage"},
    ],
}

EXEC_RESULT = {
    "status": "partial",
    "completed_steps": 3,
    "total_steps": 3,
    "steps": [
        {"step": "port_scan", "tool": "nmap_scan", "status": "success",
         "attempts": 1, "drift_score": 0.05, "confidence": "high",
         "findings_added": 2},
        {"step": "dir_enum", "tool": "gobuster_dir", "status": "success",
         "attempts": 3, "drift_score": 0.9, "confidence": "uncertain",
         "findings_added": 0},
        {"step": "web_check", "tool": "curl_request", "status": "success",
         "attempts": 1, "drift_score": 0.1, "confidence": "high",
         "findings_added": 0},
    ],
    "warnings": [{"step": "dir_enum", "reason": "validation failed: output did not match"}],
    "findings": [{"severity": "medium"}],
}

# LLM verdicts: modify dir_enum (swap to nikto), remove web_check, add sqlmap step
IMPROVE_RESPONSE = json.dumps({
    "assessment": "The port scan worked well but dir enumeration drifted heavily; "
                  "the curl step added no findings and the workflow needs a vuln scan.",
    "step_verdicts": [
        {"step": "port_scan", "verdict": "keep", "rationale": "worked cleanly"},
        {"step": "dir_enum", "verdict": "modify",
         "rationale": "high drift, 3 retries, no findings — swap to nikto",
         "replacement_tool": "nikto_scan",
         "replacement_args": {"target": "{{target}}"},
         "new_retries": 1},
        {"step": "web_check", "verdict": "remove",
         "rationale": "redundant, no findings"},
    ],
    "new_steps": [
        {"name": "sql_injection", "tool": "sqlmap_scan",
         "args": {"url": "http://{{target}}"},
         "description": "SQL injection test", "gate": False,
         "retries": 1, "timeout": 300},
    ],
})


def make_env():
    tmp = tempfile.mkdtemp(prefix="rt_improve_")
    path = os.path.join(tmp, "web_recon.yaml")
    import yaml
    with open(path, "w") as f:
        yaml.safe_dump(TEMPLATE, f, sort_keys=False)
    return tmp, path


def read_template(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def test_suggestions_only():
    tmp, path = make_env()
    llm = FakeLLM(IMPROVE_RESPONSE)
    gen = WorkflowGenerator(llm, FakeRegistry(), templates_dir=tmp)
    res = gen.improve_template(path, EXEC_RESULT, apply=False)

    assert "error" not in res, f"unexpected error: {res}"
    assert "drifted heavily" in res["assessment"], res["assessment"]
    assert len(res["verdicts"]) == 3, f"expected 3 verdicts, got {len(res['verdicts'])}"
    by_step = {v["step"]: v for v in res["verdicts"]}
    assert by_step["port_scan"]["verdict"] == "keep"
    assert by_step["dir_enum"]["verdict"] == "modify"
    assert by_step["dir_enum"]["changes"].get("tool") == "nikto_scan"
    assert by_step["web_check"]["verdict"] == "remove"
    assert len(res["new_steps"]) == 1
    assert res["new_steps"][0]["tool"] == "sqlmap_scan"
    assert res["applied"] is False
    # Template file must be untouched
    t = read_template(path)
    assert len(t["steps"]) == 3, "template should be unchanged when apply=False"
    print("1. suggestions-only: OK")
    shutil.rmtree(tmp, ignore_errors=True)


def test_apply_changes():
    tmp, path = make_env()
    llm = FakeLLM(IMPROVE_RESPONSE)
    gen = WorkflowGenerator(llm, FakeRegistry(), templates_dir=tmp)
    res = gen.improve_template(path, EXEC_RESULT, apply=True)

    assert res["applied"] is True, f"should have applied: {res.get('rejected')}"
    assert res["applied_changes"]["removed"] == ["web_check"]
    assert res["applied_changes"]["modified"] == ["dir_enum"]
    assert res["applied_changes"]["added"] == ["sql_injection"]
    import glob
    baks = glob.glob(path + ".bak.*")
    assert len(baks) == 1, f"expected 1 timestamped backup, got {baks}"

    t = read_template(path)
    names = [s["name"] for s in t["steps"]]
    assert names == ["port_scan", "dir_enum", "sql_injection"], f"steps: {names}"
    dir_enum = next(s for s in t["steps"] if s["name"] == "dir_enum")
    assert dir_enum["tool"] == "nikto_scan", "tool should be swapped"
    assert dir_enum["retries"] == 1, "retries should be updated"
    # New step added with correct tool
    sql = next(s for s in t["steps"] if s["name"] == "sql_injection")
    assert sql["tool"] == "sqlmap_scan"
    assert "[auto-improved" in t.get("description", ""), "description should be tagged"
    print("2. apply changes: OK")
    shutil.rmtree(tmp, ignore_errors=True)


def test_reject_unknown_tool():
    tmp, path = make_env()
    bad = json.loads(IMPROVE_RESPONSE)
    bad["step_verdicts"][1]["replacement_tool"] = "not_a_real_tool"
    llm = FakeLLM(json.dumps(bad))
    gen = WorkflowGenerator(llm, FakeRegistry(), templates_dir=tmp)
    res = gen.improve_template(path, EXEC_RESULT, apply=True)

    assert "error" not in res
    # dir_enum falls back to keep (rejected change), but remove + add still apply
    dir_enum = next(v for v in res["verdicts"] if v["step"] == "dir_enum")
    assert dir_enum["verdict"] == "keep", "unknown tool must fall back to keep"
    assert any("not_a_real_tool" in r.get("reason", "") for r in res["rejected"])
    t = read_template(path)
    dir_enum_t = next(s for s in t["steps"] if s["name"] == "dir_enum")
    assert dir_enum_t["tool"] == "gobuster_dir", "bad tool must not be written"
    print("3. reject unknown tool: OK")
    shutil.rmtree(tmp, ignore_errors=True)


def test_garbage_llm():
    tmp, path = make_env()
    llm = FakeLLM("this is not json at all")
    gen = WorkflowGenerator(llm, FakeRegistry(), templates_dir=tmp)
    res = gen.improve_template(path, EXEC_RESULT, apply=True)
    assert "error" in res, "garbage LLM output must return an error"
    t = read_template(path)
    assert len(t["steps"]) == 3, "template must be untouched on failure"
    print("4. garbage LLM output: OK")
    shutil.rmtree(tmp, ignore_errors=True)


def test_no_llm():
    tmp, path = make_env()
    gen = WorkflowGenerator(None, FakeRegistry(), templates_dir=tmp)
    res = gen.improve_template(path, EXEC_RESULT, apply=True)
    assert "error" in res and "No LLM" in res["error"]
    print("5. no LLM backend: OK")
    shutil.rmtree(tmp, ignore_errors=True)


def test_orchestrator_wiring():
    """Verify orchestrator.auto_workflow hooks the improvement pass."""
    src = open(os.path.join(os.path.dirname(__file__), "..", "core", "orchestrator.py")).read()
    assert "template_self_improve" in src, "orchestrator must read template_self_improve config"
    assert "improve_template" in src, "orchestrator must call generator.improve_template"
    assert "template_improvement" in src, "orchestrator must store the improvement result"
    print("6. orchestrator wiring: OK")


test_suggestions_only()
test_apply_changes()
test_reject_unknown_tool()
test_garbage_llm()
test_no_llm()
test_orchestrator_wiring()

print("\n=== ALL TEMPLATE IMPROVEMENT TESTS PASSED ===")
