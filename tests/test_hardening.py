"""
Tests for core/hardening.py — the HardenedToolRunner seam (candidate #6).

Every LLM tool call routes through registry → safety → hardening. This pins
the hardening layer: unknown/not-installed tool rejection, required-param
validation, type coercion, command-injection rejection, audit trail, and the
cache integration.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.hardening import HardenedToolRunner
from core.tool_registry import ToolRegistry, ToolDefinition


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def _make_registry(tmpdir):
    reg = ToolRegistry({"output_dir": os.path.join(tmpdir, "out")})
    # A real, installed binary ("echo") for the happy path
    reg._tools["echo_test"] = ToolDefinition(
        "echo_test", "recon", "echo a message", "echo",
        {"message": {"type": "string", "required": True, "description": "text"}},
        timeout=30,
    )
    reg._tools["echo_test"].installed = True
    reg._tools["echo_test"].path = "/usr/bin/echo"
    return reg


def test_unknown_tool():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    r = HardenedToolRunner(reg)
    res = r.execute("no_such_tool", {})
    assert res["blocked"] and res["block_reason"] == "unknown_tool"
    assert "Unknown tool" in res["stderr"]


def test_not_installed():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    reg._tools["missing_tool"] = ToolDefinition(
        "missing_tool", "recon", "not installed", "definitely_missing_binary_xyz",
        {"target": {"type": "string", "required": True}})
    reg._tools["missing_tool"].installed = False
    r = HardenedToolRunner(reg)
    res = r.execute("missing_tool", {"target": "10.0.0.5"})
    assert res["blocked"] and res["block_reason"] == "not_installed"


def test_required_param_validation():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    r = HardenedToolRunner(reg)
    res = r.execute("echo_test", {})
    assert res["blocked"]
    assert "Missing required param" in res["stderr"]


def test_integer_type_validation():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    reg._tools["int_tool"] = ToolDefinition(
        "int_tool", "recon", "int param", "echo",
        {"count": {"type": "integer", "required": True}})
    reg._tools["int_tool"].installed = True
    reg._tools["int_tool"].path = "/usr/bin/echo"
    r = HardenedToolRunner(reg)
    # Non-integer rejected
    res = r.execute("int_tool", {"count": "not-a-number"})
    assert res["blocked"] and "must be an integer" in res["stderr"]


def test_injection_rejection():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    r = HardenedToolRunner(reg)
    for payload in ["$(id)", "${IFS}id", "`id`", "rm -rf /", "../../etc/passwd"]:
        res = r.execute("echo_test", {"message": payload})
        assert res["blocked"], f"payload not rejected: {payload}"
        assert "rejected" in res["stderr"] or "dangerous" in res["stderr"]


def test_happy_path_and_cache():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    r = HardenedToolRunner(reg)
    res = r.execute("echo_test", {"message": "hello world"})
    assert not res["blocked"], res.get("stderr")
    assert res["exit_code"] == 0
    assert "hello world" in res["stdout"]
    assert res["killed"] is False
    # Second identical call → cache hit
    res2 = r.execute("echo_test", {"message": "hello world"})
    assert res2.get("from_cache") is True


def test_audit_log():
    import tempfile
    reg = _make_registry(tempfile.mkdtemp())
    r = HardenedToolRunner(reg)
    r.execute("echo_test", {"message": "hello"})
    log = r.get_audit_log()
    assert len(log) == 1
    assert log[0]["tool"] == "echo_test"
    assert log[0]["exit_code"] == 0
    assert "command" in log[0]
    r.clear_audit_log()
    assert r.get_audit_log() == []


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} hardening tests PASSED.")
