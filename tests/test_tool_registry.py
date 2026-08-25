"""
Tests for core/tool_registry.py — the ToolRegistry seam (candidate #6).

The registry every tool call passes through: registration completeness
(Kali arsenal), category queries, installed detection, LLM-facing
definitions, and the execute() guard rails for unknown/missing tools.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.tool_registry import ToolRegistry, ToolDefinition


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def _make_registry():
    d = tempfile.mkdtemp()
    return ToolRegistry({"output_dir": os.path.join(d, "out")})


def test_registry_populated():
    reg = _make_registry()
    assert reg.get_total_count() >= 100, "Kali arsenal must be registered"
    assert reg.get_available_count() >= 0


def test_get_tool():
    reg = _make_registry()
    t = reg.get_tool("nmap_scan")
    assert t is not None
    assert t.category == "recon"
    assert t.binary == "nmap"
    assert "target" in t.parameters
    assert t.parameters["target"]["required"] is True
    assert reg.get_tool("no_such_tool") is None


def test_categories():
    reg = _make_registry()
    recon = reg.get_tools_by_category("recon")
    assert len(recon) >= 5
    cats = {t.category for t in reg.get_all_tools().values()}
    for expected in ("recon", "vuln", "web", "exploit", "postex", "password"):
        assert expected in cats, f"missing category {expected}"


def test_to_dict_and_llm_definition():
    reg = _make_registry()
    t = reg.get_tool("nmap_scan")
    d = t.to_dict()
    assert d["name"] == "nmap_scan" and d["category"] == "recon"
    assert "installed" in d and "parameters" in d
    llm = t.to_llm_definition()
    # OpenAI-style function schema: {type, function: {name, description, parameters}}
    assert llm["type"] == "function"
    assert llm["function"]["name"] == "nmap_scan"
    assert "description" in llm["function"]
    assert llm["function"]["parameters"]["type"] == "object"


def test_execute_guards():
    reg = _make_registry()
    res = reg.execute("no_such_tool", {})
    assert res["exit_code"] == -1 and "Unknown tool" in res["stderr"]
    # A registered-but-not-installed tool → guarded not-installed response
    from core.tool_registry import ToolDefinition
    reg._tools["definitely_missing"] = ToolDefinition(
        "definitely_missing", "recon", "d", "binary_that_does_not_exist_xyz",
        {"target": {"type": "string", "required": True}})
    reg._tools["definitely_missing"].installed = False
    res2 = reg.execute("definitely_missing", {"target": "10.0.0.5"})
    assert res2["exit_code"] == -1
    assert "not installed" in res2["stderr"]


def test_llm_definitions_list():
    # get_tool_definitions_for_llm returns only INSTALLED tools, so the
    # host-dependent count is not asserted — structure + a registered
    # installed tool are pinned instead.
    reg = _make_registry()
    from core.tool_registry import ToolDefinition
    reg._tools["echo_probe"] = ToolDefinition(
        "echo_probe", "recon", "probe", "echo",
        {"target": {"type": "string"}})
    reg._tools["echo_probe"].installed = True
    defs = reg.get_tool_definitions_for_llm()
    assert isinstance(defs, list)
    # to_llm_definition returns OpenAI-style function schemas
    for d in defs:
        assert d["type"] == "function"
        assert "name" in d["function"] and "description" in d["function"]
        assert d["function"]["parameters"]["type"] == "object"
    assert any(d["function"]["name"] == "echo_probe" for d in defs)
    # to_llm_definition always yields dicts regardless of install state
    assert isinstance(reg.get_tool("nmap_scan").to_llm_definition(), dict)


def test_status():
    reg = _make_registry()
    st = reg.get_status()
    assert st["total_tools"] >= 100
    assert "installed_tools" in st and "categories" in st
    assert isinstance(st["categories"], dict)
    assert "recon" in st["categories"]


def test_tool_definition_basics():
    t = ToolDefinition("x", "recon", "desc", "echo",
                       {"p": {"type": "string"}}, timeout=120)
    assert t.name == "x" and t.timeout == 120
    assert t.installed is False
    d = t.to_dict()
    assert d["destructive"] is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} tool-registry tests PASSED.")
