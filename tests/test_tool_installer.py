"""
Tests for core/tool_installer.py — the ToolInstaller seam (candidate #6).

Mid-engagement tool acquisition: unknown-tool recipe rejection, already-
installed detection, missing-tool listing, status checks, and installable
count. No actual network installs are performed — only the safe surface.
"""
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.tool_installer as ti
from core.tool_installer import ToolInstaller, INSTALL_RECIPES


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


class _FakeRegistry:
    """Minimal registry stub exposing just what the installer uses."""

    def __init__(self, tools):
        self._tools = tools

    def get_all_tools(self):
        return self._tools

    def get_tool(self, name):
        return self._tools.get(name)


def _fake_tool(name, binary, category="recon", installed=False, description="d"):
    from core.tool_registry import ToolDefinition
    t = ToolDefinition(name, category, description, binary)
    t.installed = installed
    return t


def test_unknown_tool_rejected():
    # Redirect cache dirs to a temp path so no real ~/.cache writes occur
    with tempfile.TemporaryDirectory() as d:
        ti.CACHE_DIR = os.path.join(d, "cache")
        ti.APT_CACHE_DIR = os.path.join(d, "apt")
        ti.GO_CACHE_DIR = os.path.join(d, "go")
        ti.PIP_CACHE_DIR = os.path.join(d, "pip")
        ti.MANUAL_CACHE_DIR = os.path.join(d, "manual")
        ti.LOCAL_BIN = os.path.join(d, "bin")
        inst = ToolInstaller(_FakeRegistry({}))
        res = inst.install_tool("totally_unknown_tool_xyz")
        assert res["status"] == "error"
        assert "No install recipe" in res["message"]


def test_check_tool_status_unknown_binary():
    # _resolve_binary must handle tools absent from the registry
    with tempfile.TemporaryDirectory() as d:
        ti.CACHE_DIR = os.path.join(d, "cache")
        ti.APT_CACHE_DIR = os.path.join(d, "apt")
        ti.GO_CACHE_DIR = os.path.join(d, "go")
        ti.PIP_CACHE_DIR = os.path.join(d, "pip")
        ti.MANUAL_CACHE_DIR = os.path.join(d, "manual")
        ti.LOCAL_BIN = os.path.join(d, "bin")
        inst = ToolInstaller(_FakeRegistry({}))
        st = inst.check_tool_status("unknown_binary_xyz")
        assert st["installed"] is False or st["binary"]
        assert st["installable"] is False


def test_list_missing_tools():
    with tempfile.TemporaryDirectory() as d:
        ti.CACHE_DIR = os.path.join(d, "cache")
        ti.APT_CACHE_DIR = os.path.join(d, "apt")
        ti.GO_CACHE_DIR = os.path.join(d, "go")
        ti.PIP_CACHE_DIR = os.path.join(d, "pip")
        ti.MANUAL_CACHE_DIR = os.path.join(d, "manual")
        ti.LOCAL_BIN = os.path.join(d, "bin")
        registry = _FakeRegistry({
            "nmap_scan": _fake_tool("nmap_scan", "nmap", installed=False),
            "nikto_scan": _fake_tool("nikto_scan", "nikto", installed=True),
        })
        inst = ToolInstaller(registry)
        missing = inst.list_missing_tools()
        names = [m["tool_name"] for m in missing]
        assert "nmap_scan" in names
        assert "nikto_scan" not in names
        entry = next(m for m in missing if m["tool_name"] == "nmap_scan")
        assert "installable" in entry and "install_method" in entry


def test_check_tool_status():
    with tempfile.TemporaryDirectory() as d:
        ti.CACHE_DIR = os.path.join(d, "cache")
        ti.APT_CACHE_DIR = os.path.join(d, "apt")
        ti.GO_CACHE_DIR = os.path.join(d, "go")
        ti.PIP_CACHE_DIR = os.path.join(d, "pip")
        ti.MANUAL_CACHE_DIR = os.path.join(d, "manual")
        ti.LOCAL_BIN = os.path.join(d, "bin")
        registry = _FakeRegistry({
            "echo_tool": _fake_tool("echo_tool", "echo", installed=True),
            "nmap_scan": _fake_tool("nmap_scan", "nmap", installed=False),
        })
        inst = ToolInstaller(registry)
        st = inst.check_tool_status("echo_tool")
        assert st["installed"] is True
        assert st["binary"] == "echo"
        st2 = inst.check_tool_status("nmap_scan")
        assert st2["binary"] == "nmap"


def test_installable_count():
    with tempfile.TemporaryDirectory() as d:
        ti.CACHE_DIR = os.path.join(d, "cache")
        ti.APT_CACHE_DIR = os.path.join(d, "apt")
        ti.GO_CACHE_DIR = os.path.join(d, "go")
        ti.PIP_CACHE_DIR = os.path.join(d, "pip")
        ti.MANUAL_CACHE_DIR = os.path.join(d, "manual")
        ti.LOCAL_BIN = os.path.join(d, "bin")
        registry = _FakeRegistry({})
        inst = ToolInstaller(registry)
        assert inst.get_installable_count() >= 0


def test_recipes_present():
    assert len(INSTALL_RECIPES) >= 80, "Kali arsenal recipes must be present"
    for key in ("aircrack-ng", "amass", "chisel", "nuclei"):
        assert key in INSTALL_RECIPES, f"expected recipe for {key}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} tool-installer tests PASSED.")
