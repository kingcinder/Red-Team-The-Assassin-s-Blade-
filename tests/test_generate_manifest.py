"""Regression tests for scripts/generate_manifest.py.

The release-manifest tool previously crashed at build time with
AttributeError: module 'posixpath' has no attribute 'which'
because it called ``os.path.which`` (which does not exist) instead of
``shutil.which``. A successful build exercises the fixed code path, so the
integration tests below are the primary regression guard.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scripts.generate_manifest as gm


def test_source_does_not_use_os_path_which():
    """Lint-style guard for the exact defect: os.path.which does not exist."""
    source = open(gm.__file__).read()
    assert "os.path.which" not in source


def test_build_manifest_completes():
    """build_manifest() must run to completion (crashed before the fix)."""
    manifest = gm.build_manifest()
    assert isinstance(manifest, dict)
    for key in ("_meta", "python_dependencies", "kali_tools",
                "installer_recipes", "offline_bundle"):
        assert key in manifest


def test_kali_tool_installed_flags_are_bool():
    """installed_on_host comes from shutil.which — must be a real bool."""
    tools = gm.build_manifest()["kali_tools"]["tools"]
    assert tools, "expected at least one tracked tool"
    for tool in tools:
        assert isinstance(tool["installed_on_host"], bool), tool["binary"]


def test_kali_summary_matches_tool_list():
    manifest = gm.build_manifest()
    tools = manifest["kali_tools"]["tools"]
    summary = manifest["kali_tools"]["summary"]
    assert summary["total_tracked"] == len(tools)
    installed = sum(1 for t in tools if t["installed_on_host"])
    assert summary["installed_on_host"] == installed
    assert summary["total_tracked"] == (summary["installed_on_host"]
                                        + summary["auto_installable"]
                                        + summary["manual_install_required"])


def test_manifest_output_is_json_serializable(tmp_path):
    """The written artifact must parse back as JSON (--verify depends on it)."""
    manifest = gm.build_manifest()
    out = tmp_path / "MANIFEST.json"
    out.write_text(json.dumps(manifest, indent=2))
    reloaded = json.loads(out.read_text())
    assert reloaded["_meta"]["generated_by"] == "scripts/generate_manifest.py"
