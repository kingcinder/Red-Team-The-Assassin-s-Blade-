#!/usr/bin/env python3
"""
Regression tests: the runtime nmap scan-type downgrade (compat fix).

Prompt-level steering has been REMOVED (unrestricted mode) — the LLM is free
to request any scan type. What remains is a pure runtime compatibility fix in
command_builder: when the harness process is genuinely unprivileged, nmap -sS
(SYN) cannot run (it needs root/CAP_NET_RAW) and fails with "requires root
privileges", so it is silently rewritten to -sT (TCP connect), which reports
the same port states. As root, -sS is left untouched — nothing is restricted.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.command_builder import _build_nmap, _unprivileged_scan_type
from core.tool_registry import ToolRegistry
import yaml


# ═══════════════════════════════════════════════════════════════
# 1. command_builder downgrades -sS -> -sT when unprivileged
# ═══════════════════════════════════════════════════════════════
def test_command_builder_downgrade_unprivileged():
    args = {"target": "127.0.0.1", "ports": "1-100", "scan_type": "-sS"}
    with patch("core.command_builder.os.geteuid", return_value=1000):
        cmd = _build_nmap("/tmp/o", "nmap_scan", args, "nmap")
    assert "-sT" in cmd, cmd
    assert "-sS" not in cmd, "root-only flag survived the unprivileged downgrade!"


def test_command_builder_keeps_ss_as_root():
    args = {"target": "127.0.0.1", "ports": "1-100", "scan_type": "-sS"}
    with patch("core.command_builder.os.geteuid", return_value=0):
        cmd = _build_nmap("/tmp/o", "nmap_scan", args, "nmap")
    assert "-sS" in cmd and "-sT" not in cmd, cmd


def test_command_builder_default_unchanged():
    with patch("core.command_builder.os.geteuid", return_value=1000):
        cmd = _build_nmap("/tmp/o", "nmap_scan", {"target": "127.0.0.1"}, "nmap")
    assert "-sV" in cmd, "default scan_type (-sV) must stay intact"


def test_unprivileged_scan_type_combined_flags():
    with patch("core.command_builder.os.geteuid", return_value=1000):
        assert _unprivileged_scan_type("-sS -sV") == "-sT -sV"
        assert _unprivileged_scan_type("-sV") == "-sV"
        assert _unprivileged_scan_type("") == ""


# ═══════════════════════════════════════════════════════════════
# 2. Tool registry description still documents the tradeoff
# ═══════════════════════════════════════════════════════════════
def test_nmap_scan_type_description():
    cfg = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "config.yaml")))
    tr = ToolRegistry(cfg.get("tools", {}))
    t = tr.get_all_tools()["nmap_scan"]
    desc = t.parameters["scan_type"]["description"]
    assert "works unprivileged" in desc, desc
    assert "requires root" in desc, desc


test_command_builder_downgrade_unprivileged()
test_command_builder_keeps_ss_as_root()
test_command_builder_default_unchanged()
test_unprivileged_scan_type_combined_flags()
test_nmap_scan_type_description()

print("=== ALL NMAP RUNTIME-DOWNGRADE TESTS PASSED ===")
