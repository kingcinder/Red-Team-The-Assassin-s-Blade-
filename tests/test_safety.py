"""
Tests for core/safety.py — the SafetyEngine seam (unrestricted mode).

All restrictions and guardrails have been removed: the engine is a
pass-through. These tests pin that:
  - every tool is approved unconditionally (no confirmation gating)
  - no target is ever blocked (no blocked list, no scope enforcement)
  - approve_tool / get_policy_summary still work for API compatibility
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.safety import SafetyEngine


def _check(name, fn):
    try:
        fn()
        print(f"  {name}: OK")
    except AssertionError as e:
        print(f"  {name}: FAIL — {e}")
        raise


def test_confirmation_gate_removed():
    # Even tools that USED to require confirmation now pass unconditionally
    eng = SafetyEngine({"require_confirmation": ["msfconsole", "hydra_brute"]})
    ok, reason = eng.check_tool("hydra_brute", {"target": "10.0.0.5"})
    assert ok, "destructive tool must NOT require confirmation anymore"
    assert reason == "Approved"

    ok, reason = eng.check_tool("nmap_scan", {"target": "10.0.0.5"})
    assert ok and reason == "Approved"


def test_blocked_targets_removed():
    # Configured blocked targets are ignored — nothing is ever blocked
    eng = SafetyEngine({"blocked_targets": ["10.0.0.5", "192.168.1.0/24", "evil.com"]})
    for target in ["10.0.0.5", "192.168.1.42", "evil.com", "8.8.8.8", "10.0.0.99"]:
        ok, _ = eng.check_tool("nmap_scan", {"target": target})
        assert ok, f"target must never be blocked: {target}"


def test_allowed_scope_removed():
    # Scope enforcement is gone — out-of-scope targets are approved too
    eng = SafetyEngine({"allowed_targets": ["10.0.0.0/24", "lab.local"]})
    ok, _ = eng.check_tool("nmap_scan", {"target": "172.16.0.1"})
    assert ok, "out-of-scope target must be approved (no scope enforcement)"


def test_approve_tool_compat():
    eng = SafetyEngine({})
    assert eng.approve_tool("hydra_brute", {"target": "10.0.0.1"}) is True


def test_policy_summary():
    eng = SafetyEngine({"log_all_commands": False})
    s = eng.get_policy_summary()
    assert s["allowed_targets"] == []
    assert s["blocked_targets"] == []
    assert s["require_confirmation"] == []
    assert s["log_all_commands"] is False
    assert s["restrictions_enabled"] is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} safety tests PASSED.")
