"""
Tests for core/safety.py — the SafetyEngine seam (architecture candidate #6).

The safety gate is the FIRST thing every LLM tool call passes through; it was
one of the load-bearing untested modules. These tests pin:
  - require_confirmation tool gating
  - blocked-target rejection (exact, prefix, CIDR overlap)
  - allowed-scope enforcement (IP-in-CIDR + string suffix)
  - target extraction from args
  - policy summary
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


def test_confirmation_gate():
    eng = SafetyEngine({"require_confirmation": ["msfconsole", "hydra_brute"]})
    ok, reason = eng.check_tool("hydra_brute", {"target": "10.0.0.5"})
    assert not ok, "destructive tool must require confirmation"
    assert "requires explicit user confirmation" in reason

    # Non-confirmation tool passes through
    ok, reason = eng.check_tool("nmap_scan", {"target": "10.0.0.5"})
    assert ok and reason == "Approved"


def test_blocked_targets():
    eng = SafetyEngine({"blocked_targets": ["10.0.0.5", "192.168.1.0/24", "evil.com"]})
    # Exact match
    ok, reason = eng.check_tool("nmap_scan", {"target": "10.0.0.5"})
    assert not ok and "blocked" in reason
    # CIDR overlap
    ok, _ = eng.check_tool("nmap_scan", {"target": "192.168.1.42"})
    assert not ok, "CIDR-blocked target must be rejected"
    # String match
    ok, _ = eng.check_tool("nmap_scan", {"url": "evil.com"})
    assert not ok
    # Outside blocked scope is fine
    ok, _ = eng.check_tool("nmap_scan", {"target": "10.0.0.99"})
    assert ok


def test_allowed_scope():
    eng = SafetyEngine({"allowed_targets": ["10.0.0.0/24", "lab.local"]})
    ok, _ = eng.check_tool("nmap_scan", {"target": "10.0.0.50"})
    assert ok, "in-scope IP must be allowed"
    ok, _ = eng.check_tool("nmap_scan", {"target": "host.lab.local"})
    assert ok, "allowed-suffix hostname must be allowed"
    ok, reason = eng.check_tool("nmap_scan", {"target": "172.16.0.1"})
    assert not ok and "not in the allowed scope" in reason

    # No allowed_targets configured → everything passes scope
    eng2 = SafetyEngine({})
    ok, _ = eng2.check_tool("nmap_scan", {"target": "172.16.0.1"})
    assert ok


def test_target_extraction():
    eng = SafetyEngine({})
    assert eng._extract_target({"target": "10.0.0.1"}) == "10.0.0.1"
    assert eng._extract_target({"url": "http://x.com"}) == "http://x.com"
    assert eng._extract_target({"domain": "x.com"}) == "x.com"
    assert eng._extract_target({"host": "x.com"}) == "x.com"
    assert eng._extract_target({"ports": "80"}) == ""


def test_policy_summary():
    eng = SafetyEngine({"allowed_targets": ["10.0.0.0/24"],
                        "blocked_targets": ["10.0.0.5"],
                        "require_confirmation": ["msfconsole"],
                        "log_all_commands": False})
    s = eng.get_policy_summary()
    assert s["allowed_targets"] == ["10.0.0.0/24"]
    assert s["blocked_targets"] == ["10.0.0.5"]
    assert s["require_confirmation"] == ["msfconsole"]
    assert s["log_all_commands"] is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        _check(fn.__name__, fn)
    print(f"\nAll {len(tests)} safety tests PASSED.")
