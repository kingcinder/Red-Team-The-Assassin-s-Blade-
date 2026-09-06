#!/usr/bin/env python3
"""
Regression test: TacticalEngine.evaluate() crashed with
"AttributeError: 'dict' object has no attribute 'confidence'" whenever two
findings produced the same tool+args suggestion (the dedup loop read
`seen[key].confidence` on a dict instead of `seen[key]["confidence"]`).

Because the crash only triggers when findings DUPLICATE (i.e. when scans
actually succeed), it never showed in sessions where tools failed — which is
why it surfaced only after the engagement loop started working end to end.
Every successful finding-producing step was being marked failed by it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.tactics import TacticalEngine


def test_evaluate_with_duplicate_suggestions():
    """Two findings that map to the SAME tool+args must dedup without crashing
    and keep the highest confidence."""
    eng = TacticalEngine()
    # Both findings match the "open http port" rule → nikto_scan with
    # identical args {host: 10.0.0.5, port: 80} → duplicate dedup key.
    findings = [
        {"title": "HTTP service on 10.0.0.5:80",
         "evidence": "80/tcp open http Apache",
         "target": "10.0.0.5"},
        {"title": "Same HTTP service (duplicate finding)",
         "evidence": "80/tcp open http nginx",
         "target": "10.0.0.5"},
    ]
    suggestions = eng.evaluate(findings, context={"host": "10.0.0.5"})
    assert isinstance(suggestions, list), "evaluate() must return a list"
    # At least one suggestion, deduplicated by tool+args
    keys = [(s["tool"], str(s["args"])) for s in suggestions]
    assert len(set(keys)) == len(keys), f"duplicates survived: {keys}"
    assert any(s["tool"] == "nikto_scan" for s in suggestions), suggestions
    # Confidence is a real number on each suggestion
    for s in suggestions:
        assert isinstance(s["confidence"], (int, float)), s
    print(f"  {len(suggestions)} unique suggestions (dedup OK): "
          f"{[(s['tool'], s['confidence']) for s in suggestions][:4]}")


def test_evaluate_empty_and_unique():
    eng = TacticalEngine()
    assert eng.evaluate([]) == []
    # Single suggestion path (no dedup pressure)
    out = eng.evaluate(
        [{"title": "SSH open", "evidence": "22/tcp open ssh OpenSSH", "target": "10.0.0.9"}],
        context={"host": "10.0.0.9"})
    assert any(s["tool"] == "hydra_brute" for s in out), out
    print(f"  empty/unique paths OK ({len(out)} suggestions)")


test_evaluate_with_duplicate_suggestions()
test_evaluate_empty_and_unique()

print("=== ALL TACTICS DEDUP TESTS PASSED ===")
