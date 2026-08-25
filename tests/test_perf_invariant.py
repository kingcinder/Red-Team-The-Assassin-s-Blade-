#!/usr/bin/env python3
"""
RedTeam Harness — structural perf invariant test (hot-path regression gate).

Catches the O(rules×findings) blowup that the v5.8 perf pass fixed, by
asserting the FIX ITSELF: `correlate()` computes `_finding_text()` and
`_extract_tokens()` ONCE per finding (id-keyed cache) instead of once per
rule × regex × finding.

Why a structural test and not just a wall-clock budget: the regression is
only ~26% slower, which any CI-safe wall-clock ceiling (with headroom for
runner noise) lets through. Counting calls is machine-independent — it fails
the moment someone re-introduces the per-rule re-join.

Run: python3 tests/test_perf_invariant.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.correlation import FindingCorrelator

# Linear-call bound: post-fix code calls _finding_text/_extract_tokens
# exactly once per finding (plus at most a small constant for helpers).
# Pre-fix code called them inside every rule × regex loop: ~29 rules × N.
# 5×N cleanly separates the two (post-fix ≤ ~2N, pre-fix ≥ ~29N).
MAX_CALLS_PER_FINDING = 5

SAMPLE_FINDINGS = [
    {"title": "Open port 445", "severity": "high", "category": "recon",
     "evidence": "SMB signing disabled on 445/tcp, Samba smbd 4.13.17, "
                 "MS17-010 EternalBlue candidates; host 10.0.0.5"},
    {"title": "Apache path traversal", "severity": "critical", "category": "web",
     "evidence": "CVE-2021-41773 on Apache httpd 2.4.41 at 10.0.0.5:80, "
                 "mod_negotiation enabled"},
    {"title": "SQL injection", "severity": "critical", "category": "web",
     "evidence": "Error-based ' OR 1=1-- on /login, union select 1,2,3, "
                 "MySQL 8.0.28 backend"},
    {"title": "SSH brute force", "severity": "medium", "category": "auth",
     "evidence": "OpenSSH 8.2p1 on 22/tcp, password auth enabled, "
                 "201 failed logins from 10.0.0.99"},
    {"title": "Backup file exposed", "severity": "medium", "category": "web",
     "evidence": "/backup.zip found by gobuster, size 890, on 10.0.0.5"},
    {"title": "PHP info leak", "severity": "low", "category": "web",
     "evidence": "phpinfo() at /config.php, PHP 7.4.3, $HOME and db creds"},
]


def main():
    correlator = FindingCorrelator()

    # ── Spy on the pure functions: count calls during one correlate() ──
    # Keep the ORIGINAL descriptors from __dict__ so the finally-restore
    # reinstates the exact staticmethod descriptors (class-level reads would
    # unwrap them to plain functions and break later bound lookups).
    calls = {"text": 0, "tokens": 0}
    orig_text = FindingCorrelator.__dict__["_finding_text"]
    orig_tokens = FindingCorrelator.__dict__["_extract_tokens"]

    def spy_text(finding):
        calls["text"] += 1
        return orig_text(finding)

    def spy_tokens(finding):
        calls["tokens"] += 1
        return orig_tokens(finding)

    FindingCorrelator._finding_text = staticmethod(spy_text)
    FindingCorrelator._extract_tokens = staticmethod(spy_tokens)
    try:
        paths = correlator.correlate(list(SAMPLE_FINDINGS))
    finally:
        FindingCorrelator._finding_text = orig_text
        FindingCorrelator._extract_tokens = orig_tokens

    n = len(SAMPLE_FINDINGS)
    limit = n * MAX_CALLS_PER_FINDING
    failed = False

    for name, count in (("_finding_text", calls["text"]),
                        ("_extract_tokens", calls["tokens"])):
        status = "OK" if count <= limit else "FAIL"
        print(f"  {name}: {count} calls for {n} findings (limit {limit}) [{status}]")
        if count > limit:
            failed = True

    if not paths:
        print("FAIL: correlate produced no paths", file=sys.stderr)
        failed = True

    if failed:
        print("PERF INVARIANT BROKEN — O(rules×findings) re-join reintroduced "
              "in correlate() (v5.8 perf regression)", file=sys.stderr)
        sys.exit(1)

    print("PERF INVARIANT OK — _finding_text/_extract_tokens computed once "
          "per finding (id-keyed cache intact)")


if __name__ == "__main__":
    main()
