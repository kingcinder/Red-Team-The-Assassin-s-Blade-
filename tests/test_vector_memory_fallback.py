#!/usr/bin/env python3
"""
RedTeam Harness — air-gap vector memory fallback test.

Guards the air-gap guarantee: numpy / scikit-learn are NOT in the wheels
bundle, so on a clean air-gapped host VectorMemory must still boot and
retrieve findings via the pure-stdlib keyword fallback. This test forces
_HAS_VECTOR_DEPS off and asserts the full ingest → query → query_by_target
→ save/load cycle works without numpy or sklearn.

Run: python3 tests/test_vector_memory_fallback.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.vector_memory as vm_module
from core.vector_memory import VectorMemory

SAMPLE = [
    {"title": "Apache path traversal", "severity": "critical", "category": "web",
     "evidence": "CVE-2021-41773 on 10.0.0.5:80, mod_negotiation enabled"},
    {"title": "SQL injection", "severity": "critical", "category": "web",
     "evidence": "Error-based ' OR 1=1-- on /login, union select 1,2,3, MySQL"},
    {"title": "SSH brute force", "severity": "medium", "category": "auth",
     "evidence": "OpenSSH 8.2p1 on 22/tcp, 201 failed logins from 10.0.0.99"},
]


def main():
    # ── Force the air-gapped condition: no numpy, no sklearn ──
    saved_flag = vm_module._HAS_VECTOR_DEPS
    vm_module._HAS_VECTOR_DEPS = False
    failed = False
    try:
        workdir = tempfile.mkdtemp(prefix="rt_mem_fb_")
        mem = VectorMemory(workdir)

        for f in SAMPLE:
            mem.ingest(f, session_id="airgap_test")

        # 1. Keyword query ranks the matching finding first
        results = mem.query("apache path traversal CVE")
        if not results or results[0]["title"] != "Apache path traversal":
            print("FAIL: keyword query did not rank the apache finding first",
                  file=sys.stderr)
            failed = True
        else:
            print(f"  ✓ keyword query -> {results[0]['title']} "
                  f"(sim {results[0]['similarity']}, "
                  f"retrieval={results[0].get('retrieval')})")

        # 2. query_by_target direct-match still works
        by_target = mem.query_by_target("10.0.0.5")
        if not any("Apache" in f["title"] for f in by_target):
            print("FAIL: query_by_target direct match missed", file=sys.stderr)
            failed = True
        else:
            print("  ✓ query_by_target direct match ->",
                  [f["title"] for f in by_target])

        # 3. get_context_block (LLM injection path) still produces output
        block = mem.get_context_block("10.0.0.5")
        if not block or "Prior Findings" not in block:
            print("FAIL: context block empty", file=sys.stderr)
            failed = True
        else:
            print(f"  ✓ context block ({len(block)} chars)")

        # 4. Save + reload cycle (JSON-only persistence, no numpy)
        mem.save()
        mem2 = VectorMemory(workdir)
        stats = mem2.get_stats()
        if stats.get("total_findings") != len(SAMPLE):
            print("FAIL: reload lost findings", file=sys.stderr)
            failed = True
        else:
            print(f"  ✓ reload: {stats['total_findings']} findings, "
                  f"fitted={stats.get('fitted')} (JSON-only, no vectors)")
    finally:
        vm_module._HAS_VECTOR_DEPS = saved_flag

    if failed:
        print("VECTOR MEMORY AIR-GAP FALLBACK FAILED", file=sys.stderr)
        sys.exit(1)
    print("VECTOR MEMORY AIR-GAP FALLBACK OK — boots and retrieves without "
          "numpy/sklearn")


if __name__ == "__main__":
    main()
