#!/usr/bin/env python3
"""Tests for ToolScorer (v4.1) — deadlock regression + persistence.

Covers the systematic-debugging fix for a critical bug: `save()`, the
periodic save inside `record()`, and `reset_*` all called `_save()` while
already holding the non-reentrant `self._lock`, deadlocking on the inner
acquire. Every engagement end called `scorer.save()` -> the harness hung.

Run: python3 tests/test_tool_scorer.py
"""
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

FAILED = []


def check(name, cond, detail=""):
    print(f"  [{'✓' if cond else '✗'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(f"{name}: {detail}")


def run_with_timeout(fn, timeout=3.0):
    """Run fn in a daemon thread; return (ok, error_or_None). A deadlock
    means the thread never returns -> ok=False after the timeout."""
    box = {}

    def target():
        try:
            fn()
            box["ok"] = True
        except Exception as e:  # noqa: BLE001
            box["err"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return False, "DEADLOCK (thread still running after timeout)"
    if "err" in box:
        return False, box["err"]
    return box.get("ok", False), None


def main():
    from core.tool_scorer import ToolScorer

    print("═══ ToolScorer deadlock + persistence suite ═══")

    tmp = tempfile.mkdtemp(prefix="rt_scorer_")
    score_file = os.path.join(tmp, "tool_scores.json")

    # ── 1. save() must not deadlock (regression: hung forever) ──
    print("\n[1] save() no deadlock")
    s = ToolScorer(tmp)
    s.record("nmap_scan", True, duration=1.2)
    ok, err = run_with_timeout(s.save)
    check("save() returns", ok, f"{err}")
    check("score file written", os.path.exists(score_file))

    # ── 2. periodic save inside record() (every 10th run) no deadlock ──
    print("\n[2] record() periodic save no deadlock")
    s2 = ToolScorer(tmp)
    ok, err = run_with_timeout(lambda: [s2.record("nikto_scan", i % 2 == 0) for i in range(12)])
    check("record() x12 returns (periodic save)", ok, f"{err}")

    # ── 3. reset_tool / reset_all no deadlock ──
    print("\n[3] reset paths no deadlock")
    ok, err = run_with_timeout(lambda: s2.reset_tool("nikto_scan"))
    check("reset_tool() returns", ok, f"{err}")
    ok, err = run_with_timeout(s2.reset_all)
    check("reset_all() returns", ok, f"{err}")

    # ── 4. persistence round-trip ──
    print("\n[4] persistence round-trip")
    s3 = ToolScorer(tmp)
    s3.record("gobuster_dir", True, duration=3.3)
    s3.record("gobuster_dir", False, error="timeout", timed_out=True)
    ok, err = run_with_timeout(s3.save)
    check("save() persists", ok, f"{err}")
    check("score file exists", os.path.exists(score_file))
    if os.path.exists(score_file):
        with open(score_file) as f:
            data = json.load(f)
        check("file is valid JSON with version", data.get("version") == "4.1")
        check("gobuster_dir tracked", "gobuster_dir" in data.get("scores", {}))
    else:
        data = {}
        check("file is valid JSON with version", False, "no file to parse")
    reloaded = ToolScorer(tmp)
    check("reload sees 2 invocations",
          reloaded.get_stats()["total_invocations"] == 2)
    rel = reloaded.get_reliability("gobuster_dir")
    check("reliability in [0,1]", 0.0 <= rel <= 1.0, f"got {rel}")

    # ── 5. reliability hint + report surfaces ──
    print("\n[5] LLM-facing surfaces")
    # hint only includes tools with >= min_runs (default 3); the fixture has
    # 2 invocations, so pass min_runs=1 to exercise the surface.
    hint = reloaded.get_reliability_hint(min_runs=1)
    check("reliability hint non-empty", len(hint) > 0)
    report = reloaded.get_report()
    check("report has tools", isinstance(report.get("tools"), (dict, list)))

    # ── 6. no re-acquire pattern remains in internal callers ──
    print("\n[6] internal callers use use_lock=False (root-cause guard)")
    src = open("core/tool_scorer.py").read()
    # save()/record()/reset_* must pass use_lock=False since they hold the lock
    import re
    bad = re.findall(r"^\s+self\._save\(\)\s*$", src, re.M)
    check("no bare self._save() from lock-holding callers", not bad,
          f"found: {bad}")

    # cleanup
    try:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    except Exception:
        pass

    print(f"\n{'═' * 50}\n{'ALL TESTS PASSED' if not FAILED else f'{len(FAILED)} FAILURES'}")
    for f in FAILED:
        print("  FAIL:", f)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
