#!/usr/bin/env python3
"""Scheduled system health check built on scripts/discover_system_bugs.py.

Runs the read-only whole-system discovery scan, compares the result with a
persisted baseline of known findings, and fails loudly (nonzero exit +
[HEALTH-ALERT] output) when any NEW high-severity finding appears — the class
of rot previously found (broken builders, stale wrappers, missing libs) gets
caught automatically instead of silently returning.

Exit codes:
    0 = healthy (no new findings, or only known ones)
    1 = alert (new finding(s), including any new high-severity finding)
    2 = operational error (scanner crashed, unreadable baseline, bad usage)

Usage:
    health_check.py [--baseline PATH] [--json PATH] [--md PATH]
                    [--fail-on {any,high}] [--update-baseline]

--update-baseline records the current findings as the accepted baseline
(used after deliberately accepting a finding or after a remediation).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

DEFAULT_BASELINE = os.path.join(REPO, "docs", "health_baseline.json")
DEFAULT_JSON = os.path.join(REPO, "docs", "system_discovery_report.json")
DEFAULT_MD = os.path.join(REPO, "docs", "system_discovery_report.md")
SCANNER = os.path.join(REPO, "scripts", "discover_system_bugs.py")


def run_scan(json_path: str, md_path: str) -> tuple[int, str]:
    """Run the discovery scanner as a subprocess. Returns (returncode, output)."""
    try:
        proc = subprocess.run(
            [sys.executable, SCANNER,
             "--repo-root", REPO,
             "--output-json", json_path,
             "--output-md", md_path],
            capture_output=True, text=True, timeout=900,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "scanner timed out after 900s"
    except OSError as exc:
        return -1, str(exc)


def load_baseline(path: str) -> dict:
    """Load the baseline. A missing file is an empty baseline, not an error."""
    if not os.path.exists(path):
        return {"findings": {}, "updated_at": None}
    try:
        with open(path) as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
            raise ValueError("baseline root must be an object with 'findings'")
        return data
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[HEALTH-ERROR] baseline unreadable: {path} ({exc})", file=sys.stderr)
        raise SystemExit(2)


def write_baseline(path: str, findings: dict) -> None:
    payload = {"findings": findings, "updated_at": _utcnow()}
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(payload, handle, indent=1, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


def _utcnow() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def finding_signature(item: dict) -> str:
    """Stable identity of a finding: category + resolved location."""
    where = (item.get("where") or "").rstrip("/")
    return f"{item.get('category','?')}::{where}"


def severity_of(item: dict) -> str:
    return (item.get("severity") or "unknown").lower()


def compare(baseline: dict, current: list) -> dict:
    known = baseline.get("findings", {})
    new = []
    for item in current:
        sig = finding_signature(item)
        if sig not in known:
            new.append(item)
    resolved = [sig for sig in known if sig not in
                {finding_signature(i) for i in current}]
    return {"new": new, "resolved": resolved, "known": known}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--json", dest="json_path", default=DEFAULT_JSON)
    parser.add_argument("--md", dest="md_path", default=DEFAULT_MD)
    parser.add_argument("--fail-on", choices=("any", "high"), default="high",
                        help="fail on any new finding, or only high-severity ones")
    parser.add_argument("--update-baseline", action="store_true",
                        help="record current findings as the baseline and exit 0")
    args = parser.parse_args(argv)

    if args.update_baseline:
        rc, output = run_scan(args.json_path, args.md_path)
        if rc != 0:
            print(f"[HEALTH-ERROR] scanner failed (rc={rc}):\n{output}",
                  file=sys.stderr)
            return 2
        with open(args.json_path) as handle:
            current = json.load(handle).get("findings", [])
        baseline = {finding_signature(i): {
            "id": i.get("id"), "category": i.get("category"),
            "severity": severity_of(i), "what": i.get("what"),
        } for i in current}
        write_baseline(args.baseline, baseline)
        print(f"[HEALTH-OK] baseline updated: {len(baseline)} finding(s) recorded")
        return 0

    rc, output = run_scan(args.json_path, args.md_path)
    if rc != 0:
        print(f"[HEALTH-ERROR] scanner failed (rc={rc}):\n{output}", file=sys.stderr)
        return 2
    try:
        with open(args.json_path) as handle:
            current = json.load(handle).get("findings", [])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[HEALTH-ERROR] scan output unreadable: {exc}", file=sys.stderr)
        return 2

    result = compare(load_baseline(args.baseline), current)
    new_high = [i for i in result["new"] if severity_of(i) == "high"]

    if not result["new"]:
        print(f"[HEALTH-OK] 0 new findings; "
              f"{len(result['known'])} known finding(s) accepted in baseline")
        return 0

    # New findings exist — report loudly regardless of the fail threshold.
    print(f"[HEALTH-ALERT] {len(result['new'])} new finding(s) "
          f"({len(new_high)} high severity)")
    for item in result["new"]:
        marker = "HIGH" if severity_of(item) == "high" else item.get("severity", "?")
        print(f"  [{marker}] {item.get('id')}: {item.get('what')} "
              f"@ {item.get('where')}")
    if result["resolved"]:
        print(f"[HEALTH-INFO] {len(result['resolved'])} previously known "
              f"finding(s) no longer present (fixed or removed)")

    if args.fail_on == "high" and not new_high:
        print("[HEALTH-WARN] new medium/low findings recorded; "
              "failing threshold is 'high'")
        return 0

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # operational failure must never look healthy
        print(f"[HEALTH-ERROR] unexpected failure: {exc}", file=sys.stderr)
        sys.exit(2)
