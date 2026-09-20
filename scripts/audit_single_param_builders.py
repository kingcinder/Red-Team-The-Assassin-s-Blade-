#!/usr/bin/env python3
"""Audit every single-param ToolRegistry entry using the exact built argv.

The original audit rebuilt commands but executed ``[real_binary, sample]``.
That discarded subcommands, flags, sudo prefixes, wrapper arguments, and
custom-builder behavior. This version executes the exact argv returned by
``ToolRegistry._build_command`` and records enough evidence to distinguish
argument-shape failures from wrapper/runtime failures.
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from core.tool_registry import ToolRegistry  # noqa: E402

SAMPLES = {
    "target": "127.0.0.1", "host": "127.0.0.1", "ip": "127.0.0.1",
    "server": "127.0.0.1:11601", "domain": "localhost",
    "url": "http://127.0.0.1:9/", "email": "probe@localhost",
    "username": "smoketest", "user": "smoketest",
    "hash": "5d41402abc4b2a76b9719d911017c592", "file": "/dev/null",
    "path": "/dev/null", "binary": "/bin/true", "command": "id",
    "image": "localhost/nonexistent:image", "interface": "lo",
    "word": "smoketest", "query": "smoketest", "kernel": "5.15.0",
    "mode": "help", "dump": "/dev/null", "apk": "/dev/null",
    "port": "9", "neo4j_url": "bolt://127.0.0.1:7687",
}

FLAG_ERROR_SIGS = (
    "unrecognized argument", "unrecognized arguments", "invalid option --",
    "unknown option", "no such option", "unrecognized option",
    "the following arguments are required", "unknown command",
    "unexpected argument", "invalid choice", "unknown flag",
    "missing required flag", "required but not found", "flag provided but not defined",
)
WRAPPER_ERROR_SIGS = (
    "bad interpreter", "exec format error", "can't open file '/home/",
    "line 2: cd:", "line 3: cd:", "no module named",
)
INTERCEPTED_TOOLS = frozenset({
    "install_tool", "list_missing_tools", "install_all_missing",
    "check_tool_status", "msf_auto_exploit",
})
TIMEOUT = 8


def sample_for(param_name: str) -> str:
    return SAMPLES.get(param_name.lower(), "smoketest-arg")


def run_isolated(argv, timeout, scratch: str):
    """Run a probe inside a disposable scratch dir with a tmp HOME and TMPDIR.

    Probed binaries may treat the sample argument as an output filename (e.g.
    gophish writes a config-derived file) or expand "~" paths; running them in
    the repo root would drop debris like a 0-byte ``smoketest-arg`` file there.
    Returns (rc, combined_output, error, created_paths).
    """
    env = {
        **os.environ,
        "TERM": "dumb",
        "HOME": scratch,
        "TMPDIR": scratch,
        "PWD": scratch,
    }
    try:
        p = subprocess.run(
            [str(part) for part in argv], capture_output=True, text=True,
            timeout=timeout, stdin=subprocess.DEVNULL, cwd=scratch, env=env,
        )
        created = sorted(
            os.path.join(root, name)
            for root, _dirs, files in os.walk(scratch)
            for name in files
        )
        return p.returncode, (p.stdout or "") + (p.stderr or ""), None, created
    except subprocess.TimeoutExpired:
        return None, "", "timeout", []
    except OSError as exc:
        return -1, "", str(exc), []


def classify_runtime(argv, rc, output, error):
    if error == "timeout":
        return "HANG-REVIEW", f"no exit within {TIMEOUT}s"
    flat = " ; ".join(output.splitlines())[:300]
    low = output.lower()
    if any(sig in low for sig in WRAPPER_ERROR_SIGS):
        return "BROKEN-WRAPPER", flat or str(error)
    if any(sig in low for sig in FLAG_ERROR_SIGS):
        return "BROKEN-ARGUMENT-SHAPE", flat or str(error)
    if rc == 0:
        return "OK", flat or "(exit 0, silent)"
    if output.strip():
        return "OK", flat
    return "REVIEW-AMBIGUOUS", f"rc={rc}, no output"


def markdown_report(report, counts):
    lines = [
        "# Single-Param Builder Audit — exact argv",
        "",
        "This report executes the exact argv produced by `ToolRegistry._build_command`; it does not reconstruct `[binary, sample]`.",
        "",
        "## Counts",
        "",
        f"Registry counts: `{counts}`",
        "",
        "| Tool | Param | Exact argv | Verdict | Evidence |",
        "|---|---|---|---|---|",
    ]
    for item in report:
        argv = " ".join(str(part) for part in item["argv"]).replace("|", "\\|")
        evidence = item["evidence"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{item['tool']}` | `{item['param']}` | `{argv}` | **{item['verdict']}** | {evidence} |")
    return "\n".join(lines) + "\n"


def main():
    reg = ToolRegistry({"output_dir": "/tmp/audit-single-param"})
    tools = sorted(reg.get_all_tools().values(), key=lambda t: t.name)
    counts = {"0": 0, "1": 0, "multi": 0}
    single = []
    for tool in tools:
        n = len(tool.parameters or {})
        key = "multi" if n > 1 else str(n)
        counts[key] += 1
        if n == 1:
            single.append(tool)

    print(f"registry: {len(tools)} tools — 0-param: {counts['0']}, 1-param: {counts['1']}, multi-param: {counts['multi']}")
    print(f"auditing {len(single)} single-param tools with exact built argv\n")
    report = []

    for tool in single:
        pname = next(iter(tool.parameters))
        sample = sample_for(pname)
        build_error = None
        try:
            argv = reg._build_command(tool, {pname: sample})
        except Exception as exc:
            argv = []
            build_error = str(exc)
        real = tool.path or tool.binary
        entry = {
            "tool": tool.name, "param": pname, "sample": sample,
            "argv": argv, "destructive": bool(tool.destructive),
            "installed": tool.installed, "realpath": real,
            "verdict": "", "evidence": "",
        }
        print(f"── {tool.name} ({pname})")
        print(f"   argv: {' '.join(str(part) for part in argv) or '(none)'}")

        if build_error:
            entry["verdict"] = "BROKEN-ARGUMENT-SHAPE"
            entry["evidence"] = f"builder error: {build_error}"
        elif tool.name in INTERCEPTED_TOOLS:
            entry["verdict"] = "INTERNAL-INTERCEPTED"
            entry["evidence"] = "Python interceptor owns execution; no shell binary probe"
        elif not tool.installed or not real or not os.path.exists(real):
            entry["verdict"] = "MISSING-BINARY"
            entry["evidence"] = f"realpath not resolvable: {real}"
        elif tool.destructive:
            entry["verdict"] = "SKIP-DESTRUCTIVE"
            entry["evidence"] = "destructive-flagged; no exec probe"
        elif argv and argv[0] == "sudo":
            entry["verdict"] = "SKIP-PRIVILEGED"
            entry["evidence"] = "exact argv requires sudo; no privileged probe"
        else:
            with tempfile.TemporaryDirectory(prefix="audit-single-param-") as scratch:
                rc, output, error, created = run_isolated(argv, TIMEOUT, scratch)
                entry["verdict"], entry["evidence"] = classify_runtime(
                    argv, rc, output, error)
                if created:
                    entry["evidence"] += \
                        f" [probe wrote {len(created)} scratch file(s)]"
        print(f"   → {entry['verdict']}: {entry['evidence']}\n")
        report.append(entry)

    # Safety net: remove 0-byte sample-named debris probes may have leaked
    # into the repo root (e.g. smoketest-arg) before reports are written.
    swept = 0
    for tool in single:
        pname = next(iter(tool.parameters), None)
        if not pname:
            continue
        name = os.path.basename(str(sample_for(pname)))
        leaked = os.path.join(REPO, name)
        if os.path.isfile(leaked) and os.path.getsize(leaked) == 0:
            os.remove(leaked)
            swept += 1
    if swept:
        print(f"swept {swept} leaked probe artifact(s) from repo root")

    tally = {}
    for item in report:
        tally[item["verdict"]] = tally.get(item["verdict"], 0) + 1
    print("═══ VERDICT TALLY ═══")
    for key in sorted(tally):
        print(f"{key}: {tally[key]}")

    json_path = os.path.join(REPO, "docs", "single_param_audit.json")
    md_path = os.path.join(REPO, "docs", "single_param_audit.md")
    payload = {"counts": counts, "results": report, "tally": tally,
               "method": "executed exact ToolRegistry._build_command argv"}
    with open(json_path, "w") as handle:
        json.dump(payload, handle, indent=1)
    with open(md_path, "w") as handle:
        handle.write(markdown_report(report, counts))
    print(f"\nfull reports: {json_path}, {md_path}")
    return 1 if any(item["verdict"] == "BROKEN-ARGUMENT-SHAPE" for item in report) else 0


if __name__ == "__main__":
    sys.exit(main())
