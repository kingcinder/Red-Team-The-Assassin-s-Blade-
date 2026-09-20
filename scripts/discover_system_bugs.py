#!/usr/bin/env python3
"""Read-only discovery pass for repository and local tool-system defects.

This scanner intentionally does not repair findings. It reads source and
metadata, inspects executable paths, runs bounded local help/version probes,
and emits structured what/when/where/why/how evidence.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from typing import Iterable

REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_PATHS = (
    "/usr/bin", "/usr/sbin", "/usr/local/bin", "/snap/bin",
)
REQUIRED_FIELDS = {
    "id", "category", "severity", "confidence", "what", "when", "where",
    "why", "how", "evidence", "status", "recommended_correction",
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def finding(fid, category, severity, confidence, what, where, why, how,
            evidence, recommendation, status="new"):
    return {
        "id": fid,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "what": what,
        "when": now_iso(),
        "where": str(where),
        "why": why,
        "how": how,
        "evidence": evidence,
        "status": status,
        "recommended_correction": recommendation,
    }


def inspect_path(path: pathlib.Path):
    """Return one static finding for a broken path, or None."""
    try:
        if path.is_symlink() and not path.exists():
            return finding(
                "PATH-DANGLING-" + path.name,
                "dangling-symlink", "medium", "high",
                "Executable symlink points to a missing target.", path,
                "The target was removed or relocated without updating the link.",
                f"Readlink and test the target: readlink {path}; test -e {path}",
                f"target={os.readlink(path)}",
                "Restore the target or remove/repoint the stale symlink.",
            )
        if not path.is_file() or not os.access(path, os.X_OK):
            return None
        with path.open("rb") as handle:
            head = handle.read(256)
        if head.startswith(b"#!"):
            line = head.splitlines()[0].decode(errors="replace")[2:].strip()
            interpreter = line.split()[0] if line else ""
            if interpreter and not pathlib.Path(interpreter).exists() and not shutil.which(interpreter):
                return finding(
                    "PATH-SHEBANG-" + path.name,
                    "missing-interpreter", "medium", "high",
                    "Executable script has no available shebang interpreter.", path,
                    "The interpreter was removed or the script was copied from another host.",
                    f"Run the script or inspect its first line: head -1 {path}",
                    f"shebang={line}",
                    "Install the required interpreter or update the launcher contract.",
                )
        return None
    except (OSError, UnicodeError) as exc:
        return finding(
            "PATH-INSPECT-" + path.name,
            "inspection-error", "low", "medium",
            "Executable path could not be inspected.", path,
            "Filesystem permissions or a transient path error interrupted inspection.",
            f"Retry a read-only stat/read of {path}", str(exc),
            "Investigate the filesystem or permissions error.",
        )


def run_safe_probe(argv: list[str], timeout: int = 6) -> dict:
    """Run a bounded, scratch-isolated, stdin-safe probe; never raises.

    Each probe executes inside a disposable TemporaryDirectory that owns the
    process CWD, HOME, TMPDIR and PWD. Probed binaries that treat arguments
    as output paths (or expand '~') can therefore only ever write into
    scratch that vanishes with the call — they can never drop debris into
    the repository root or the user's home (the same leak class previously
    fixed in scripts/audit_single_param_builders.py).

    All call sites pass absolute paths (realpath'd tool paths, absolute file
    arguments), so isolation cannot change any probe's verdict.
    """
    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix="sysdisc-probe-") as scratch:
            env = {
                **os.environ,
                "TERM": "dumb",
                "HOME": scratch,
                "TMPDIR": scratch,
                "PWD": scratch,
            }
            proc = subprocess.run(
                argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=timeout, cwd=scratch, env=env, check=False,
            )
        return {
            "argv": argv, "returncode": proc.returncode,
            "timed_out": False,
            "output": ((proc.stdout or "") + (proc.stderr or ""))[:500],
        }
    except subprocess.TimeoutExpired:
        return {"argv": argv, "returncode": None, "timed_out": True, "output": "timeout"}
    except OSError as exc:
        return {"argv": argv, "returncode": -1, "timed_out": False, "output": str(exc)}


def scan_wrappers(paths: list[pathlib.Path]) -> list[dict]:
    findings = []
    for root in paths:
        if not root.exists():
            continue
        for path in root.iterdir():
            issue = inspect_path(path)
            if issue:
                findings.append(issue)
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            cwd_flagged = False
            if re.search(r"(^|\s)cd\s+/(tmp|var/tmp)/", text, re.MULTILINE):
                cwd_flagged = True
                findings.append(finding(
                    "WRAPPER-VOLATILE-CWD-" + path.name,
                    "wrapper-cwd", "medium", "high",
                    "Executable wrapper depends on a volatile temporary directory.", path,
                    "The wrapper assumes an installation under /tmp or /var/tmp that may disappear after cleanup or reboot.",
                    f"Inspect wrapper and execute its help probe: sed -n '1,5p' {path}; {path} --help",
                    text[:500],
                    "Use a durable verified installation path and preserve argv forwarding.",
                ))
            if not cwd_flagged:
                # Durability: only TEXT scripts are inspected, and only for
                # load-bearing execution references into volatile storage
                # (cd/exec/source/interpreter on a /tmp path). ELF binaries
                # legitimately embed '/tmp' string constants (default socket
                # paths, compile-time defaults) and are NOT wrappers. Scratch
                # writes ("> /tmp/x.log") and mktemp usage are exempt.
                with path.open("rb") as handle:
                    if handle.read(4) == b"\x7fELF":
                        continue
                head = text[:2]
                if head != "#!":
                    continue
                active = [
                    line for line in text.splitlines()
                    if re.search(
                        r"(^|\s|;|&&)(cd|exec|source|(python3?(\.\d+)?|bash|sh|perl|ruby)\s+)\s*/?(tmp|var/tmp|dev/shm|run)/",
                        line)
                    and "mktemp" not in line
                    and not line.lstrip().startswith("#")
                ]
                if active:
                    findings.append(finding(
                        "WRAPPER-VOLATILE-REF-" + path.name,
                        "wrapper-cwd", "medium", "high",
                        "Executable script executes from or loads code under volatile storage.",
                        path,
                        "The wrapper cd's into, executes, or sources files under volatile directories (/tmp, /var/tmp, /dev/shm, /run) that do not survive cleanup or reboot.",
                        f"Inspect references: grep -nE '(cd|exec|source) .*/(tmp|var/tmp|dev/shm|run)/' {path}",
                        "\n".join(active[:8])[:500],
                        "Reinstall the tool in a durable location and repoint the wrapper.",
                    ))
            if re.search(r"python3\s+[^\n]*\.py", text) and "rsmangler.py" in text:
                target = pathlib.Path("/home/cody/tools/rsmangler/rsmangler.py")
                if not target.exists():
                    findings.append(finding(
                        "WRAPPER-MISSING-TARGET-" + path.name,
                        "wrapper-target", "high", "high",
                        "Wrapper invokes a missing Python source file.", path,
                        "The wrapper points at a stale source filename while a different implementation may exist.",
                        f"Run the wrapper with --help: {path} --help",
                        f"missing_target={target}",
                        "Point the wrapper at a verified installed entry point.",
                    ))
    return findings


def scan_elf_dependencies(paths: list[pathlib.Path]) -> list[dict]:
    findings = []
    for root in paths:
        if not root.exists():
            continue
        for path in root.iterdir():
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            try:
                with path.open("rb") as handle:
                    if handle.read(4) != b"\x7fELF":
                        continue
                # Probe the resolved target: ldd mis-expands $ORIGIN when
                # handed a symlink path (e.g. /usr/bin/<-> /etc/alternatives),
                # reporting libs as missing for binaries that run correctly.
                real = path.resolve()
                result = run_safe_probe(["ldd", str(real)], timeout=4)
                missing = [line.strip() for line in result["output"].splitlines()
                           if "not found" in line]
                if missing:
                    findings.append(finding(
                        "ELF-MISSING-LIB-" + path.name,
                        "elf-dependency", "high", "high",
                        "ELF executable has unresolved shared-library dependencies.", real,
                        "The binary and its libraries were installed or removed out of sync.",
                        f"Run: ldd {real}", "\n".join(missing),
                        "Restore compatible libraries or remove the unusable binary.",
                    ))
            except OSError:
                continue
    return findings


def scan_python_environments(home: pathlib.Path) -> list[dict]:
    findings = []
    candidates = [home / ".local" / "bin"]
    candidates.extend(home.glob("**/bin"))
    seen = set()
    for bindir in candidates:
        if not bindir.is_dir() or bindir in seen:
            continue
        seen.add(bindir)
        python = bindir / "python"
        pip = bindir / "pip"
        if not python.exists() or not pip.exists():
            continue
        probe = run_safe_probe([str(pip), "check"], timeout=10)
        # A clean environment is not a finding: only a nonzero exit is a
        # dependency problem. pip check prints "No broken requirements found."
        # on success, so stdout alone must never trigger a record.
        if probe["returncode"] not in (0, None):
            findings.append(finding(
                "PYENV-PIP-CHECK-" + str(bindir).replace("/", "-").strip("-"),
                "python-dependency", "medium", "medium",
                "Python environment reports dependency metadata problems.", bindir,
                "Installed package metadata does not form a clean dependency set.",
                f"Run: {pip} check", probe["output"],
                "Resolve or isolate the conflicting environment dependencies.",
            ))
    return findings


def _resolve_probe_binary(name: str) -> str | None:
    """Locate a probe binary in PATH or common version-manager locations.

    Scheduled runs (systemd timers) do not source interactive shell profiles,
    so tools installed via nvm-style managers are invisible to PATH. A probe
    binary that cannot be located must never be reported as an asset defect.
    """
    found = shutil.which(name)
    if found:
        return found
    extra_bases = (
        pathlib.Path.home() / ".nvm" / "versions",
        pathlib.Path.home() / ".local" / "bin",
    )
    for base in extra_bases:
        if not base.exists():
            continue
        direct = base / name
        if direct.exists():
            return str(direct)
        candidates = sorted(base.glob(f"*/bin/{name}"))
        if candidates:
            return str(candidates[-1])
    return None


def scan_assets(repo_root: pathlib.Path) -> list[dict]:
    """Parse repo data and syntax-check local script assets read-only."""
    findings = []
    for path in repo_root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            suffix = path.suffix.lower()
            if suffix == ".json":
                json.loads(path.read_text(errors="replace"))
            elif suffix in (".yaml", ".yml"):
                import yaml
                yaml.safe_load(path.read_text(errors="replace"))
            elif suffix == ".sh":
                bash = _resolve_probe_binary("bash")
                if bash:
                    probe = run_safe_probe([bash, "-n", str(path)], timeout=4)
                    if probe["returncode"] not in (0, None, -1):
                        findings.append(finding(
                            "ASSET-SHELL-SYNTAX-" + path.name, "syntax", "high", "high",
                            "Shell script fails a syntax-only parse.", path,
                            "The script contains shell syntax that bash cannot parse.",
                            f"Run: bash -n {path}", probe["output"],
                            "Correct the shell syntax before executing the script.",
                        ))
            elif suffix == ".js":
                node = _resolve_probe_binary("node")
                if not node:
                    # Probe tool unavailable in this environment (e.g. node
                    # lives in nvm and systemd PATH lacks it): skip, never flag.
                    continue
                probe = run_safe_probe([node, "--check", str(path)], timeout=4)
                if probe["returncode"] not in (0, None, -1):
                    findings.append(finding(
                        "ASSET-JS-SYNTAX-" + path.name, "syntax", "high", "high",
                        "JavaScript asset fails a syntax-only parse.", path,
                        "The asset contains invalid JavaScript syntax.",
                        f"Run: node --check {path}", probe["output"],
                        "Correct the JavaScript syntax before loading the asset.",
                    ))
        except Exception as exc:
            findings.append(finding(
                "ASSET-PARSE-" + path.name, "asset-parse", "high", "high",
                "Repository data or asset could not be parsed.", path,
                "The file is malformed or its parser failed.",
                f"Parse/check {path} with its native validator", str(exc),
                "Correct the malformed asset or regenerate it from its source.",
            ))
    return findings


def scan_inventory(repo_root: pathlib.Path, home: pathlib.Path) -> list[dict]:
    """Check generated external inventory paths and known stale contracts."""
    findings = []
    manifest = home / "redteam-tools" / "MANIFEST.tsv"
    if manifest.exists():
        try:
            for number, line in enumerate(manifest.read_text(errors="replace").splitlines(), 1):
                fields = line.split("\\t")
                if len(fields) < 5 or fields[0] == "binary":
                    continue
                path = pathlib.Path(fields[4])
                if fields[3] == "MISSING" or not fields[4]:
                    continue
                if not path.exists():
                    findings.append(finding(
                        f"INVENTORY-MISSING-{number}", "inventory-consistency", "high", "high",
                        "Generated tool inventory points at a missing executable.", manifest,
                        "The inventory was not regenerated after an installation was removed or moved.",
                        f"Inspect MANIFEST.tsv line {number} and test -e {path}",
                        f"tool={fields[0]}, path={path}",
                        "Rebuild the inventory after correcting the installation or mark the tool missing.",
                    ))
        except OSError as exc:
            findings.append(finding(
                "INVENTORY-READ-ERROR", "inventory-consistency", "medium", "high",
                "External tool inventory could not be read.", manifest,
                "The inventory file is unavailable or unreadable.",
                f"Read {manifest}", str(exc),
                "Restore readable inventory metadata and regenerate it.",
            ))

    roots = [repo_root / "core", repo_root / "tools", repo_root / "workflows",
             repo_root / "dashboard", repo_root / "scripts"]
    stale_patterns = (
        ("/tmp/enum4linux-ng", "stale volatile enum4linux path"),
        ("/home/cody/tools/rsmangler/rsmangler.py", "stale rsmangler Python path"),
    )
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (not path.is_file() or "__pycache__" in path.parts
                    or path.resolve() == pathlib.Path(__file__).resolve()):
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for marker, label in stale_patterns:
                if marker in text:
                    findings.append(finding(
                        "STALE-CONTRACT-" + path.name + "-" + str(len(findings)),
                        "stale-reference", "medium", "high",
                        f"Source or runtime asset retains a {label}.", path,
                        "The implementation or documentation still references a removed external path.",
                        f"Search: grep -nF {marker!r} {path}", marker,
                        "Update the reference to the verified durable contract.",
                    ))
    return findings


def scan_local_app(repo_root: pathlib.Path) -> list[dict]:
    """Boot the Flask app and inspect route registration without listening."""
    try:
        sys.path.insert(0, str(repo_root))
        from dashboard.server import create_app
        app = create_app()
        routes = [str(rule) for rule in app.url_map.iter_rules()]
        if not routes:
            return [finding(
                "APP-NO-ROUTES", "application-boot", "high", "high",
                "Dashboard app boots without registering routes.", repo_root,
                "Blueprint registration did not run during app assembly.",
                "Instantiate create_app() and inspect app.url_map", "route_count=0",
                "Restore blueprint registration before launching the dashboard.",
            )]
        return []
    except Exception as exc:
        return [finding(
            "APP-BOOT-ERROR", "application-boot", "high", "high",
            "Dashboard app cannot be created locally.", repo_root,
            "Application assembly or an import failed before a listener was started.",
            "Run a local create_app() smoke probe", str(exc),
            "Fix the app assembly/import failure before relying on the dashboard.",
        )]


def scan_registry(repo_root: pathlib.Path) -> list[dict]:
    findings = []
    sys.path.insert(0, str(repo_root))
    try:
        from core.tool_registry import ToolRegistry
        from core.tool_interceptor import INTERCEPTED_TOOLS
        registry = ToolRegistry({"output_dir": "/tmp/system-discovery"})
        for tool in registry.get_all_tools().values():
            if not tool.binary and tool.name not in INTERCEPTED_TOOLS:
                findings.append(finding(
                    "REGISTRY-EMPTY-BINARY-" + tool.name,
                    "registry-schema", "high", "high",
                    "Registry entry has no binary and is not intercepted.", tool.name,
                    "The entry can fall through to command construction with an empty executable.",
                    f"Inspect registry entry and call _build_command for {tool.name}",
                    f"binary={tool.binary!r}, intercepted={tool.name in INTERCEPTED_TOOLS}",
                    "Add a Python interceptor or remove the non-executable registry entry.",
                ))
            if tool.binary and tool.installed and not tool.path:
                findings.append(finding(
                    "REGISTRY-PATH-MISSING-" + tool.name,
                    "registry-resolution", "medium", "high",
                    "Registry marks a tool installed without a resolved executable path.", tool.name,
                    "Detection state and executable resolution disagree.",
                    f"Inspect ToolDefinition for {tool.name}",
                    f"binary={tool.binary}, path={tool.path}, installed={tool.installed}",
                    "Make installed state depend on a valid resolved path.",
                ))
    except Exception as exc:
        findings.append(finding(
            "REGISTRY-SCAN-ERROR", "scanner-error", "high", "high",
            "Registry scan could not complete.", repo_root,
            "Import or registry initialization failed during discovery.",
            "Run scripts/discover_system_bugs.py with stderr captured.", str(exc),
            "Fix the scanner or the import failure before relying on registry results.",
        ))
    return findings


def scan_repository(repo_root: pathlib.Path) -> list[dict]:
    findings = []
    for path in repo_root.rglob("*.py"):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            findings.append(finding(
                "REPO-PY-SYNTAX-" + path.name, "syntax", "high", "high",
                "Python source cannot be parsed.", path,
                "The file contains invalid syntax or could not be read.",
                f"Run: python3 -m py_compile {path}", str(exc),
                "Correct the syntax or restore the readable file.",
            ))
            continue
        imports_subprocess = any(
            isinstance(node, ast.Import) and any(alias.name == "subprocess" for alias in node.names)
            for node in ast.walk(tree)
        )
        if "core" in path.parts and "mech" in path.parts and imports_subprocess:
            findings.append(finding(
                "REPO-MECH-SUBPROCESS-" + path.name,
                "architecture-contract", "high", "high",
                "Mech package directly imports subprocess despite its execution boundary contract.", path,
                "The module bypasses the documented HardenedToolRunner ownership boundary.",
                f"Search imports and run the structural Mech test for {path}", "import subprocess",
                "Move process ownership behind the non-Mech execution boundary.",
            ))
    return findings


def scan_tool_probes(repo_root: pathlib.Path) -> list[dict]:
    findings = []
    sys.path.insert(0, str(repo_root))
    try:
        from core.tool_registry import ToolRegistry
        registry = ToolRegistry({"output_dir": "/tmp/system-discovery"})
        for tool in registry.get_installed_tools():
            if not tool.path or tool.destructive or not tool.parameters:
                continue
            probe = run_safe_probe([tool.path, "--help"], timeout=4)
            if probe["timed_out"]:
                findings.append(finding(
                    "PROBE-HANG-" + tool.name, "runtime-probe", "low", "medium",
                    "Safe help probe did not exit within the bounded timeout.", tool.path,
                    "The tool may be interactive, perform first-run work, or ignore help under its wrapper.",
                    f"Run with timeout: timeout 4 {tool.path} --help", probe["output"],
                    "Classify the tool as interactive/slow or add a deterministic noninteractive health check.",
                    status="inconclusive",
                ))
    except Exception:
        pass
    return findings


def scan_repo_root_leaks(repo_root: pathlib.Path,
                         before: dict[str, tuple[int, float]]) -> list[dict]:
    """Detect 0-byte files that appeared in the repo root during the scan.

    With every probe scratch-isolated, probes cannot create these; if one
    appears anyway, it is from a concurrent process or a non-probe code
    path, so it is REPORTED, never deleted (deleting a file we cannot
    attribute would risk destroying a concurrent user file).
    """
    findings = []
    try:
        after = {
            entry.name: (entry.stat().st_size, entry.stat().st_mtime)
            for entry in repo_root.iterdir()
            if entry.is_file()
        }
    except OSError:
        return findings
    for name, (size, mtime) in after.items():
        if name in before:
            continue
        if size == 0:
            findings.append(finding(
                "SCAN-ROOT-LEAK-" + name, "scanner-integrity", "medium", "high",
                "A 0-byte file appeared in the repo root during the scan.",
                repo_root / name,
                "With probes scratch-isolated, this cannot come from a probe; a concurrent process or non-probe path created it.",
                f"Inspect timestamps and lsof for {repo_root / name}",
                f"name={name}, size=0, appeared during scan",
                "Identify the creating process; do not delete an unattributable file.",
                status="inconclusive",
            ))
    return findings


def discover(repo_root: pathlib.Path, home: pathlib.Path) -> dict:
    try:
        root_before = {
            entry.name: (entry.stat().st_size, entry.stat().st_mtime)
            for entry in repo_root.iterdir() if entry.is_file()
        }
    except OSError:
        root_before = {}
    path_roots = [pathlib.Path(p) for p in DEFAULT_PATHS]
    path_roots.extend([home / ".local" / "bin", home / "go" / "bin",
                       home / "redteam-tools" / "bin", home / "tools"])
    findings = []
    findings.extend(scan_repository(repo_root))
    findings.extend(scan_assets(repo_root))
    findings.extend(scan_registry(repo_root))
    findings.extend(scan_inventory(repo_root, home))
    findings.extend(scan_local_app(repo_root))
    findings.extend(scan_wrappers(path_roots))
    findings.extend(scan_elf_dependencies(path_roots[:4]))
    findings.extend(scan_python_environments(home))
    findings.extend(scan_tool_probes(repo_root))
    findings.extend(scan_repo_root_leaks(repo_root, root_before))
    return {
        "generated_at": now_iso(),
        "repo_root": str(repo_root),
        "home": str(home),
        "read_only": True,
        "findings": findings,
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Whole-System Discovery Report",
        "",
        f"Generated: `{report['generated_at']}`  ",
        f"Repository: `{report['repo_root']}`  ",
        f"Read-only: `{report['read_only']}`",
        "",
        "This pass is discovery-only. Findings below were not repaired during the scan.",
        "",
        f"**Findings:** {len(report['findings'])}",
        "",
    ]
    for item in report["findings"]:
        lines.extend([
            f"## {item['id']}", "",
            f"- **Category:** {item['category']}  ",
            f"- **Severity / confidence:** {item['severity']} / {item['confidence']}  ",
            f"- **Status:** {item['status']}  ",
            f"- **When:** {item['when']}  ",
            f"- **Where:** `{item['where']}`  ",
            f"- **What:** {item['what']}  ",
            f"- **Why:** {item['why']}  ",
            f"- **How detected/reproduced:** {item['how']}  ",
            f"- **Evidence:** `{item['evidence']}`  ",
            f"- **Recommended correction:** {item['recommended_correction']}", "",
        ])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=pathlib.Path, default=REPO)
    parser.add_argument("--home", type=pathlib.Path, default=pathlib.Path.home())
    parser.add_argument("--output-json", type=pathlib.Path, default=REPO / "docs/system_discovery_report.json")
    parser.add_argument("--output-md", type=pathlib.Path, default=REPO / "docs/system_discovery_report.md")
    args = parser.parse_args(argv)
    report = discover(args.repo_root.resolve(), args.home.resolve())
    for item in report["findings"]:
        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            raise ValueError(f"finding {item.get('id')} missing fields: {sorted(missing)}")
    args.output_json.write_text(json.dumps(report, indent=2) + "\n")
    args.output_md.write_text(render_markdown(report) + "\n")
    print(f"DISCOVERY_COMPLETE findings={len(report['findings'])}")
    print(f"JSON={args.output_json}")
    print(f"MARKDOWN={args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
