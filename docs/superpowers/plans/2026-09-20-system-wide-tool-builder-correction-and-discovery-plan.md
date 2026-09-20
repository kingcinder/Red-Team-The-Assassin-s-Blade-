# System-Wide Tool Builder Correction and Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the audited single-parameter command failures and known external wrappers, verify all affected execution paths safely, then freeze changes and produce a whole-system discovery report with no Phase 2 fixes.

**Architecture:** Keep command construction centralized in `core/command_builder.py`, with explicit builders for tools whose binaries require flags or subcommands. Make the audit faithful to the harness by executing the exact argv returned by `ToolRegistry._build_command`, then use a separate read-only scanner for repository and host-wide discovery after Phase 1 is green.

**Tech Stack:** Python 3.10+, pytest-compatible standalone test scripts, subprocess with `shell=False`, Flask/SocketIO boot checks, Node syntax checks, JSON/Markdown reports, local PATH/venv/ELF inspection.

## Global Constraints

- Preserve the four pre-existing untracked audit files and do not overwrite unrelated user changes.
- Phase 1 may fix only the known builder, routing, audit, and named wrapper defects.
- Phase 2 is discovery-only; do not edit any finding discovered during Phase 2.
- Never execute external-network scans or destructive/offensive host operations as verification.
- Use exact argv assertions and bounded local/help/version probes for unsafe tools.
- Request explicit approval for each consequential elevated command; root availability is not blanket authorization.
- Use the repository’s existing standalone test conventions and run all existing gates after code changes.

---

### Task 1: Establish a clean Phase 1 baseline

**Files:**
- Read: `git status`, `README.md`, `DEVELOPMENT.md`, `CONTRIBUTING.md`, `docs/single_param_audit.md`, `docs/single_param_audit.json`
- Read: `core/command_builder.py`, `core/tool_registry.py`, `core/tool_interceptor.py`, `core/hardening.py`
- Read: `tests/test_tool_registry_commands.py`, related workflow/Mech tests
- Create: `docs/superpowers/reports/2026-09-20-phase1-baseline.md`

**Interfaces:**
- Consumes: current registry, existing audit artifacts, existing test commands.
- Produces: a baseline record of current counts, failures, changed paths, and exact verification commands.

- [ ] **Step 1: Capture repository state without modifying files**

Run:

```bash
git status --short --branch
git log -8 --oneline
```

Expected: confirm `main` and record the four pre-existing untracked audit files; do not stage, discard, or overwrite them.

- [ ] **Step 2: Run focused baseline tests**

Run:

```bash
python3 tests/test_tool_registry_commands.py
python3 tests/test_tool_registry.py
python3 tests/test_hardening_integration.py
python3 tests/mech/test_executor.py
```

Expected: record pass/fail output and preserve any existing failures as baseline evidence.

- [ ] **Step 3: Inspect the current exact commands for the eight named tools**

Run:

```bash
python3 - <<'PY'
from core.tool_registry import ToolRegistry
samples = {
    'amass_enum': {'domain': 'localhost'},
    'trivy_scan': {'image': 'localhost/nonexistent:image'},
    'recon_ng_gather': {'workspace': 'smoketest'},
    'linux_exploit_suggester': {'kernel': '5.15.0'},
    'gospider_crawl': {'url': 'http://127.0.0.1:9/'},
    'gophish_setup': {'config': '/dev/null'},
    'ophcrack_crack': {'hash_file': '/dev/null'},
    'bloodhound_analyze': {'neo4j_url': 'bolt://127.0.0.1:7687'},
}
reg = ToolRegistry({'output_dir': '/tmp/phase1-baseline'})
for name, args in samples.items():
    tool = reg.get_tool(name)
    print(name, reg._build_command(tool, args))
PY
```

Expected: capture the current incorrect positional forms as a before snapshot.

- [ ] **Step 4: Write the baseline report**

Record the command outputs, current audit disagreement (`amass_enum`, `gophish_setup`, `gospider_crawl`, and other evidence mismatches), and the exact starting working-tree state in `docs/superpowers/reports/2026-09-20-phase1-baseline.md`.

---

### Task 2: Add regression tests for all known builder defects

**Files:**
- Modify: `tests/test_tool_registry_commands.py`
- Test: `core/command_builder.py`
- Test: `core/tool_registry.py`

**Interfaces:**
- Consumes: `_build_command(output_dir, tool, args)` and `ToolRegistry` definitions.
- Produces: exact argv regression tests for all eight affected tools and meta-tool safety tests.

- [ ] **Step 1: Add failing exact-argv tests**

Append tests with this shape:

```python
def test_amass_enum_uses_enum_subcommand_and_domain_flag():
    cmd = _build_command('/tmp/out', tool('amass_enum', 'amass', {
        'domain': {'type': 'string'},
    }), {'domain': 'localhost'})
    assert cmd == ['amass', 'enum', '-d', 'localhost']


def test_trivy_scan_uses_image_subcommand():
    cmd = _build_command('/tmp/out', tool('trivy_scan', 'trivy', {
        'image': {'type': 'string'},
    }), {'image': 'localhost/nonexistent:image'})
    assert cmd == ['trivy', 'image', 'localhost/nonexistent:image']


def test_recon_ng_gather_uses_workspace_flag():
    cmd = _build_command('/tmp/out', tool('recon_ng_gather', 'recon-ng', {
        'workspace': {'type': 'string'},
    }), {'workspace': 'smoketest'})
    assert cmd == ['recon-ng', '-w', 'smoketest']


def test_linux_exploit_suggester_uses_kernel_flag():
    cmd = _build_command('/tmp/out', tool('linux_exploit_suggester', 'linux-exploit-suggester', {
        'kernel': {'type': 'string'},
    }), {'kernel': '5.15.0'})
    assert cmd == ['linux-exploit-suggester', '-k', '5.15.0']


def test_gospider_crawl_uses_url_flag():
    cmd = _build_command('/tmp/out', tool('gospider_crawl', 'gospider', {
        'url': {'type': 'string'},
    }), {'url': 'http://127.0.0.1:9/'})
    assert cmd == ['gospider', '-u', 'http://127.0.0.1:9/']


def test_gophish_setup_uses_config_flag():
    cmd = _build_command('/tmp/out', tool('gophish_setup', 'gophish', {
        'config': {'type': 'string'},
    }), {'config': '/dev/null'})
    assert cmd == ['gophish', '--config', '/dev/null']


def test_ophcrack_crack_uses_list_flag():
    cmd = _build_command('/tmp/out', tool('ophcrack_crack', 'ophcrack', {
        'hash_file': {'type': 'string'},
    }), {'hash_file': '/dev/null'})
    assert cmd == ['ophcrack', '-l', '/dev/null']
```

For BloodHound, first assert the selected contract. The preferred contract is a collector command with explicit credentials/domain/collection parameters; if backward compatibility is retained, assert that a lone `neo4j_url` call returns a deterministic build error rather than a misleading positional command.

For meta-tools, add a registry test that obtains `install_tool`, `install_all_missing`, and `check_tool_status` and asserts their execution is intercepted or explicitly rejected before `_build_command` can produce an empty executable.

- [ ] **Step 2: Run the focused tests to confirm failure**

Run:

```bash
python3 tests/test_tool_registry_commands.py
python3 tests/test_tool_registry.py
```

Expected: the new tests fail against the current generic positional builder.

---

### Task 3: Implement the explicit builders and BloodHound contract

**Files:**
- Modify: `core/command_builder.py`
- Modify: `core/tool_registry.py` only if BloodHound parameter metadata must change

**Interfaces:**
- Consumes: the exact-argv tests from Task 2.
- Produces: explicit builders dispatched before the generic single-parameter fallback.

- [ ] **Step 1: Add explicit dispatch entries**

Insert dispatch before positional fallback:

```python
if name == "amass_enum": return _build_amass(output_dir, args, binary)
if name == "trivy_scan": return _build_trivy(output_dir, args, binary)
if name == "recon_ng_gather": return _build_recon_ng(output_dir, args, binary)
if name == "linux_exploit_suggester": return _build_les(output_dir, args, binary)
if name == "gospider_crawl": return _build_gospider(output_dir, args, binary)
if name == "gophish_setup": return _build_gophish(output_dir, args, binary)
if name == "ophcrack_crack": return _build_ophcrack(output_dir, args, binary)
if name == "bloodhound_analyze": return _build_bloodhound(output_dir, args, binary)
```

- [ ] **Step 2: Add minimal pure builders**

Implement these exact forms:

```python
def _build_amass(output_dir, args, binary):
    return [binary, "enum", "-d", str(args.get("domain", ""))]


def _build_trivy(output_dir, args, binary):
    return [binary, "image", str(args.get("image", ""))]


def _build_recon_ng(output_dir, args, binary):
    return [binary, "-w", str(args.get("workspace", ""))]


def _build_les(output_dir, args, binary):
    return [binary, "-k", str(args.get("kernel", ""))]


def _build_gospider(output_dir, args, binary):
    return [binary, "-u", str(args.get("url", ""))]


def _build_gophish(output_dir, args, binary):
    return [binary, "--config", str(args.get("config", ""))]


def _build_ophcrack(output_dir, args, binary):
    return [binary, "-l", str(args.get("hash_file", ""))]
```

- [ ] **Step 3: Implement BloodHound without a misleading positional URL**

Use an explicit collector schema. The preferred registered parameters are `domain`, `username`, `password`, and optional `collection_method`, `nameserver`, `dc`, `zip`, and `output_dir`; emit:

```python
cmd = [binary, "-d", domain, "-u", username, "-p", password,
       "-c", collection_method]
```

Add optional flags only when present. If the legacy call supplies only `neo4j_url`, raise `ValueError("bloodhound_analyze requires collector credentials and domain; neo4j_url is not a collector argument")` so the caller receives a clear schema error. Update `ToolDefinition` metadata and LLM schema only if required to express this contract.

- [ ] **Step 4: Run focused tests**

Run:

```bash
python3 tests/test_tool_registry_commands.py
python3 tests/test_tool_registry.py
```

Expected: all builder regression tests pass.

---

### Task 4: Close meta-tool routing and audit exact-argv defects

**Files:**
- Modify: `core/tool_interceptor.py` only if dispatch coverage is incomplete
- Modify: `core/orchestrator.py` only if it bypasses `INTERCEPTED_TOOLS`
- Modify: `scripts/audit_single_param_builders.py`
- Modify: `docs/single_param_audit.md` and `docs/single_param_audit.json` only after the corrected audit runs
- Test: `tests/test_tool_registry.py`, `tests/test_hardening_integration.py`, focused new audit tests if needed

**Interfaces:**
- Consumes: corrected builders and existing `ToolInterceptor.dispatch`.
- Produces: no empty-binary execution path and a faithful audit report.

- [ ] **Step 1: Add failing interceptor-path assertions**

Use a fake installer and fake registry to assert:

```python
assert "install_tool" in INTERCEPTED_TOOLS
assert "install_all_missing" in INTERCEPTED_TOOLS
assert "check_tool_status" in INTERCEPTED_TOOLS
```

Verify `ToolInterceptor.dispatch("check_tool_status", {"tool_name": "nmap"})` returns a normalized result without invoking `_build_command`.

- [ ] **Step 2: Correct audit execution to use the full built argv**

Replace the probe call:

```python
rc, out, err = run([real, sample], TIMEOUT)
```

with execution of the exact built command:

```python
rc, out, err = run([str(part) for part in argv], TIMEOUT)
```

For commands beginning with `sudo`, do not prompt or mutate the host. Mark them `SKIP-PRIVILEGED` with the exact argv and reason. For wrappers, retain the wrapper path and capture its stderr separately in the evidence.

- [ ] **Step 3: Add explicit verdict classes**

Use these stable verdicts: `OK`, `BROKEN-ARGUMENT-SHAPE`, `BROKEN-WRAPPER`, `MISSING-BINARY`, `HANG-REVIEW`, `SKIP-DESTRUCTIVE`, `SKIP-PRIVILEGED`, `INTERNAL-INTERCEPTED`, and `REVIEW-AMBIGUOUS`.

- [ ] **Step 4: Regenerate the audit artifacts**

Run:

```bash
python3 scripts/audit_single_param_builders.py
```

Expected: JSON and Markdown agree, exact argv is recorded, and the eight corrected builders no longer appear as argument-shape failures. Do not interpret runtime/network failures as builder failures.

- [ ] **Step 5: Run interceptor and hardening tests**

Run:

```bash
python3 tests/test_tool_registry.py
python3 tests/test_hardening.py
python3 tests/test_hardening_integration.py
```

Expected: PASS, or record any unrelated baseline failure without hiding it.

---

### Task 5: Repair the two named external wrappers in place

**Files:**
- External modify: `/home/cody/.local/bin/rsmangler`
- External modify: `/home/cody/.local/bin/enum4linux`
- Read: `/home/cody/tools/rsmangler/rsmangler.rb`, `/home/cody/redteam-tools/DEFICIENCY-LEDGER.md`, external manifests

**Interfaces:**
- Consumes: verified external paths and wrapper contracts.
- Produces: working wrapper paths without relocating installed sources.

- [ ] **Step 1: Verify prerequisites read-only**

Run:

```bash
test -x /home/cody/tools/rsmangler/rsmangler.rb
ruby --version
command -v enum4linux-ng || true
find /home/cody/.local/opt /home/cody/redteam-tools -maxdepth 4 -type f -name 'enum4linux-ng.py' -o -name 'enum4linux-ng'
```

Expected: identify the valid rsmangler source and the valid enum4linux-ng entry point, or record the latter as unavailable.

- [ ] **Step 2: Request approval for the exact external edits if needed**

If direct file editing is unavailable through the workspace tools, request approval for a command containing the complete content and target paths. Do not use a blanket root shell. The rsmangler wrapper should be equivalent to:

```bash
#!/bin/sh
exec ruby /home/cody/tools/rsmangler/rsmangler.rb "$@"
```

The enum4linux wrapper should use the verified durable executable/script path and its interpreter, preserving `"$@"`.

- [ ] **Step 3: Probe wrappers safely**

Run:

```bash
printf 'a\n' >/tmp/rsmangler-phase1-input.txt
/home/cody/.local/bin/rsmangler --file /tmp/rsmangler-phase1-input.txt --perms --output /tmp/rsmangler-phase1-output.txt
/home/cody/.local/bin/rsmangler --help
/home/cody/.local/bin/enum4linux --help
```

Expected: rsmangler exits successfully and creates bounded output; enum4linux reaches its own help/usage path or reports a verified dependency issue rather than a missing `/tmp` directory.

- [ ] **Step 4: Update external ledger/inventory evidence only for the fixed named defects**

Mark D-015 and D-016 resolved only if the probes pass. Do not alter unrelated ledger entries.

---

### Task 6: Verify all Phase 1 paths before discovery freeze

**Files:**
- Read/verify: all changed Phase 1 files
- Create: `docs/superpowers/reports/2026-09-20-phase1-verification.md`

**Interfaces:**
- Consumes: corrected code, wrappers, audit artifacts, and tests.
- Produces: a complete Phase 1 verification record and a go/no-go decision for Phase 2.

- [ ] **Step 1: Run all standalone Python tests**

Run:

```bash
set -o pipefail
for t in tests/test_*.py tests/mech/test_*.py; do python3 "$t" || exit 1; done
```

Expected: every test passes. If a test fails, stop Phase 2, fix only Phase 1 regressions, and rerun the complete command.

- [ ] **Step 2: Run compilation/import/JS gates**

Run:

```bash
python3 -m compileall -q core dashboard tools tests scripts harness.py
python3 tests/smoke_imports.py
node --check dashboard/static/js/cockpit.js
node --check dashboard/static/js/mech.js
python3 scripts/validate_mech_manifests.py
```

Expected: all gates pass.

- [ ] **Step 3: Boot the local app without starting a public listener**

Run:

```bash
python3 - <<'PY'
from dashboard.server import create_app
app = create_app()
print('APP_BOOT_OK', bool(app))
PY
```

Expected: `APP_BOOT_OK True` without contacting external services.

- [ ] **Step 4: Run corrected audit and safe affected-tool probes**

Run the corrected audit and bounded help/version probes for all affected installed binaries. Use loopback-only fixtures where a tool accepts a target, and skip destructive/privileged commands with evidence.

- [ ] **Step 5: Write the Phase 1 report and stop if any gate is red**

Record exact commands, pass/fail results, repaired external paths, residual intentional limitations, and any unresolved Phase 1 defect in `docs/superpowers/reports/2026-09-20-phase1-verification.md`.

---

### Task 7: Build the frozen whole-system discovery scanner

**Files:**
- Create: `scripts/discover_system_bugs.py`
- Create: `docs/system_discovery_report.json`
- Create: `docs/system_discovery_report.md`
- Test: `tests/test_system_discovery.py`

**Interfaces:**
- Consumes: registry metadata, external tool inventory, filesystem paths, safe subprocess probes.
- Produces: deterministic issue records with `id`, `category`, `severity`, `confidence`, `what`, `when`, `where`, `why`, `how`, `evidence`, `status`, and `recommended_correction`.

- [ ] **Step 1: Add scanner unit tests before implementation**

Test pure helpers for:

```python
def test_classifies_dangling_symlink(tmp_path):
    link = tmp_path / 'dead'
    link.symlink_to(tmp_path / 'missing')
    finding = inspect_path(link)
    assert finding['category'] == 'dangling-symlink'


def test_classifies_missing_shebang_interpreter(tmp_path):
    script = tmp_path / 'bad-script'
    script.write_text('#!/missing/interpreter\n')
    script.chmod(0o755)
    finding = inspect_path(script)
    assert finding['category'] == 'missing-interpreter'


def test_scanner_does_not_modify_files(tmp_path):
    before = (tmp_path / 'x').write_text('x')
    scan_paths([tmp_path])
    assert (tmp_path / 'x').read_text() == 'x'
```

- [ ] **Step 2: Run tests to confirm they fail**

Run:

```bash
python3 tests/test_system_discovery.py
```

Expected: FAIL because the scanner module does not yet exist.

- [ ] **Step 3: Implement read-only scanner components**

Implement functions with these signatures:

```python
def inspect_path(path: pathlib.Path) -> dict | None: ...
def scan_registry(repo_root: pathlib.Path) -> list[dict]: ...
def scan_wrappers(paths: list[pathlib.Path]) -> list[dict]: ...
def scan_python_environments(home: pathlib.Path) -> list[dict]: ...
def scan_elf_dependencies(paths: list[pathlib.Path]) -> list[dict]: ...
def scan_repository(repo_root: pathlib.Path) -> list[dict]: ...
def run_safe_probe(argv: list[str], timeout: int = 6) -> dict: ...
def discover(repo_root: pathlib.Path, home: pathlib.Path) -> dict: ...
def render_markdown(report: dict) -> str: ...
```

The scanner may read files, inspect metadata, run `--help`/`--version`, import modules, run local app boot checks, and call `ldd`; it must not write to inspected paths, install packages, alter services, alter interfaces, or contact external targets.

- [ ] **Step 4: Cover all required discovery surfaces**

Include registry/builders/interceptors; all repository source and tests; `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/snap/bin`, `~/.local/bin`, `~/go/bin`, `/home/cody/redteam-tools/bin`, and relevant `/home/cody/tools`; symlinks/shebangs/permissions; Python environments and dependency checks; ELF dependencies; manifests/logs/ledger consistency; local app boot; and safe tool probes.

- [ ] **Step 5: Run scanner unit tests**

Run:

```bash
python3 tests/test_system_discovery.py
```

Expected: PASS and no filesystem changes outside generated report artifacts.

---

### Task 8: Execute the discovery-only scan and publish the final report

**Files:**
- Modify generated: `docs/system_discovery_report.json`
- Modify generated: `docs/system_discovery_report.md`
- Create: `docs/superpowers/reports/2026-09-20-final-system-debugging-report.md`

**Interfaces:**
- Consumes: frozen Phase 1 state and discovery scanner.
- Produces: complete discovery findings with no fixes applied after the freeze.

- [ ] **Step 1: Confirm the Phase 1 freeze**

Run:

```bash
git status --short
sha256sum docs/superpowers/reports/2026-09-20-phase1-verification.md
```

Record the freeze point. From this step until the final report, do not edit code or external tool files.

- [ ] **Step 2: Run the whole-system discovery scanner**

Run:

```bash
python3 scripts/discover_system_bugs.py --repo-root . --home "$HOME" --output-json docs/system_discovery_report.json --output-md docs/system_discovery_report.md
```

Expected: complete scan with bounded probes and no repair actions.

- [ ] **Step 3: Verify discovery non-mutation**

Run:

```bash
git diff -- core scripts tests dashboard tools harness.py
find /home/cody/.local/bin /home/cody/tools /home/cody/redteam-tools -type f -newermt '2026-09-20 00:00:00' -print 2>/dev/null
```

Expected: no Phase 2 source or external wrapper edits; only generated report artifacts may change.

- [ ] **Step 4: Review findings for completeness and false positives**

Ensure each finding contains what/when/where/why/how, reproduction evidence, affected paths, severity/confidence, and a recommended correction. Do not fix any finding during this review.

- [ ] **Step 5: Write the final report**

Separate Phase 1 fixed findings, residual known limitations, inconclusive probes, and Phase 2 newly discovered findings. State plainly that Phase 2 findings remain unfixed by instruction.

- [ ] **Step 6: Run report schema validation only**

Run:

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = json.loads(Path('docs/system_discovery_report.json').read_text())
assert isinstance(p.get('findings'), list)
required = {'id','category','severity','confidence','what','when','where','why','how','evidence','status','recommended_correction'}
for finding in p['findings']:
    missing = required - finding.keys()
    assert not missing, (finding.get('id'), missing)
print('DISCOVERY_REPORT_SCHEMA_OK', len(p['findings']))
PY
```

Expected: schema validation passes; no source or external-system modifications occur.
