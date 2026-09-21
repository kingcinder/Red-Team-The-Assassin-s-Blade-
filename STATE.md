# STATE.md — RedTeam Harness completeness manifest

Self-designated state file: what is done, what is next, what is deferred.
Searched (never edited) by the Omega convergence loop; authoritative context
for both of its halves. Last updated: 2026-09-20, after the serpent-circle
quick-start prompt-trees campaign (branch picker + hermetic smoke E2E).

## DONE

**Toolchain correctness (Phase 1 — single-param builder audit)**
- All 61 single-param tools audited; 8 ligolo-class positional-arg bugs fixed
  with dedicated builders + regression tests (amass, trivy, recon-ng, LES,
  gospider, gophish, ophcrack, bloodhound schema; rsmangler repoint).
- Ligolo subprocess ownership moved out of core/mech (`core/ligolo_process.py`);
  8 Pivot REST routes + cockpit panel live; TUN e2e smoke script added.
- Reports: `docs/superpowers/reports/2026-09-20-phase1-*.md`

**Whole-system health (Phase 2 — discovery + remediation + monitoring)**
- Read-only discovery scanner (`scripts/discover_system_bugs.py`) with
  scratch-isolated probes and leak detection; 90 findings remediated to 0
  (37 were symlink false positives — scanner fixed to probe resolved targets).
- 41 stale llama.cpp b9784 test binaries removed from /usr/local/bin (operator
  directive: no reinstall; ollama untouched and verified).
- Scheduled health check (`scripts/health_check.py` + `docs/health_baseline.json`
  + `deploy/systemd/redteam-health.{service,timer}`, daily 09:00, enabled) —
  alert path and healthy path both proven live through systemd.
- System-wide durability audit: zero tool installs depend on volatile /tmp.
- enum4linux-ng durably installed at `~/tools/enum4linux-ng`, both wrappers
  verified end-to-end against a loopback SMB target.
- Reports: `docs/superpowers/reports/2026-09-20-phase2-*.md`,
  `2026-09-20-durability-audit-and-health-check.md`

**Release tooling**
- `scripts/generate_manifest.py` `os.path.which` crash fixed (`shutil.which`);
  first successful run produced `MANIFEST.json` (146 Kali tools tracked);
  5 regression tests added.

**Omega campaign (dashboard GUI usability — no LLM)**
- Baseline certified CONVERGED (both halves GREEN), lens audit executed live
  against a booted dashboard with zero LLM, fixes landed, certification pass
  CONVERGED on `6a6dd42` (campaign 2, cycle 1; ledger in `.omega/state.json`).
- Fixed: `nmap_scan` multi-flag `scan_type` collapsed into one argv token →
  nmap exit 255 → every template-driven workflow aborted at its first gate
  (old regression test asserted the bug; corrected). Socket error handler now
  reads `data.message ?? data.error` (was "Error: undefined"). No-LLM Send
  gives instant LLM-free guidance instead of 4 doomed backend calls + raw
  connection error. LLM banner states what works without an LLM. Confirm
  guards added to Bring Down / Monitor ON / Monitor OFF.
- Live no-LLM E2E: Recon Scan on localhost went ABORTED 1/6 → PARTIAL 5/6
  (6th step `httpx_probe` non-gate, truthfully reports no HTTP service).
- LLM-free quick starts: the five quick-action buttons (Network Recon, Web
  App Test, WiFi Attack, OSINT, AD Attack) now open a **branch picker** — two
  concrete workflows per objective (10 `qs_*.yaml` templates: quick/deep
  recon, surface/SQLi web, capture/crack wifi, domain/URLs OSINT,
  Kerberoast/enum AD) — then the Run Workflow modal with the branch
  preselected + first required variable focused. Verified live in the
  browser, including the WiFi interface auto-fill path. Guarded by
  `tests/test_quick_start_llm_free.py` (7 tests, incl. the no-inline-onclick
  guard: branch names contain double quotes, which used to terminate inline
  handler attributes — found live).
- Automated no-LLM dashboard smoke (`tests/test_dashboard_smoke.py`): drives
  the cockpit via the Flask test client + socket test client — GUI serving,
  LLM status, tool exec, socket error contract, full workflow E2E — against
  the hermetic `Cockpit Smoke Check` template; 13 tests in ~2s (earlier
  draft ran real nmap `--script vuln` and took 4m40s; retargeted).
- Wheelhouse complete: manifest generator joined requirements↔wheels on raw
  spellings (PEP 503 violation) and reported 4 fully-present wheels as
  MISSING (flask-socketio, gevent-websocket, python-dateutil, scikit-learn);
  canonical-name normalization added + regression test. The one true gap
  (argon2-cffi) closed by downloading argon2-cffi + bindings + cffi +
  pycparser wheels. `MANIFEST.json`: 39 wheels, 0 missing,
  `all_wheels_present: true`; proven by a clean venv installing
  requirements.txt with `--no-index --find-links=wheels/` only.

**Verification state at this manifest's date**
- Full suite: **570 passed**; `MANIFEST.json` current (39 wheels, 0 missing);
  `SHA256SUMS` regenerated (163 source files + 39 wheels) + Good signature
  (machine-local, deliberately gitignored per `.gitignore`).
- Whole-system discovery scan: **0 findings** (1 baseline-accepted, see Deferred).
- Recovery anchor for this campaign: `recovery/2026-09-20-pre-quick-start-trees`
  (pushed to origin before any mutation, per serpent-circle doctrine).

## NEXT

1. **Push pending commits to origin** — the serpent-circle campaign commits
   (`98b9b0b`, `d9d96d4`, `7a16811`) once Omega certifies them; blocked on
   explicit operator go-ahead.
2. **Convergence certification** — run the Omega loop on the final state of
   this campaign (both halves GREEN on the same HEAD).

## DEFERRED (logged, intentionally not actioned)

- **Unsloth ROCm/torch mismatch** (`~/.unsloth/studio/unsloth_studio`): unsloth
  import fails at GPU init — torch installed without HIP support on an AMD GPU.
  Dependency metadata is healthy (`pip check` clean); the GPU-stack reinstall is
  a heavyweight, operator-owned decision.
- **oracle-tts venv drift** (`~/Documents/the oracle tts/.venv`): externally
  developed project whose workflow reinstalls `chatterbox-tts 0.1.6` + gradio 6.x.
  Current state repaired (`pip check` clean); its signature is baseline-accepted
  in `docs/health_baseline.json` so the health check alerts only on *new* findings.
- **`RequestsDependencyWarning`** (urllib3/`charset_normalizer` version skew):
  cosmetic import-time warning; does not fail any gate.
- **enum4linux-ng `-oJ` quirk (upstream)**: JSON export is SIGINT-driven and
  appends `.json` to the given path (`-oJ result.json` → `result.json.json`);
  natural-completion runs write no file. Documented, not patched.

## HOW TO RE-VERIFY

```bash
python3 -m pytest -q tests/                 # full suite (570 expected)
python3 scripts/discover_system_bugs.py --repo-root .   # scan (0 new findings)
python3 scripts/health_check.py             # baseline diff, exit-code contract
python3 scripts/generate_manifest.py --verify
python3 scripts/audit_single_param_builders.py          # argv-shape audit
bash ~/.agents/skills/omega-meta-skill/scripts/omega.sh --execute --repo "$PWD"
systemctl --user list-timers redteam-health.timer       # daily 09:00
```
