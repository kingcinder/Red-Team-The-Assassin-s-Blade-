# Just-Works Resilience (v7.1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Mech-Unit degrade gracefully instead of dying — every tool timeout, crash, browser refresh, and process restart recovers; a novice gets a `doctor` first-run report; every wireless capture chain has a fallback path.

**Architecture:** Wiring-and-completion pass over the existing v7.0 Mech-Unit. No new architecture: implement the validated-but-dead `on_timeout` directive in the executor, rebuild `CompiledPlan` from persisted `plan.json` so resume survives process restarts, fix the REST resume no-op, add plan-list/detail endpoints for cockpit reattach, add a probe-based `doctor`, re-bind the scan interface after monitor-mode enable, and add fallback/`use_intent` reroutes to the wireless manifests.

**Tech Stack:** Python 3 stdlib + PyYAML + pytest (unittest-style tests with `sys.path` bootstrap), Flask + SocketIO, vanilla JS (no build step).

## Global Constraints

- Executor calls tools ONLY through `HardenedToolRunner` — no subprocess in `core/mech/` (Decision Register #23).
- Manifests must keep `llm_required: false`; validator enforces it.
- Every state mutation persists atomically via `core.state_store.atomic_write_json`.
- Existing tests must stay green: 441 baseline (131 mech + 310 legacy). New behavior gets new tests; no existing test is edited except to fix a genuine pre-existing bug.
- Directives vocabulary stays pinned to `VALID_DIRECTIVES = {"warn", "abort", "retry_then_fallback"}`.
- New SocketIO events must be added to `core/mech/events.py ALL_EVENTS` (single mapping point) and documented in API.md §16.
- Build on `main` (user-authorized this session); commit after each task.

---

### Task 1: Implement `on_timeout` in the executor (hang-proofing)

**Files:**
- Modify: `core/mech/executor.py` (`_run_step_with_routing`, `_route_failure`)
- Modify: `core/mech/events.py` (add `STEP_TIMEOUT`)
- Test: `tests/mech/test_executor.py`

**Interfaces:**
- Consumes: `HardenedToolRunner` results carrying `killed: True` on timeout-kill (existing hardening contract).
- Produces: `mech_events.STEP_TIMEOUT = "step_timeout"` event (payload: plan_id, step, attempt); `_route_failure(..., timed_out: bool = False)` signature.

- [x] **Step 1: Write the failing tests**

```python
class TestTimeoutRouting(unittest.TestCase):
    """on_timeout must be honored — the directive was validated but never read."""

    def _run(self, on_timeout, on_fail="abort", fallbacks=None):
        calls = {"n": 0}
        class R:
            def execute(self, tool, args, timeout=300, sandbox_output_dir=None):
                calls["n"] += 1
                return {"stdout": "", "stderr": "timed out", "exit_code": -9,
                        "duration": timeout, "blocked": False, "killed": True}
        bus = mech_events.EventBus()
        timeouts = []
        bus.subscribe(mech_events.STEP_TIMEOUT, lambda e: timeouts.append(e))
        plan = CompiledPlan(plan_id="p", intent=_intent("t"), target={},
                            plan_dir=tempfile.mkdtemp(),
                            steps=[CompiledStep(step="s", tool="x", on_timeout=on_timeout,
                                                on_fail=on_fail, fallbacks=fallbacks or [])],
                            artifacts={}, probe_results=[], unresolved=[], compiled_at="")
        st = PlanRunState(plan_id="p", intent_id="t", plan_dir=plan.plan_dir)
        PlanExecutor(R(), bus).run(plan, st)
        return st, timeouts, calls

    def test_timeout_warn_completes_plan(self):
        st, ev, _ = self._run(on_timeout="warn")
        self.assertEqual(st.state, "done")
        self.assertEqual(st.records["s"].state, "failed")
        self.assertTrue(ev)

    def test_timeout_absent_falls_back_to_on_fail(self):
        st, ev, _ = self._run(on_timeout=None, on_fail="abort")
        self.assertEqual(st.state, "failed")
        self.assertEqual(ev, [])

    def test_timeout_retry_then_fallback_runs_fallback(self):
        fb = [{"step": "s_fb", "tool": "fb",
               "args": {}, "extracts": {}}]
        class R:
            def __init__(self): self.n = 0
            def execute(self, tool, args, timeout=300, sandbox_output_dir=None):
                self.n += 1
                if tool == "fb":
                    return {"stdout": "ok", "stderr": "", "exit_code": 0,
                            "duration": 0, "blocked": False, "killed": False}
                return {"stdout": "", "stderr": "", "exit_code": -9,
                        "duration": timeout, "blocked": False, "killed": True}
        r = R()
        plan = CompiledPlan(plan_id="p", intent=_intent("t"), target={},
                            plan_dir=tempfile.mkdtemp(),
                            steps=[CompiledStep(step="s", tool="x", retries=2,
                                                on_timeout="retry_then_fallback",
                                                fallbacks=fb)],
                            artifacts={}, probe_results=[], unresolved=[], compiled_at="")
        st = PlanRunState(plan_id="p", intent_id="t", plan_dir=plan.plan_dir)
        PlanExecutor(r, mech_events.EventBus()).run(plan, st)
        self.assertEqual(st.state, "done")
        self.assertEqual(r.n, 4)  # 3 timed-out attempts + 1 fallback
```

- [x] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/mech/test_executor.py::TestTimeoutRouting -q`
Expected: FAIL (plan aborts / no timeout event).

- [x] **Step 3: Implement**

In `core/mech/events.py`: add `STEP_TIMEOUT = "step_timeout"` constant and include it in `ALL_EVENTS`.

In `core/mech/executor.py` `_run_step_with_routing`: track `last_timed_out = bool(result.get("killed"))` on failure; when `timed_out and step.on_timeout in ("warn", "abort")`, `break` (a hung tool must not burn remaining retries); else honor retries.

In `_route_failure(..., timed_out: bool = False)`: select
`directive = step.on_timeout if (timed_out and step.on_timeout) else (step.on_fail or "abort")`; when the timeout directive is chosen, emit `mech_events.STEP_TIMEOUT` first. Fallbacks still run before the directive (existing order), except when directive is `abort`.

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/mech/test_executor.py -q`
Expected: PASS (all, including pre-existing).

- [x] **Step 5: Commit**

```bash
git add core/mech/executor.py core/mech/events.py tests/mech/test_executor.py
git commit -m "feat(mech): implement on_timeout directive — hung tools honor operator routing"
```

---

### Task 2: Resume across process restarts (rebuild plan from plan.json)

**Files:**
- Modify: `core/mech/compiler.py` (add `CompiledPlan.from_report`)
- Modify: `core/mech/__init__.py` (`MechUnit.resume`, add `list_plans`, `get_plan_report`)
- Modify: `core/mech/cli.py` (add `plans` verb)
- Test: `tests/mech/test_mech_core.py`

**Interfaces:**
- Consumes: `plan.json` written by `CompiledPlan.write_report()` (full `to_dict()`); `PlanRunState.load(plan_dir)`.
- Produces: `CompiledPlan.from_report(plan_dir: str, intent: IntentManifest) -> CompiledPlan`; `MechUnit.list_plans() -> List[dict]` (summary per persisted plan); `MechUnit.get_plan_report(plan_id) -> dict`.

- [x] **Step 1: Write the failing tests**

```python
class TestResumeAcrossRestart(unittest.TestCase):
    def test_resume_rebuilds_plan_from_report(self):
        unit = MechUnit(config={}, manifest_dir=MANIFEST_DIR,
                        sandbox_root=tempfile.mkdtemp())
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        unit.run(plan)  # reaches a terminal state (fake-friendly: probes pass)
        # Simulate a NEW process: fresh MechUnit, same sandbox.
        unit2 = MechUnit(config={}, manifest_dir=MANIFEST_DIR,
                         sandbox_root=unit.sandbox_root)
        st = unit2.resume(plan.plan_id)   # must not raise KeyError
        self.assertIn(st.state, ("done", "failed", "aborted"))

    def test_resume_terminal_state_is_idempotent(self):
        unit = MechUnit(config={}, manifest_dir=MANIFEST_DIR,
                        sandbox_root=tempfile.mkdtemp())
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        st = unit.resume(plan.plan_id)  # never ran: COMPILED → runs
        self.assertIn(st.state, ("done", "failed", "aborted"))

    def test_list_plans_finds_persisted_runs(self):
        unit = MechUnit(config={}, manifest_dir=MANIFEST_DIR,
                        sandbox_root=tempfile.mkdtemp())
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        names = [p["plan_id"] for p in unit.list_plans()]
        self.assertIn(plan.plan_id, names)
```

Note: `wifi_pmkid` steps will fail fast against the fake environment (tools absent → hardening blocks) — the test asserts resume mechanics, not attack success.

- [x] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/mech/test_mech_core.py::TestResumeAcrossRestart -q`
Expected: FAIL (KeyError "plan not loaded in this session").

- [x] **Step 3: Implement**

`CompiledPlan.from_report`:
```python
@classmethod
def from_report(cls, plan_dir: str, intent: IntentManifest) -> "CompiledPlan":
    data = read_json(os.path.join(plan_dir, "plan.json"))
    if not data:
        raise ValueError(f"no plan.json in {plan_dir}")
    steps = [CompiledStep(
        step=s["step"], tool=s["tool"], args=dict(s.get("args", {})),
        when=s.get("when"), gate=s.get("gate"), retries=s.get("retries", 0),
        max_wait=s.get("max_wait"), on_timeout=s.get("on_timeout"),
        on_fail=s.get("on_fail"), fallbacks=list(s.get("fallbacks", [])),
        extracts=dict(s.get("extracts", {})),
        resolution_log=list(s.get("resolution_log", [])))
        for s in data.get("steps", [])]
    return cls(plan_id=data["plan_id"], intent=intent,
               target=dict(data.get("target", {})), plan_dir=plan_dir,
               steps=steps, artifacts=dict(data.get("artifacts", {})),
               probe_results=[], unresolved=[], compiled_at=data.get("compiled_at", ""),
               resolution_log=list(data.get("resolution_log", [])))
```
(import `read_json` from `core.state_store`.)

`MechUnit.resume`: when `plan_id not in self._plans`, load `PlanRunState` from `os.path.join(self.sandbox_root, plan_id)`; if `run_state.state` is terminal (`done/failed/aborted`) return it unchanged (idempotent); else rebuild the plan via `CompiledPlan.from_report(run_state.plan_dir, self.get_intent(run_state.intent_id))`, register it, and run. If the manifest vanished, raise `KeyError` naming the missing intent.

Add `MechUnit.list_plans()`: scan `sandbox_root` dirs containing `state.json`, return `{plan_id, intent_id, state, started_at, ended_at, error}` sorted by plan_id desc. Add `MechUnit.get_plan_report(plan_id)`: `read_json(plan_dir/plan.json)` or raise `KeyError`.

CLI: add `plans` verb → `_print({"plans": unit.list_plans()})`, and document in `MECH_HELP`.

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/mech/test_mech_core.py -q`
Expected: PASS.

- [x] **Step 5: Verify the CLI crash-recovery path end-to-end**

Run: `python3 harness.py --mech compile wifi_pmkid --target bssid=AA:BB:CC:DD:EE:FF` then `python3 harness.py --mech plans` — the plan must appear (separate processes).

- [x] **Step 6: Commit**

```bash
git add core/mech/compiler.py core/mech/__init__.py core/mech/cli.py tests/mech/test_mech_core.py
git commit -m "feat(mech): resume works across process restarts via plan.json rebuild"
```

---

### Task 3: Fix the REST resume no-op + plan-list/detail endpoints

**Files:**
- Modify: `dashboard/blueprints/mech.py` (`/resume` route; add `GET /api/mech/plans`, `GET /api/mech/plan/<plan_id>`)
- Test: `tests/mech/test_mech_routes.py` (new — Flask app test client)

**Interfaces:**
- Consumes: `MechUnit.resume` (Task 2), `MechUnit.list_plans`, `MechUnit.get_plan_report`.
- Produces: `POST /api/mech/plan/<plan_id>/resume` → `{"status": "started"}` (threaded run, like `/run`); `GET /api/mech/plans` → `{"plans": [...]}`; `GET /api/mech/plan/<plan_id>` → plan report dict.

- [x] **Step 1: Write the failing test**

```python
class TestMechResumeRoute(unittest.TestCase):
    def setUp(self):
        from dashboard.blueprints.mech import register
        # Minimal ctx double: Flask app + fake socketio + orchestrator stub.
        ...
    def test_resume_route_starts_run(self):
        resp = self.client.post(f"/api/mech/plan/{plan_id}/resume")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "started")
    def test_resume_unknown_plan_is_404(self):
        resp = self.client.post("/api/mech/plan/nope/resume")
        self.assertEqual(resp.status_code, 404)
```

- [x] **Step 2: Run to verify failure** — route returns `resume_requested` without starting anything today.

- [x] **Step 3: Implement** — the resume route mirrors `/run`: 404 when `plan_id` unknown to the unit (check `unit._plans` OR a persisted `state.json`), then `threading.Thread(target=unit.resume, args=(plan_id,), daemon=True).start()` and return started. Add the two GET routes (404 via `KeyError` → 404 handler).

- [x] **Step 4: Run tests to verify they pass** — `python3 -m pytest tests/mech/test_mech_routes.py -q`.

- [x] **Step 5: Commit**

```bash
git add dashboard/blueprints/mech.py tests/mech/test_mech_routes.py
git commit -m "fix(dashboard): resume route actually resumes; add plans list/detail endpoints"
```

---

### Task 4: Cockpit reattach + UX (refresh-proof console)

**Files:**
- Modify: `dashboard/static/js/mech.js` (plans list, reattach, busy-state controls, inline banner)
- Modify: `dashboard/templates/index.html` (add `mech-plans` container + banner div)

**Interfaces:**
- Consumes: `GET /api/mech/plans`, `GET /api/mech/plan/<plan_id>`, `POST .../resume` (Task 3).
- Produces: `mechLoadPlans()`, `mechReattach(planId)`, `mechBanner(msg, kind)`; run/pause/abort buttons disabled while a plan runs.

- [x] **Step 1: Implement `mechLoadPlans` + `mechReattach`** — render persisted plans with state badges; REATTACH fetches the plan report, sets `mechState.currentPlan`, re-renders the preview, and (if state is `running`) leaves controls disabled; if `paused`, shows an enabled RESUME button calling the fixed resume route. Auto-call `mechLoadPlans()` on boot and on every tab show.
- [x] **Step 2: Busy-state + banner** — `mechSetPlanState` toggles `disabled` on `#mech-run-btn/#mech-pause-btn/#mech-abort-btn`; replace both `alert(...)` calls with a dismissible inline `#mech-banner` div (`role="alert"`).
- [x] **Step 3: Verify in browser** — boot the dashboard, refresh mid-run: the plans list shows the running plan; REATTACH restores the console and live step streaming continues.
- [x] **Step 4: Commit**

```bash
git add dashboard/static/js/mech.js dashboard/templates/index.html
git commit -m "feat(cockpit): refresh-proof reattach, busy-state controls, inline banners"
```

---

### Task 5: `--mech doctor` — first-run capability report (novice onboarding)

**Files:**
- Modify: `core/mech/probes.py` (add `host_readiness()`)
- Modify: `core/mech/__init__.py` (`MechUnit.doctor()`)
- Modify: `core/mech/cli.py` (human-readable `doctor` verb)
- Modify: `dashboard/blueprints/mech.py` (`GET /api/mech/doctor`)
- Test: `tests/mech/test_doctor.py` (new)

**Interfaces:**
- Consumes: `PROBE_REGISTRY`, per-intent `unit.probe(id)`.
- Produces: `probes.host_readiness() -> dict` (`{probes: [ProbeResult...], ok: bool}` — runs the parameterless probes: `wireless_adapter_monitor_capable`, `running_as_root`); `MechUnit.doctor() -> dict` (`{host: ..., intents: [{id, ready, missing, fix}...]}`).

- [x] **Step 1: Write the failing test**

```python
class TestDoctor(unittest.TestCase):
    def test_doctor_reports_every_intent(self):
        unit = MechUnit(config={}, manifest_dir=MANIFEST_DIR, sandbox_root=tempfile.mkdtemp())
        d = unit.doctor()
        self.assertEqual(len(d["intents"]), len(unit.list_intents()))
        self.assertIn("host", d)
        for entry in d["intents"]:
            self.assertIn("ready", entry)
            self.assertIn("missing", entry)
```

- [x] **Step 2: Run to verify failure**, then **Step 3: implement** the three pieces above. CLI prints a human report (host lines + per-intent `READY`/`blocked: <missing> (fix: <fix>)`); blueprint returns JSON.
- [x] **Step 4: Run tests to verify they pass** — `python3 -m pytest tests/mech/test_doctor.py -q`.
- [x] **Step 5: Commit**

```bash
git add core/mech/probes.py core/mech/__init__.py core/mech/cli.py dashboard/blueprints/mech.py tests/mech/test_doctor.py
git commit -m "feat(mech): doctor — first-run host capability report + per-intent readiness"
```

---

### Task 6: Target scan survives interface renaming

**Files:**
- Modify: `core/mech/targets.py` (`scan_wireless`)
- Test: `tests/mech/test_targets.py` (extend)

**Interfaces:**
- Consumes: `probes.list_interfaces()` (monitor-type detection via `/sys/class/net/<if>/type` ∈ {802, 803}).
- Produces: scan response gains `"interface_used"`; `capture_state.set()` receives the monitor vhost when one appears.

- [x] **Step 1: Write the failing test** — stub runner records the interface passed to `airodump_capture`; stub `list_interfaces` to report `wlan0` managed + `wlan0mon` monitor after enable. Assert the scan used `wlan0mon` and returned `interface_used: "wlan0mon"`.
- [x] **Step 2: Run to verify failure** (today the original `wlan0` is used).
- [x] **Step 3: Implement** — after `monitor_mode_enable`, call `list_interfaces()`; pick the first monitor-typed interface; if found and different, switch the sweep to it and persist it via `capture_state.set`; fall back to the original name when none appears. Include `interface_used` in the response.
- [x] **Step 4: Run tests to verify they pass** — `python3 -m pytest tests/mech/test_targets.py -q`.
- [x] **Step 5: Commit**

```bash
git add core/mech/targets.py tests/mech/test_targets.py
git commit -m "fix(mech): target scan rebinds to the monitor vhost after airmon rename"
```

---

### Task 7: Manifest resilience batch — every wireless chain degrades

**Files:**
- Modify: `attacks/wifi_wpa_handshake.yaml`, `attacks/wifi_pmkid.yaml`, `attacks/wifi_evil_twin.yaml`, `attacks/wifi_wps.yaml`, `attacks/wifi_rogue_ap.yaml`
- Test: `tests/mech/test_manifest_resilience.py` (new)

**Interfaces:**
- Consumes: existing `use_intent` reroute + inline-fallback machinery (no executor changes).
- Produces: every deauth/capture step carries at least one fallback (`use_intent` reroute to a sibling intent, or a retry-tolerant inline tool); long captures get `on_timeout: warn`.

- [x] **Step 1: Write the failing test**

```python
class TestManifestResilience(unittest.TestCase):
    LONG_TOOLS = {"airodump_capture", "hcxdumptool_capture", "reaver_run"}

    def test_every_wireless_capture_step_degrades(self):
        from core.mech.intents import load_manifest_dir
        ms = load_manifest_dir(MANIFEST_DIR)
        for m in ms.values():
            if m.category != "wireless":
                continue
            for s in m.plan:
                if s.tool in self.LONG_TOOLS:
                    self.assertTrue(
                        s.fallbacks or s.retries > 0 or s.on_fail == "warn",
                        f"{m.id}.{s.step} has no degrade path")

    def test_wpa_handshake_reroutes_to_pmkid(self):
        from core.mech.intents import load_manifest_dir
        m = load_manifest_dir(MANIFEST_DIR)["wifi_wpa_handshake"]
        reroutes = [fb["use_intent"] for s in m.plan
                    for fb in s.fallbacks if "use_intent" in fb]
        self.assertIn("wifi_pmkid", reroutes)
```

- [x] **Step 2: Run to verify failure**, then **Step 3: edit the five manifests** — add `fallbacks` with `use_intent` reroutes (handshake→pmkid, pmkid→handshake, evil_twin→handshake, wps→handshake) and `on_timeout: warn` on long captures. Only reference intent ids that exist; every `tool:` name must already exist in `core/tool_registry.py`.
- [x] **Step 4: Verify** — `python3 scripts/validate_mech_manifests.py` and `python3 -m pytest tests/mech/ -q` green.
- [x] **Step 5: Commit**

```bash
git add attacks/ tests/mech/test_manifest_resilience.py
git commit -m "feat(attacks): every wireless chain degrades — use_intent reroutes + timeout tolerance"
```

---

### Task 8: Docs + version bump (v7.1.0)

**Files:**
- Modify: `API.md` §16 (resume semantics, `GET /plans`, `GET /plan/<id>`, `GET /doctor`, `step_timeout` event)
- Modify: `README.md` (novice quickstart: 3 commands — doctor, list, run)
- Modify: `DEVELOPMENT.md` (decision register: timeout semantics, resume-from-report; header/timeline → v7.1.0)

- [x] **Step 1: Update the three docs** with the shipped behavior (no placeholders).
- [x] **Step 2: Full verification matrix** — `python3 -m pytest tests/ -q` (expect 441 + new green), `python3 scripts/validate_mech_manifests.py`, `python3 tests/smoke_imports.py`, dashboard boot check.
- [x] **Step 3: Commit**

```bash
git add API.md README.md DEVELOPMENT.md
git commit -m "docs: v7.1.0 — resilience semantics, doctor, reattach API"
```

---

## Self-Review

- **Spec coverage:** user's three demands map to: effortless/novice → Tasks 5, 4; veteran-fast → Task 8 quickstart + existing CLI; JUST WORKS / single-tool-failure degrade → Tasks 1, 2, 3, 6, 7. No uncovered requirement.
- **Placeholder scan:** each task carries concrete test code or an explicit implementable contract; Task 4's JS is specified by behavior contract (no `TBD`).
- **Type consistency:** `mech_events.STEP_TIMEOUT`, `CompiledPlan.from_report(plan_dir, intent)`, `MechUnit.list_plans/get_plan_report/doctor`, `probes.host_readiness()` — used consistently across Tasks 2–5 and docs.
