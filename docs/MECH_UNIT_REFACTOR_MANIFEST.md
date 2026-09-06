# ═══════════════════════════════════════════════════════════════
# RedTeam Harness v7.0 "MECH-UNIT" — Design & Execution Manifest
# AP Vulnerability Capitalization · Deterministic Exploitation ·
# Point-and-Click Operation · Zero LLM Required
# ═══════════════════════════════════════════════════════════════
> **Status**: PROPOSED — not yet approved or implemented
> **Written**: 2026-09-06
> **Baseline**: HEAD `483eb90` on `main`, 44 uncommitted working-tree changes
> **Scope rule**: This manifest is a plan. It changes no code until each
>   phase is executed in order. Every phase ends with gates that must pass.
> **Canon rule**: Per repo policy (AGENTS.md §4), this refactor touches core
>   abstractions. Execution begins only after explicit operator approval of
>   this document.

---

## 0. Executive Summary

**The problem.** Today's harness is *LLM-shaped*: every engagement step in
`core/orchestrator._run_iteration()` begins with an LLM call; phase logic in
`core/autonomous.py` is a loop *around* that LLM call; the tactical engine
(`core/tactics.py`) — which is already a deterministic finding→action
decision engine — is buried underneath it as an afterthought. The result:
an operator who wants to "attack this AP" must understand tools, parameters,
interfaces, channels, capture-file paths, and the kill chain, or trust a
35B model that runs at 3–5 tok/s to guess correctly. The AP workflow
(discovery → target selection → attack-path selection → exploitation →
credential recovery → post-exploitation) is *structurally* deterministic,
yet the harness runs it through a stochastic bottleneck.

**The proposal.** Invert the architecture. Make deterministic code the
pilot and the LLM the optional co-pilot:

1. **VULN-GRAPH — a vulnerability capitalization engine.** A machine-readable
   vulnerability→exploitation-graph (successor to today's 24 tactical rules)
   that turns findings into a scored, ordered, dependency-aware attack plan
   *without any LLM*. The existing vocabulary is already there: `tactics.py`
   rules, `msf_generator.auto_exploit()` (parse→match→validate→save,
   LLM-free today), `findings.py` regex engine, `correlation.py` attack-path
   linking, `kb_data.py` CVE/ATT&CK dataset.
2. **AP ATTACK CHAINS as first-class Mech-Unit packages.** Wireless attack
   sequences (handshake capture, PMKID, WPS, evil twin, rogue AP) become
   *campaign plans* — compiled, validated, pre-parameterized, with
   deterministic step ordering, gates, retries, and fallbacks. The operator
   selects "Attack type: WPA handshake", the Mech-Unit selects the chain,
   fills every parameter from live interface/scan state, and runs it.
3. **Mech-Unit runtime.** `core/mech/`: a plan compiler + plan executor +
   plan state machine that turns "objective + target + attack intent" into
   a validated DAG and runs it with the same list-mode subprocess hardening
   that exists today. The LLM becomes an **optional advisor** — suggested
   parameters when a resolver comes up empty, plan critique — never a
   dependency. `llm_required: false` on every step.
4. **Point-and-click cockpit.** The dashboard becomes a target→intent→run
   console: pick a target from the live scan grid, pick an attack intent
   from a card wall, watch the plan render as a DAG, click Run, watch
   progress + findings + artifacts stream in. No CLI knowledge, no tool
   knowledge, no parameter knowledge required.

**What changes structurally:** the engagement loop stops being
"LLM → parse tool call → execute" and becomes "intent → compiled plan →
deterministic execution with resolvers → findings → capitalization graph →
next plan step". The LLM moves from the hot path to an advisory sidecar.

**What does NOT change:** list-mode subprocess execution, hardening.py
kill cascade, task isolation, audit trail, result cache, parallel executor,
findings/correlation/report engines, the 27 workflow templates' YAML dialect
(they gain fields; nothing existing is removed), the offline-first guarantee,
and the operator's unrestricted-mode ownership of risk.

---

## 1. Terminology (used consistently below)

| Term | Meaning |
|------|---------|
| **Mech-Unit** | The deterministic runtime: plan compiler + executor + state. Works with zero LLM. |
| **Intent** | Operator's high-level selection: *what outcome* + *against what target*. E.g. "crack WPA" + `BSSID AA:BB:..`. |
| **Attack intent card** | Cockpit card representing one intent (one AP attack family, one web attack family, …). |
| **Plan** | Ordered DAG of steps compiled deterministically from intent + live state. |
| **Step** | One tool invocation + gates + retries + fallbacks + `llm_required: false`. |
| **Resolver** | Deterministic function that fills a step parameter from live state (interfaces, scan results, artifacts, wordlists). |
| **Attack intent manifest** | YAML file defining one attack family: preconditions, plan skeleton, parameter resolvers, fallbacks. |
| **VULN-GRAPH** | The vulnerability capitalization engine: findings → scored, dependency-aware exploitation plan. |
| **Capability probe** | Deterministic host check (adapter caps, tool presence, privileges) that gates plans. |

---

## 2. Non-Goals (explicit, to prevent scope drift)

- **Not** building scope enforcement, confirmation gates, or arg rejection
  back into the engine. The unrestricted-mode contract (SECURITY.md) stands;
  the Mech-Unit *surfaces* risk (time-to-impact, noise, legality notes) on
  intent cards, it does not *gate* on it.
- **Not** deleting the LLM or the orchestrator's LLM path. Legacy mode
  remains available; v7 makes it optional, not absent.
- **Not** rewriting the dashboard as a JS framework app. Vanilla JS +
  SocketIO stands (repo decision register #4); cockpit grows new panels.
- **Not** pursuing a chain-format rewrite. The YAML dialect is kept;
  new fields are additive.
- **Not** attempting multi-radio orchestrated attacks (one adapter at a
  time) — that is a v8 candidate.

---

## 3. Target Architecture

### 3.1 New module map (`core/mech/`)

```
core/mech/
├── __init__.py            # MechUnit facade (public API for dashboard/CLI)
├── intents.py             # Loads/validates attack intent manifests (YAML)
├── compiler.py            # Intent + live state → validated plan DAG
├── resolver.py            # Deterministic parameter resolution
├── probes.py              # Capability probes (iface caps, tools, privileges)
├── executor.py            # DAG executor: gates, retries, fallbacks, events
├── state.py               # Plan state machine + atomic persistence + resume
├── events.py              # Typed event bus → SocketIO relay
└── advisors.py            # Optional LLM advisor (disabled when backend down)
```

Supporting modules (existing, extended in place):

| Module | v7 change |
|--------|-----------|
| `core/tactics.py` | Becomes VULN-GRAPH seed: rules gain `requires`, `provides`, `grants`, `phase`, `fallbacks`, `time_to_impact`, `noise` fields. |
| `core/msf_generator.py` | `auto_exploit()` becomes a step provider ("exploit candidate factory"); no behavioral change, adds `provides` metadata. |
| `core/findings.py` | Gains AP-specific extractors (BSSID/ESSID/channel/encryption/handshake-seen/WPS-locked). |
| `core/capture_state.py` | Extended into full radio state: interface, monitor mode, channel lock, band, driver warnings. |
| `core/hardening.py` | Unchanged (list-mode, kill cascade) — executor calls through it. |
| `dashboard/blueprints/*` | New `mech.py` blueprint: intent wall, plan DAG, run/resume/abort APIs. |
| `dashboard/static/js/cockpit.js` | New panels: Intent Wall, Plan DAG view, Run Console. |

### 3.2 The intent model (attack intent manifest)

One YAML file per attack family. This is the heart of "point-and-click with
zero tool knowledge": the manifest encodes what an expert would know.

```yaml
# attacks/wifi_wpa_handshake.yaml
id: wifi_wpa_handshake
name: WPA/WPA2 Handshake Capture + Crack
category: wireless          # wireless | network | web | ad | cloud | host
icon: wifi
operator_label: "Crack a WiFi password (handshake)"
operator_description: >
  Forces nearby clients to reconnect, captures the 4-way handshake,
  then cracks it offline against a wordlist. Best when the target AP
  has active clients. Noisy (visible deauth), needs a good wordlist.
outcome: "PSK (WiFi password) in plaintext, or exhaustion"
grants: [wifi.psk]           # capabilities this intent can produce
time_to_impact: minutes-to-hours
noise: high
risk_notes: >
  Deauthentication is disruptive to other users of the target network.
  Only use on networks you own or are authorized to test.

preconditions:
  - probe: wireless_adapter_monitor_capable   # deterministic check
  - probe: tools_present
    with: [airodump-ng, aireplay-ng, aircrack-ng]
  - probe: wordlist_available
    with: ["/usr/share/wordlists/rockyou.txt"]

plan:
  - step: monitor_up
    tool: monitor_mode_enable
    args: { interface: "{{ resolver.interface.monitor }}" }
  - step: discover
    tool: airodump_capture
    args: { interface: "{{ resolver.interface.monitor }}",
            channel: "{{ resolver.channel.or_hop }}",
            capture_file: "{{ resolver.artifacts.capture_prefix }}" }
    extracts: { bssid: "...", essid: "...", channel: "...", clients: "..." }
  - step: deauth
    tool: aireplay_attack
    args: { interface: "...", bssid: "{{ target.bssid }}", attack: "0" }
    when: "{{ facts.clients_seen }}"
    fallbacks:
      - step: pmkid_attempt
        use_intent: wifi_pmkid      # deterministic intent-to-intent fallback
  - step: capture
    tool: airodump_capture
    gate: { output: "WPA handshake" }   # same gate semantics as workflow engine
    max_wait: 300
    on_timeout: retry(2) then fallback(pmkid_attempt)
  - step: crack
    tool: aircrack_crack
    args: { cap_file: "{{ artifacts.capture }}", wordlist: "{{ resolver.wordlist.adaptive }}" }
    gate: { output: "KEY FOUND" }
    on_fail: escalate(wordlist)

artifacts:
  capture: "{{ plan_dir }}/capture-01.cap"
  handshake_proof: "{{ plan_dir }}/handshake.png"   # auto-captured evidence

llm_required: false           # every step in every manifest carries this
```

Manifest schema (validated at load, fail-fast like `kb_data._validate_dataset()`):

| Field | Required | Notes |
|-------|----------|-------|
| `id`, `name`, `category`, `operator_label`, `operator_description` | ✓ | Cockpit card content |
| `outcome`, `grants`, `time_to_impact`, `noise`, `risk_notes` | ✓ | Card expectations + VULN-GRAPH capitalization values |
| `preconditions[]` | ✓ | Named probes (§3.4) — plans refuse to compile if any fails |
| `plan[]` | ✓ | Steps with `tool`, `args`, optional `when`/`gate`/`on_fail`/`fallbacks` |
| `artifacts` | – | Named output files, exported to the plan sandbox |
| `llm_required` | ✓ (literal `false`) | Structural guarantee — enforced by schema validation |

Initial manifest set (v7.0) — 12 intents:
`wifi_wpa_handshake`, `wifi_pmkid`, `wifi_wps`, `wifi_evil_twin`,
`wifi_rogue_ap`, `wifi_wep`, `smb_credential_relay`, `ad_kerberoast`,
`web_sql_injection`, `web_rce_via_upload`, `host_privesc_linux`,
`host_privesc_windows`. (All twelve already have workflow templates or
tool-chain coverage in the repo today — the manifests *repackage* them.)

### 3.3 The plan lifecycle

```
INTENT selected (cockpit click)
   │
   ▼
[1] PROBE    — capability probes run (adapter caps, tools, wordlists)
   │           fail → card shows "missing: X" with install button
   ▼
[2] COMPILE  — resolver fills every {{...}} from live state; plan DAG validated
   │           unresolvable param → advisor (optional LLM) suggests → else compile error shown
   ▼
[3] PREVIEW  — DAG rendered in cockpit; operator sees steps, gates, fallbacks, ETA
   │           operator may edit any arg in-place before Run
   ▼
[4] EXECUTE  — executor walks DAG honoring when/gate/fallbacks; findings stream live
   │           every artifact lands in plan sandbox (tasks/mech/<plan_id>/)
   ▼
[5] CAPITALIZE — findings feed VULN-GRAPH; newly-granted capabilities
   │             (wifi.psk → creds → lateral) surface as "Next moves" on the run console
   ▼
[6] REPORT   — plan report merges into engagement report (core/report.py writer)
```

Pause / resume / abort at any point (state machine mirrors `autonomous.py`
but persists atomically per-step via `state_store.atomic_write_json`).

### 3.4 Parameter resolution — the "no knowledge required" layer

The compiler never asks the operator for a parameter it can derive:

| Placeholder | Resolver source (deterministic) |
|-------------|--------------------------------|
| `resolver.interface.monitor` | `capture_state` + `/sys/class/net` inventory → pick monitor-capable adapter; auto-enable monitor mode if needed |
| `resolver.channel.or_hop` | Last `airodump` scan hint, else channel-hopping `0` |
| `resolver.artifacts.capture_prefix` | Plan sandbox dir + collision-safe name |
| `resolver.wordlist.adaptive` | Target-dependent ordering: router-default lists by vendor OUI, then rockyou; falls through on exhaustion |
| `resolver.tool.first_installed` | `tool_registry` presence check with fallback chains |
| `target.bssid` / `target.essid` | Operator's cockpit selection (click a row in the AP grid) or discovery-step extraction |
| `facts.clients_seen` | Discovery-step `extracts` → boolean facts consumed by `when:` conditions |

Rules:
1. **Operator input is only ever *selection*, never typing** — targets and
   intents are clicked; free-text entry is an escape hatch, not the flow.
2. Every resolution is logged (`plan.json` records `param ← source`) so the
   operator learns *why* a value was chosen (teaching mode).
3. Only when every deterministic resolver fails does the **optional advisor**
   (LLM, one bounded call, max_tokens ≤ 512) propose a value, tagged
   `llm_suggested: true` in the plan; the operator confirms on the preview
   screen. No backend → the param surfaces as a highlighted blank on preview.

### 3.5 VULN-GRAPH — vulnerability capitalization engine

Successor to `TACTICAL_RULES`. Each rule becomes a **vertex**:

```python
# core/mech/vuln_graph.py (data lives in YAML: attacks/vuln_graph.yaml)
- id: ap.wpa_handshake_captured
  matched_by: {finding_category: wifi_handshake, pattern: "WPA handshake"}
  requires: [radio.monitor_active]
  provides: [wifi.handshake_file]
  grants:  [wifi.psk_candidates]
  capitalization:
    - intent: wifi_wpa_handshake.crack        # scored next move
      confidence: 0.95
      effort: minutes
    - intent: wifi_evil_twin                  # alternative capitalization
      confidence: 0.4
      effort: tens-of-minutes
```

Engine behavior:
- Findings (from `findings.py` + step extracts) are matched against vertices
  → the run console shows a live **"Next moves"** list ordered by
  `confidence × capitalization_value × precondition_satisfaction`.
- One click launches the referenced intent; the Mech-Unit compiles a plan
  with prior facts pre-seeded (`capture_state`, extracted vars, artifacts).
- Cross-domain chaining (AP → creds → lateral movement) emerges from the
  graph instead of from LLM improvisation: `wifi.psk` → `creds.valid` →
  `smb_credential_relay`, exactly the capitalization semantics the repo's
  correlation engine already models (ATT&CK-linked attack paths).
- **AP-specific capitalization** is a first-class subgraph:
  `ap.discovered` → `ap.wps_enabled?` → (`wifi_wps` | `wifi_pmkid` |
  `wifi_wpa_handshake`) → `wifi.psk` → `ap.spoofable` (evil twin with
  recovered PSK) → `client.credential_harvest` (responder against roared
  clients). The graph makes the *order* an expert would try things
  deterministic and explainable.

### 3.6 Cockpit UX — point-and-click contract

Three-screen flow, no keyboard required (typing optional):

1. **TARGETS** — live grid: APs (from airodump scan), hosts (nmap), web
   apps. Each row: signal, encryption, clients, "known from prior sessions"
   (vector memory). Click = select target.
2. **INTENT WALL** — cards filtered to the selected target's category,
   greyed when a precondition probe fails (with the reason + one-click
   install/fix). Each card: label, outcome, time-to-impact, noise meter,
   risk note. Click = select intent.
3. **RUN CONSOLE** — plan DAG preview (editable params, `llm_suggested`
   values flagged) → Run → live step timeline, per-step output drawer,
   findings feed, artifacts gallery, **Next moves** from VULN-GRAPH,
   pause/resume/abort. Engagement-level Mission Control (existing panel)
   keeps working for multi-target campaigns.

Implementation notes: extend `dashboard/blueprints/` with a `mech.py`
blueprint (REST: intents/probe/compile/run/resume/abort/status) + SocketIO
events (`mech_step_started`, `mech_step_complete`, `mech_finding`,
`mech_next_moves`, `mech_plan_state`). `cockpit.js` gains the three panels;
existing panels unchanged. Wireframes are NOT included in v7.0 — the panel
contract is the SocketIO event schema, which is specified here.

### 3.7 LLM demotion — optional advisor contract

- The orchestrator's LLM loop remains for legacy mode (`--legacy` / config
  `mode: legacy`), unchanged for existing users.
- Mech mode is the default entry point (`harness.py` → cockpit) and never
  requires `llm_backend.connected == true`.
- `advisors.py` exposes exactly two advisory calls (both bounded, both
  non-blocking, both skippable):
  1. `suggest_param(param, context)` — compile-time, only when resolvers fail.
  2. `critique_plan(plan)` — preview-time; suggestions render as optional
     diffs the operator can accept or ignore.
- Both wrap `core/injection_defense.sanitize_for_llm()` for anything that
  flows from tool output into a prompt (tool output remains untrusted —
  SECURITY.md boundary preserved even in advisory mode).
- No step may carry `llm_required: true` in v7 manifests; the schema
  validator rejects it. (Advisor *calls* are compile/preview-time, never
  execution-time.)

### 3.8 Repo workflow overhaul — what moves where

| Concern | Today | v7 |
|---------|-------|----|
| Entry point | `harness.py` (CLI flags, dashboard) | Same binary; dashboard boots into TARGETS screen; `--cli --mech` for terminal operator; `--legacy` for v6 loop |
| Engagement driver | `autonomous.py` around `_run_iteration` (LLM) | `mech/executor.py` DAG executor; `autonomous.py` kept for legacy mode, refactored to *use* mech plans when in mech mode |
| Parameter selection | LLM guesses; `_selected_interface` patch-up; `{{placeholders}}` | `resolver.py` deterministic; capture_state authoritative; logged `param ← source` |
| Attack sequencing | LLM decides phases | Intent manifests + plan DAG; VULN-GRAPH suggests continuations |
| Failure handling | `escalate_retry` levels tied to LLM suggestions | Deterministic `fallbacks:` chains in manifests; escalation is a graph edge, not an LLM prompt |
| Findings→actions | 24 rules under an auto-run threshold | VULN-GRAPH vertices with capitalization scoring; surfaced, operator-clicked (auto-run only where manifest declares `autonomous: true`) |
| Human's job | Write prompts / understand tools | Select target, select intent, click Run, review findings |
| LLM's job | Everything | Optional: param suggestion + plan critique (bounded, tagged) |

**Sessions, reports, memory:** unchanged seams. Plans run inside
`task_isolation` sandboxes (`tasks/mech/<plan_id>/`), write findings through
`findings.py`, feed `vector_memory` keyed by target so prior AP sessions
pre-populate the TARGETS grid ("this AP was cracked on 2026-08-30 — PSK in
report"), and merge reports through `report.py`.

---

## 4. Work Breakdown & Execution Plan

> Execution order matters. Every phase is independently valuable and ends
> in green gates. Phases P1–P3 are pure additions (zero behavior change to
> existing paths) — safe to land first. P4+ touches seams.

### P0 — Groundwork & decisions (½ session)
| # | Task | Files | Gate |
|---|------|-------|------|
| P0.1 | Operator approves this manifest (or amends §2 Non-Goals) | this doc | recorded decision |
| P0.2 | Decide manifest set for v7.0 (the 12 listed in §3.2 or a subset) | `attacks/` | list committed |
| P0.3 | Commit or stash strategy for the 44 dirty working-tree files (they predate this work and must not be silently mixed) | git | clean baseline or explicit carry-forward note in every PR |

### P1 — Mech core skeleton (pure addition, no seams touched)
| # | Task | Detail |
|---|------|--------|
| P1.1 | `core/mech/__init__.py` + `intents.py` | Manifest loader + fail-fast schema validation (pattern: `kb_data._validate_dataset()`). Test: malformed manifest → `ValueError` naming the field. |
| P1.2 | `core/mech/probes.py` | Probes: `wireless_adapter_monitor_capable`, `tools_present`, `wordlist_available`, `interface_exists`, `running_as_root`, `report_capability` (structured result: ok / missing / reason / fix). Tests with fakes. |
| P1.3 | `core/mech/resolver.py` | Placeholder grammar `{{ resolver.* }}`, `{{ target.* }}`, `{{ facts.* }}`, `{{ artifacts.* }}`; deterministic resolution order; `param ← source` log. Tests: adapter choice, channel hop fallback, wordlist ordering, collision-safe artifact paths. |
| P1.4 | `core/mech/compiler.py` | Intent + state → plan DAG; validates every placeholder resolved; rejects `llm_required: true`; emits compile report (params, sources, unresolved-with-advice). Tests: wifi_wpa_handshake compiles against a fake state; precondition failure blocks compile with the exact probe reason. |
| P1.5 | `core/mech/state.py` | Plan state machine (compiled→running→paused→done/failed/aborted), atomic per-step persistence via `state_store.atomic_write_json`; resume-from-step. Tests: kill -9 simulation (drop executor mid-run) → resume completes. |
| P1.6 | `core/mech/events.py` | Typed events; mapping table event→SocketIO channel documented in API.md. Test: event ordering stable. |

**Gate P1:** `python3 -m pytest tests/mech/ -q` all green; no existing test
touched; `core/mech` imports cleanly with no LLM backend running.

### P2 — Executor + first manifests (still additive)
| # | Task | Detail |
|---|------|--------|
| P2.1 | `core/mech/executor.py` | DAG walk honoring `when`/`gate`/`on_fail`/`fallbacks`/`max_wait`/`on_timeout`; calls tools **through `tool_registry` + `hardening`** (list-mode, kill cascade) — never its own subprocess path; per-step artifacts into plan sandbox. |
| P2.2 | `tests/mech/test_executor.py` | Fake tool registry: gate pass/fail, fallback triggered, retry-then-fallback, timeout kill, artifact capture, event sequence assertions. |
| P2.3 | Manifests batch 1 (wireless): `wifi_wpa_handshake`, `wifi_pmkid`, `wifi_wps`, `wifi_evil_twin`, `wifi_rogue_ap`, `wifi_wep` | Repackaging the existing wireless quick-chains + `evil_twin_chain.yaml` semantics; every param resolvable or explicitly operator-selected (bssid/essid). |
| P2.4 | `attacks/vuln_graph.yaml` — AP subgraph | Vertices for the §3.5 AP capitalization chain; `core/mech/vuln_graph.py` loader + scorer (deterministic ordering, no LLM). |
| P2.5 | MechUnit facade (`core/mech/__init__.py`) | Public API: `list_intents()`, `probe(intent_id)`, `compile(...)`, `run(plan)`, `resume(plan_id)`, `abort(plan_id)`, `status(plan_id)`, `next_moves(plan_id)`. |
| P2.6 | `harness.py` mech mode | `--mech` CLI flag: `list`, `probe`, `run <intent> --target <...>`, `resume`, `status`; dashboard untouched this phase. |

**Gate P2:** full manifest set validates; executor tests green; an AP
chain compiles end-to-end **on a machine with no LLM backend running**;
`harness.py --mech list` shows all intents with probe status.

### P3 — VULN-GRAPH full build-out
| # | Task | Detail |
|---|------|--------|
| P3.1 | Upgrade `TACTICAL_RULES` fields | Add `requires`/`provides`/`grants`/`phase`/`fallbacks`/`time_to_impact`/`noise` to existing 24 rules; keep old keys so current tests pass unchanged. |
| P3.2 | `vuln_graph.py` scoring | `confidence × capitalization_value × precondition_satisfaction` ordering; cycle detection; explanation strings ("why this next move") for the console. |
| P3.3 | Manifests batch 2 (network/host/web): `smb_credential_relay`, `ad_kerberoast`, `web_sql_injection`, `web_rce_via_upload`, `host_privesc_linux`, `host_privesc_windows` | Compiled from existing workflow templates (sql_injection_chain, linux_privesc_chain, ntlm_relay_chain, kerberoasting_chain …). |
| P3.4 | Cross-domain edges | `wifi.psk → creds.valid → smb_credential_relay`; `creds.valid → ad_kerberoast`; documented in `attacks/vuln_graph.yaml` with ATT&CK references from `kb_data.py`. |
| P3.5 | Tests | Scoring order, cycle detection, explanation generation, cross-domain seeding of facts into compiled plans. |

**Gate P3:** `tests/mech/` + existing suites green; Next-moves for a seeded
wifi.psk finding deterministically produce the documented chain; zero
behavior change to legacy mode (run full existing test suite).

### P4 — Cockpit integration (the point-and-click layer)
| # | Task | Detail |
|---|------|--------|
| P4.1 | `dashboard/blueprints/mech.py` | REST: `GET /api/mech/intents`, `GET /api/mech/intents/<id>/probe`, `POST /api/mech/plan/compile`, `POST /api/mech/plan/<id>/run|pause|resume|abort`, `GET /api/mech/plan/<id>/status`, `GET /api/mech/plan/<id>/next-moves`. |
| P4.2 | SocketIO relay | `mech/*` events → cockpit; event schema documented in API.md §16-style table. |
| P4.3 | TARGETS panel | Live AP/host grid fed by probe scans (airodump/nmap through the executor); vector-memory "seen before" badges. |
| P4.4 | INTENT WALL panel | Card wall with probe-greyed cards + reason + one-click fix (reuses `tool_installer`). |
| P4.5 | RUN CONSOLE panel | DAG preview (editable params, `llm_suggested` flags), run/pause/resume/abort, step timeline, output drawers, findings feed, artifacts gallery, Next moves. |
| P4.6 | cockpit.js / index.html / cockpit.css | New panels in existing vanilla-JS style; no build step; no CDN. |

**Gate P4:** a fresh operator with no tool knowledge completes
target→intent→run→report for `wifi_wpa_handshake` using only the mouse;
`API.md` updated with every new route/event.

### P5 — LLM demotion & legacy parity
| # | Task | Detail |
|---|------|--------|
| P5.1 | `core/mech/advisors.py` | The two bounded advisory calls (§3.7); sanitize via `injection_defense`; feature-flagged off by default; when backend absent, param surfaces as highlighted blank on preview. |
| P5.2 | Advisor tests | Bound → ≤512 tokens enforced; sanitize path; backend-down degradation. |
| P5.3 | `config.yaml` | `mech:` section (default_mode: mech, advisor: enabled/disabled, manifest_dir, sandbox_root); legacy keys untouched. |
| P5.4 | `autonomous.py` legacy/mech bridge | Autonomous campaign may *drive* mech plans instead of LLM iterations when `mode: mech`; `MIN_FINDINGS_PER_PHASE`-style budgets map onto plan budgets. Legacy path byte-for-byte unchanged when `mode: legacy`. |
| P5.5 | Docs | README architecture table gains v7 section; DEVELOPMENT.md gains "PART 7 — v7.0 Mech-Unit" decision register entries; SECURITY.md threat model row for the advisor boundary. |

**Gate P5:** whole existing test suite green with `mode: mech` default
(no legacy regression); advisor absent → full AP chain still completes;
docs updated.

### P6 — Hardening, audit, release
| # | Task | Detail |
|---|------|--------|
| P6.1 | Audit trail parity | Every mech step logs args/exit/duration/target like `hardening` does today; plan.json is append-only evidence. |
| P6.2 | SECURITY.md updates | Threat model rows: manifest files are code (validate + review), advisor boundary, cockpit localhost-bind unchanged. |
| P6.3 | Air-gap check | `install.sh`/`install_kali_tools.sh` unchanged; verify manifests ship with repo (no downloads); `wheels/` story unchanged. |
| P6.4 | Full verification matrix run | All suites, compile check, AST dead-code scan, manifest validation script (`scripts/validate_mech_manifests.py`). |
| P6.5 | Release | Version bump, tag `v7.0.0`, SHA256SUMS per RELEASING.md. |

---

## 5. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|-----------|
| Manifest sprawl — 12 intents × fallback trees become unmaintainable | Medium | High | Schema validation fail-fast; one intent per file; the 12 must each map to an *existing* tested template/chain — no new attack logic invented in YAML. |
| Executor drift from hardening guarantees (someone adds a raw subprocess call) | Low | Critical | Executor *only* calls through `tool_registry`; tests assert no `subprocess` import in `core/mech/`. |
| Plan compile surprises (param resolved to something unexpected) | Medium | Medium | `param ← source` log + preview screen shows every resolved value before Run. |
| Cockpit complexity creep | Medium | Medium | Three-screen contract is fixed; SocketIO event schema is the spec; panels reuse existing CSS system. |
| Advisor (LLM) suggested a bad param | Medium | Low-Med | Tagged `llm_suggested`; preview confirmation; resolver-first design means advisor is the exception path. |
| Legacy regression | Low | High | P1–P3 additive; P5.4 bridge behind `mode:` flag; full existing suite in every gate. |
| Scope creep into v8 (multi-radio, mesh) | High | Medium | §2 Non-Goals; new ideas go to `docs/BACKLOG.md`, not this plan. |
| 44 dirty working-tree files mixing with refactor commits | High | Medium | P0.3: baseline decision before any code moves; refactor commits reference only their own files. |

---

## 6. Estimation

| Phase | Effort | Can parallelize? |
|-------|--------|------------------|
| P0 | ½ session | – |
| P1 | 2–3 sessions | P1.2/P1.3 parallel |
| P2 | 2–3 sessions | Executor tests + manifests parallel |
| P3 | 1–2 sessions | Manifests batch 2 parallel |
| P4 | 2–4 sessions | Backend blueprint before frontend panels |
| P5 | 1–2 sessions | – |
| P6 | 1 session | – |
| **Total** | **~10–15 focused sessions** | |

---

## 7. Decision Register Additions (to append to DEVELOPMENT.md on P5.5)

| # | Decision | Rationale |
|---|----------|-----------|
| 19 | Determinism-first: plans compiled from manifests, LLM advisory only | AP/kill-chain work is structurally deterministic; stochasticity belongs in research, not parameter selection. |
| 20 | Intent manifests as the operator interface | Encodes expert knowledge once; operator needs outcome-expectation knowledge only. |
| 21 | Resolver layer over prompt engineering | Deterministic parameter selection is auditable, offline-safe, and testable. |
| 22 | VULN-GRAPH replaces the auto-run threshold model | Capitalization becomes a visible, scored choice instead of silent auto-execution; matches unrestricted-mode ownership while restoring operator visibility. |
| 23 | Executor must not own subprocess logic | Single hardened execution path (tool_registry + hardening) — no second unsafe path. |
| 24 | Legacy mode preserved behind `mode:` flag | Existing LLM-piloted behavior stays available; v7 is additive supremacy, not removal. |

---

## 8. Open Questions (need operator input before or during P1)

1. **Default mode**: should the cockpit default to mech mode with legacy
   behind a toggle (recommended), or keep legacy default until P4 lands?
2. **Manifest location**: `attacks/` (new top-level, mirrors `workflows/`) —
   confirm, or prefer `workflows/attacks/`?
3. **AP automation depth for v7.0**: does "Next moves" auto-run the next
   intent when confidence ≥ threshold (like today's auto-run), or always
   require the click? (Manifest `autonomous: true` flag can mix both.)
4. **Language**: keep the "Assassin's Blade" naming for v7 or adopt
   "Mech-Unit" as the codename throughout?
