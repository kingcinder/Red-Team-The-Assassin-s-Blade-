# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — Complete Development Timeline & Architecture
# The Road to v4.0 "Assassin's Blade" — Every Feature, Every Decision
# ═══════════════════════════════════════════════════════════════

> **Project**: AI-Piloted Penetration Testing Cockpit
> **Codename**: Assassin's Blade
> **Version**: v4.0 (final)
> **Origin**: 2026-08-24 · **Current HEAD**: `483eb90` (2026-08-25)
> **Scale**: 24 core modules · 15 tool modules · 27 workflow templates · 88 tracked files · ~14,200 lines of Python

---

## 📖 Document Purpose

This document is the authoritative development history of the RedTeam Harness. It traces
the project's evolution from a bare command-line skeleton (v1.0) through the autonomous,
campaign-aware, LLM-piloted assault platform it is today (v4.0). Every major feature
addition and architectural decision is recorded here — what was built, why it was built
that way, and what it replaced.

---

# PART 1 — VERSION TIMELINE

> **A note on versioning**: The v1.0 → v3.5 phases below are *retrospective classifications*
> of capability layers present in the codebase, not distinct shipped releases. The git history
> contains one squashed initial commit (`05fc49b`) followed by enhancement commits — there were
> no separate v1.0/v2.0/v3.0 tags or releases. The phases document *what was built in what
> order* (both chronologically and conceptually), not five published milestones. Only v4.0
> exists as a named, tagged release (`v4.0.0`).

---

## 🔹 v1.0 — The Skeleton (2026-08-24)

**Commit**: `05fc49b` — *"Initial commit — RedTeam Harness v4.0 Assassin's Blade"*

> ⚠️ Note: The initial commit was labeled v4.0, but it actually contained the complete
> v1.0 foundation *plus* many later modules squashed together (the repo was created from
> the finished state and re-committed in layers). Subsequent feature commits
> (`de26e45`, `7947eeb`, `1f13e75`, `6dfae94`) *enhanced* those squashed-in modules rather
> than introducing them from scratch — the initial snapshot and the feature commits both
> touch the same files because the commits layer improvements on top of the snapshot.

### What existed at v1.0

| Area | Contents |
|------|----------|
| **Entry point** | `harness.py` — CLI mode, dashboard launcher, workflow runner |
| **LLM** | `core/llm_backend.py` — llama-server + Ollama adapters, streaming, JSON schema (GBNF) |
| **Orchestration** | `core/orchestrator.py` — plan → tool-call → execute → reflect → report loop |
| **Tools** | `core/tool_registry.py` — 140+ tool definitions across 14 Kali categories |
| **Tool modules** | 15 category modules (`tools/recon.py` … `tools/hardware.py`) + `tools/base.py` ABC |
| **Safety** | `core/safety.py` — CIDR scope enforcement, blocked targets, confirmation gates |
| **Session** | `core/session.py` — JSON-backed conversation history + command log |
| **Dashboard** | `dashboard/server.py` + `index.html` + `cockpit.css` + `cockpit.js` |
| **Config** | `config.yaml` — LLM, tools, safety, harness, dashboard settings |

### Key architectural decisions (v1.0)

1. **Offline-first by construction** — the LLM only talks to `127.0.0.1` loopback
   (llama-server :8080 or Ollama :11434). No cloud API, no telemetry.
2. **YAML configuration** over Python constants — human-readable, diffable, env-independent.
3. **Flat tool registry with category tags** — each tool = name, binary, category, args
   builder; enables both direct execution and LLM-driven calls.
4. **Flask + SocketIO** chosen for the dashboard — real-time streaming of tool output to
   the browser over WebSockets without a frontend build step.
5. **Safety gates at the orchestrator layer** — destructive tools (`hydra`, `sqlmap`,
   `msfvenom`) require explicit confirmation; scope is CIDR-validated before any scan.

---

## 🔹 v2.0 — The Hardened Execution Engine

> **Evolution**: Performance + safety hardening of the execution path.

### Feature additions

| Feature | Module | What it does |
|---------|--------|-------------|
| Task isolation | `core/task_isolation.py` | Per-workflow sandbox: `tasks/<name>/<timestamp>/` with output/, artifacts/, logs/, state.json — every run's data bound to that task alone |
| Drift detection | `core/hardening.py` | Subprocess hardening, injection-pattern rejection, timeout SIGTERM→SIGKILL |
| Result cache | `core/result_cache.py` | LRU cache keyed by tool+args hash — identical scans never re-run |
| Context trimming | `core/context_manager.py` | Sliding token-budget window, old-output compression, persistent facts |

### Architectural decisions (v2.0)

1. **List-mode subprocess execution** — never shell-joined; args passed as arrays to
   prevent injection and word-splitting bugs.
2. **Hard kill cascade** — every tool gets a timeout; on expiry SIGTERM then SIGKILL so
   no zombie scans linger.
3. **Per-step sandbox directories** — solved the "where did that output go" problem by
   binding every step's artifacts to its own timestamped directory (later re-used by the
   workflow engine and campaign manager).
4. **Cache as a pure optimization** — cache hits return stored stdout; cache is never
   trusted for state-changing tools (confirmation-gated tools bypass the cache).

---

## 🔹 v3.0 — The Workflow Engine

> **Evolution**: From "LLM calls tools ad-hoc" to "deterministic YAML kill-chains."

### Feature additions

| Feature | Module | What it does |
|---------|--------|-------------|
| YAML state machine | `core/workflow_engine.py` | Loads templates, interpolates `{{var}}` and `{{chain.step.field}}`, executes steps, validates gates, checkpoints progress |
| LLM workflow generator | `core/workflow_generator.py` | Turns natural-language objectives ("compromise the web tier and pivot to the DB") into validated YAML |
| Finding extractor | `core/findings.py` | Pre-compiled regexes auto-classify tool output into Critical/High/Medium/Low findings |
| Parallel execution | `core/parallel.py` | `ParallelExecutor` — independent tool calls run concurrently |
| Tactical engine | `core/tactics.py` | 21 rules mapping findings → next actions; auto-runs at confidence ≥ 0.85 |
| Target prioritizer | `core/prioritizer.py` | Host attackability scoring (ports + vulns + exposure) |
| Multi-target scheduler | `core/task_scheduler.py` | ThreadPoolExecutor over targets; pools findings; writes combined reports |

### The template library (27 templates, 12 categories)

```
AD ───────────── adcs_abuse_chain · asrep_roasting_chain · dcsync_chain · kerberoasting_chain
Cloud ────────── cloud_iam_enum
Container ────── container_escape_chain · docker_socket_abuse · kubernetes_assessment
Exploit ──────── smb_enum_exploit_chain
Network ──────── ntlm_relay_chain
OSINT ────────── osint_footprinting
Password ─────── password_hash_attack
PostEx ───────── lateral_movement_pivot · linux_privesc_chain
Recon ────────── network_recon
Web ──────────── api_abuse_chain · graphql_introspection_chain · jwt_forgery_chain ·
                 lfi_rce_chain · nosql_injection_chain · oauth_saml_attack ·
                 sql_injection_chain · ssrf_cloud_chain · web_app_assessment · xxe_exfil_chain
Wireless ─────── evil_twin_chain · wireless_wpa_chain
```

### Architectural decisions (v3.0)

1. **YAML as the workflow DSL** — human-editable, LLM-generatable, schema-checkable.
   The generator produces YAML that the engine re-validates against the tool registry
   before a single command runs.
2. **Chain variables** — `{{chain.step_name.field}}` lets one step's extracted output
   feed the next step's arguments, enabling true exploit chaining (e.g. nmap finds port →
   version extract → searchsploit lookup → msf resource generation).
3. **Gates, not gotchas** — each step declares an `expected_output` regex; if the tool
   output doesn't match, the step is flagged and the workflow can branch or halt.
4. **Extraction as first-class** — steps declare `extracts:` with regexes; captured
   groups become named variables for downstream steps and the findings engine.

---

## 🔹 v3.5 → v4.0 — The Assassin's Blade Optimization Campaign

> **Evolution**: A deliberate 7-phase plan to maximize *efficiency, speed, power, and
> accuracy*. This is where the harness earned its codename.

| Phase | Module | Optimization |
|-------|--------|-------------|
| **P1** ⚡ Speed | `core/parallel.py` | Concurrent tool execution — N calls finish in ~max(duration), not Σ |
| **P2** ⚡ Speed | `core/result_cache.py` | LRU keyed by tool+args hash + TTL + stats — never re-run identical scans |
| **P3** 🎯 Accuracy | `core/context_manager.py` | Token-budget sliding window, old-output compression, persistent facts |
| **P4** 🎯 Accuracy | `Orchestrator._generate_best_plan()` | Best-of-N plan voting (temp 0.7 diversity) + post-engagement reflection |
| **P5** 💥 Power | `core/tactics.py` | Finding → action rule engine; auto-run at confidence ≥ 0.85 |
| **P6** 🎯 Accuracy | `WorkflowEngine.validate_template()` | Mock-run validator, per-step drift scores, confidence tagging |
| **P7** 💥 Power | `core/prioritizer.py` | Host attackability scoring → priority-ordered multi-target runs |

### Architectural decisions (v3.5–v4.0)

1. **Best-of-N planning** — the orchestrator generates N candidate plans with
   temperature 0.7 (diversity), self-evaluates each, and executes the winner. Cost is
   N× tokens; accuracy gain justifies it.
2. **Reflection loop** — after each engagement the LLM critiques its own plan
   (`reasoning_reflection_steps: 2`), feeding corrections into the next planning round.
3. **Drift hardening** — every tool result is confidence-tagged (high → uncertain);
   results below `drift_confidence_threshold: 0.7` are re-run or flagged instead of
   trusted blindly.
4. **Self-critique gate** — `drift_require_self_critique: true` forces the LLM to
   evaluate output quality before chaining it into the next step.

---

## 🔹 v4.0 — The Autonomous Assault Platform

> **Evolution**: From "human-in-the-loop assistant" to "fire-and-forget engagement
> engine." 5 new core modules shipped in a single feature commit (`de26e45`).

### New modules (commit `de26e45`)

| Module | Purpose |
|--------|---------|
| `core/autonomous.py` | Kill-chain state machine: IDLE → RUNNING → PAUSED → STOPPING → COMPLETE/FAILED |
| `core/campaign.py` | Multi-target campaign manager with cumulative risk scoring |
| `core/injection_defense.py` | Prompt-injection sanitizer for all LLM-facing inputs |
| `core/msf_generator.py` | Metasploit `.rc` script auto-generator from nmap findings |
| `core/tool_scorer.py` | Per-tool reliability scoring — the LLM learns which tools work on this host |
| `core/vector_memory.py` | ChromaDB/FAISS session memory — remembers targets across engagements |
| `core/tool_installer.py` | Runtime tool installer (apt/pip) — LLM can fetch missing tools mid-engagement |

### The autonomous kill chain

```
START ──▶ RECON ──▶ VULN ──▶ EXPLOIT ──▶ POSTEX ──▶ REPORT
             │         │          │           │
             └─────────┴──────────┴───────────┘
              adaptive retry escalation:
              retry → alternative tool → LLM-suggest → skip phase
```

- **LLM-driven phase transitions** with per-phase completion criteria (recon needs
  ports; exploit checks for shells).
- **Thread-safe pause/resume/stop** with 2-second timeout gates.
- **Engagement timeout** (`MAX_ENGAGEMENT_DURATION = 3600s`) prevents runaway runs.
- **Fire-and-forget reporting** — LLM report with rule-based fallback if the LLM dies.

### Dashboard v4.0 (commit `1f13e75`)

| Panel | What it shows |
|-------|--------------|
| Campaign panel | Multi-target concurrent runs, per-target progress bars |
| Findings heatmap | Severity-coded grid of all discovered findings |
| Drift gauges | Confidence meters for output drift |
| Risk scoring | Cumulative risk across the whole campaign |
| Workflow graph | Interactive SVG step-chain with chained-value flow |
| Tool reliability | Bar chart of tool success/failure rates |
| Memory panel | Vector-memory search across sessions |
| Tactical feed | Real-time next-action suggestions with one-click execute |
| Autonomous panel | Start / stop / pause / resume engagements |

---

## Technology Stack (all versions)

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| LLM Backend | llama-server (llama.cpp, OpenAI-compatible API) / Ollama |
| Web Framework | Flask + Flask-SocketIO |
| Real-time | Socket.IO over WebSocket |
| Workflow Engine | Custom YAML state machine |
| Vector Memory | ChromaDB (with FAISS fallback) |
| Task Isolation | subprocess + resource limits |
| Tool Ecosystem | 140+ Kali Linux tools, 14 categories |
| Packaging | pip wheels (offline/air-gap installer) |
| Frontend | Vanilla JS + SVG (no build step, no CDN) |

---

# PART 2 — COMPLETE COMMIT HISTORY

| Commit | Date | Description |
|--------|------|-------------|
| `05fc49b` | 2026-08-24 | **Initial commit** — foundation, tool registry, orchestrator, dashboard, 14 tool modules, config |
| `e753c98` | 2026-08-25 | Comprehensive `.gitignore` — sessions/, output/, tasks/, wheels/, secrets, IDE files |
| `fb86a43` | 2026-08-25 | `SHA256SUMS` integrity manifest + `install_kali_tools.sh` (140+ tool installer) |
| `de26e45` | 2026-08-25 | **Autonomous agent, campaign manager, injection defense, MSF generator, tool scoring, vector memory** |
| `7947eeb` | 2026-08-25 | Enhanced orchestrator, workflow engine, correlation engine, findings extractor, task scheduler, hardening |
| `1f13e75` | 2026-08-25 | **Campaign dashboard, workflow visualizer, tool reliability panel, memory panel, tactical feed** |
| `6dfae94` | 2026-08-25 | MSF `.rc` auto-generator, parallel tool execution, tool-scoring hooks, config updates |
| `d46c2a2` | 2026-08-25 | Test suites — correlation engine (10 tests) + parallel execution (5 tests) |
| `d889653` | 2026-08-25 | Missing `__init__.py` files, `.env.example`, import cleanup across 10 files |
| `43fd740` | 2026-08-25 | Module docstrings, this document, tests moved to `tests/`, test path fixes |
| `483eb90` | 2026-08-25 | `.env.example` gitignore exception + rename |

---

# PART 3 — POST-v4.0 HARDENING & POLISH

After the core engine shipped, a dedicated cleanup pass addressed code quality, packaging,
and documentation (commits `d889653` → `483eb90`):

1. **Dead-code sweep** — AST-based scan across all 26+ modules found **zero** unreachable
   code after `return`/`raise`/`break`/`continue`; **zero** TODO/FIXME/HACK markers; **zero**
   bare `except:` clauses.
2. **Unused-import purge** — 10 files cleaned (`harness.py`, `correlation.py`,
   `autonomous.py`, `campaign.py`, `hardening.py`, `orchestrator.py`, `task_scheduler.py`,
   `tool_installer.py`, `dashboard/server.py`, tests).
3. **Packaging fixes** — `__init__.py` added to `tools/`, `workflows/`,
   `workflows/templates/`, `tests/`; module docstrings on every package.
4. **Test reorganization** — tests moved from repo root to `tests/` with `sys.path`
   setup; verified 15/15 pass from the new location.
5. **Secrets hygiene** — `.env.example` shipped with documented env vars; gitignore
   exception added so the template itself is tracked.

---

### 🔹 Architecture-deepening pass (re-review candidates #2 / #3 / R1–R3)

A focused deepening pass generalized the flat modules into **deep, single-purpose
modules** while keeping all 27 test suites green (net −257 lines on the touched files):

| Candidate | Refactor | Result |
|-----------|----------|--------|
| **#2 orchestrator deepen** *(earlier)* | Prompt construction → `core/prompt_builder.py`; Python-level tool interception → `core/tool_interceptor.py`; orchestrator delegates | `orchestrator.py` 1967 → 1703 lines, −10 dead private methods |
| **#3 dashboard split** *(earlier)* | Dashboard API → `dashboard/blueprints/*` | `server.py` slimmed |
| **R1 KB data split** | Embedded ATT&CK + CVE dataset → canonical `core/kb_data.py`; `core/knowledge_base.py` imports + re-exports (identity preserved) | `knowledge_base.py` 1286 → ~490 lines |
| **R2 report consolidation** | `paths_to_markdown` / `summary_to_markdown` moved from detection engine → `core/report.py`; `correlation.py` keeps thin delegating `@staticmethod`s | presentation logic leaves the correlator |
| **R3 command-builder extraction** | All `_build_*` command constructors + dispatcher → pure, stateless `core/command_builder.py`; `ToolRegistry._build_command` is a thin facade | `tool_registry.py` 1132 → 807 lines; zero circular imports |
| **R1 hardening** | `kb_data._validate_dataset()` runs at import, raising `ValueError` on any malformed ATT&CK/CVE record | fail-fast data integrity |

Trade-offs: the R2 delegates keep a compatibility shim on `FindingCorrelator`, and the
single `report.py` grows as new formats are added — but every writer is discoverable in
one place.

---

# PART 4 — CURRENT ARCHITECTURE (v4.0)

## Module inventory

### Core (24 modules)
```
core/
├── orchestrator.py        # Central loop: plan → tool-call → execute → reflect → report
├── llm_backend.py         # llama-server (OpenAI-compat) / Ollama, streaming, GBNF grammar
├── tool_registry.py       # 140+ tool definitions, 14 categories, auto-detection
├── command_builder.py     # Pure command constructors for every registered tool (R3)
├── report.py              # Unified markdown report writers, incl. correlation rendering (R2)
├── knowledge_base.py      # Offline CVE/ATT&CK lookup, signatures, grounding
├── kb_data.py             # Canonical offline ATT&CK + CVE dataset (integrity-guarded)
├── workflow_engine.py     # YAML state machine: interpolate → chain → validate → checkpoint
├── workflow_generator.py  # NL objective → validated YAML workflow
├── task_isolation.py      # Per-workflow sandbox (tasks/<name>/<ts>/)
├── hardening.py           # Subprocess hardening, injection rejection, kill cascade
├── safety.py              # CIDR scope, blocked lists, confirmation gates
├── session.py             # JSON conversation history + command log
├── findings.py            # Regex auto-findings: credentials, vulns, misconfigs, leaks
├── correlation.py         # Rule-table attack-path linking + per-finding remediation
├── parallel.py            # ParallelExecutor — concurrent tool calls
├── result_cache.py        # LRU tool-result cache with TTL + stats
├── context_manager.py     # Sliding-window context trimmer + persistent facts
├── tactics.py             # Finding → action rule engine + auto-run thresholds
├── prioritizer.py         # Port-weighted + vuln-severity host scoring
├── task_scheduler.py      # Multi-target ThreadPoolExecutor, pooled findings, combined reports
├── autonomous.py          # Kill-chain state machine (recon→vuln→exploit→postex)
├── campaign.py            # Campaign manager, risk scoring, completion tracking
├── injection_defense.py   # Prompt-injection sanitizer for LLM inputs
├── msf_generator.py       # Metasploit .rc generator from nmap results
├── tool_scorer.py         # Tool reliability scoring (learns which tools work here)
├── vector_memory.py       # ChromaDB/FAISS memory across engagements
├── tool_installer.py      # Runtime apt/pip installer for missing tools
└── __init__.py
```

### Tools (15 modules)
```
tools/
├── base.py        # BaseTool ABC — every tool module inherits
├── __init__.py    # ALL_TOOL_MODULES export
├── recon.py · vuln.py · web.py · password.py · wireless.py
├── sniffing.py · exploit.py · forensics.py · reversing.py
├── social.py · postex.py · osint.py · stress.py · hardware.py
```

### Dashboard
```
dashboard/
├── server.py              # REST API + WebSocket event handlers
├── templates/index.html   # Single-page cockpit UI
└── static/
    ├── css/cockpit.css    # Cyberpunk HUD theme
    └── js/cockpit.js      # WebSocket streaming, SVG chain graph, campaign views
```

### Tests
```
tests/
├── __init__.py
├── test_correlation_v5.py   # 10 tests — FindingCorrelator, remediation, ATT&CK, cross-workflow
└── test_parallel_v5.py      # 5 tests — risk computation, correlation, reports, campaigns
```

## Data flow (end-to-end)

```
┌────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
│  Dashboard  │──▶│  Orchestrator │──▶│  LLM (local)  │   │  Tool Registry │
│  (Flask)    │◀──│  (planner)    │◀──│  (llama/ollama)│──▶│  + 140 tools  │
└────────────┘   └──────┬───────┘   └───────────────┘   └──────┬───────┘
                        │                                      │
                        ▼                                      ▼
                 ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
                 │  Workflow    │──▶│  Task Sandbox  │   │  Parallel    │
                 │  Engine      │   │  (isolation)   │   │  Executor    │
                 └──────┬───────┘   └───────────────┘   └──────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  Findings →      │
              │  Correlation →   │
              │  Attack paths →  │
              │  Report / Memory │
              └──────────────────┘
```

---

# PART 5 — ARCHITECTURAL DECISION REGISTER

A running register of every significant "why" decision in the project:

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | LLM talks only to `127.0.0.1` | Guarantees offline operation; no data leaves the host |
| 2 | YAML everywhere (config + workflows) | Human-readable, LLM-generatable, schema-validatable |
| 3 | Flat tool registry with categories | One lookup table; easy for LLM to enumerate |
| 4 | Flask + SocketIO, no JS build step | Real-time streaming without a frontend toolchain |
| 5 | List-mode subprocess execution | Injection-resistant; no shell word-splitting |
| 6 | SIGTERM→SIGKILL timeout cascade | No orphaned scans; predictable resource use |
| 7 | Per-step sandbox directories | Every task's data bound to that task alone |
| 8 | LRU result cache with TTL | Duplicate scans eliminated; cache never trusted for state-changing tools |
| 9 | Regex extracts → chain variables | Deterministic data flow between workflow steps |
| 10 | Gates on every step | Failure is detected and handled, not silently chained |
| 11 | Best-of-N plan voting | Diversity (temp 0.7) + self-evaluation beats a single plan |
| 12 | Drift confidence tagging | Low-confidence results re-run or flagged, never blindly chained |
| 13 | Kill-chain state machine | Pause/resume/stop is thread-safe; timeouts prevent runaway |
| 14 | Rule-based report fallback | LLM death doesn't lose the engagement report |
| 15 | Injection defense at every LLM boundary | Tool output is untrusted until sanitized |
| 16 | Vector memory keyed by target | Re-engagements start with prior findings instead of from zero |
| 17 | Tool scoring + installer | The harness adapts to the host's actual tool inventory |
| 18 | Gitignore everything generated | sessions/, output/, tasks/, wheels/ never pollute the repo |

---

# PART 6 — VERIFICATION MATRIX

The state of the repo at HEAD (`483eb90`):

| Check | Result |
|-------|--------|
| Python modules compile | ✅ 26/26 clean |
| Core modules import | ✅ 23/23 clean |
| Workflow templates validate | ✅ 27/27 (YAML + step counts) |
| Correlation tests | ✅ 10/10 pass |
| Parallel/campaign tests | ✅ 5/5 pass |
| Unreachable code (AST scan) | ✅ 0 found |
| TODO/FIXME/HACK markers | ✅ 0 found |
| Bare `except:` clauses | ✅ 0 found |
| Unused imports (AST) | ✅ purged across 10 files |
| Tracked files | ✅ 88 |
| Tags | ✅ `v1.0.0`, `v4.0.0` |
| Remote | ✅ `origin` → `github.com/kingcinder/redteam-harness` (private) |

---

## Design principles that survived every version

1. **Offline-first** — zero internet dependency, by construction.
2. **Defense-in-depth** — injection defense, drift detection, scope enforcement, sanitization.
3. **Graceful degradation** — rule-based fallbacks when the LLM is unavailable.
4. **Task isolation** — sandboxed subprocesses with timeout and resource limits.
5. **Exploit chaining** — step outputs feed subsequent steps deterministically.
6. **Campaign awareness** — concurrent multi-target runs with pooled findings and unified reports.
