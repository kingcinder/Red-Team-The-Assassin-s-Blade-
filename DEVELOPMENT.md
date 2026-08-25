# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — Development Timeline & Pipeline
# Assassin's Blade v4.0 — Full Development History
# ═══════════════════════════════════════════════════════════════

## Overview

The RedTeam Harness is an offline-first, AI-powered penetration testing cockpit that integrates 140+ Kali Linux tools with a local LLM (llama-server / Ollama) to provide autonomous, workflow-driven red team engagements. Every component runs locally — zero internet dependency.

---

## Development Phases

### Phase 1 — Foundation (v1.0)

**Goal**: Core architecture and tool registry.

| Module | Purpose |
|--------|---------|
| `harness.py` | Main entry point — CLI + dashboard launcher |
| `core/llm_backend.py` | LLM adapter with llama-server and Ollama backends |
| `core/tool_registry.py` | Registry of 140+ Kali tools with auto-detection |
| `core/orchestrator.py` | Prompt → plan → execution → results pipeline |
| `core/session.py` | Session persistence and history |
| `core/safety.py` | Scope enforcement and target allowlisting |
| `config.yaml` | Master configuration (LLM, tools, safety, harness) |
| `requirements.txt` | Python dependencies |

**Key decisions**:
- YAML-based configuration for human readability
- Flat tool registry with category-based organization
- Flask + SocketIO for real-time dashboard

---

### Phase 2 — Execution Engine (v2.0)

**Goal**: Hardened tool execution with isolation.

| Module | Purpose |
|--------|---------|
| `core/task_isolation.py` | Per-task sandboxed execution (cgroup/namespace) |
| `core/hardening.py` | Drift detection, integrity checks, output sanitization |
| `core/result_cache.py` | LRU cache with TTL for tool output deduplication |
| `core/context_manager.py` | Context-window trimming for LLM prompts |

**Key decisions**:
- Each tool runs in an isolated subprocess with timeout enforcement
- Output is sanitized before passing to LLM (injection defense)
- Results are cached to avoid redundant tool invocations

---

### Phase 3 — Workflow Engine (v3.0)

**Goal**: YAML workflow templates with variable interpolation and chaining.

| Module | Purpose |
|--------|---------|
| `core/workflow_engine.py` | State machine: load YAML → interpolate → execute → chain |
| `core/workflow_generator.py` | LLM generates YAML workflows from natural-language objectives |
| `core/findings.py` | Severity-classified finding extraction from tool output |
| `core/parallel.py` | ThreadPool-based parallel tool execution |
| `core/tactics.py` | Tactical suggestion engine (next-action recommendations) |
| `core/prioritizer.py` | Target prioritization by risk score |
| `core/task_scheduler.py` | Multi-target concurrent workflow scheduler |

**Key decisions**:
- YAML as the workflow DSL (human-readable, LLM-generatable)
- Regex-based finding extraction with pre-compiled patterns
- Chain variables (`{{chain.step_name.field}}`) for exploit chaining
- Gate validators for step-level success criteria

**Workflow templates created** (20+):
- `full_recon_chain.yaml` — Complete network reconnaissance
- `web_vuln_assessment.yaml` — Web application vulnerability scan
- `linux_privesc_chain.yaml` — Linux privilege escalation
- `windows_lateral_movement.yaml` — Windows domain pivoting
- `active_directory_full.yaml` — AD enumeration and exploitation
- `smb_exploitation_chain.yaml` — EternalBlue and SMB attacks
- `sql_injection_rce.yaml` — SQL injection → RCE chain
- `ssh_bruteforce_privesc.yaml` — SSH brute + privesc
- `cloud_iam_privesc.yaml` — AWS/Azure/GCP IAM escalation
- `kubernetes_rbac_exploit.yaml` — K8s RBAC exploitation
- `docker_socket_escape.yaml` — Container escape via Docker socket
- `graphql_introspection_abuse.yaml` — GraphQL introspection attacks
- `oauth_token_abuse.yaml` — OAuth/SAML token exploitation
- `php_lfi_rce_chain.yaml` — PHP LFI → RCE chain
- `xxe_to_rce.yaml` — XXE → RCE exploitation
- `nosql_injection.yaml` — NoSQL injection attacks
- `api_rate_limit_bypass.yaml` — API rate limiting bypass
- `wifi_evil_twin.yaml` — WiFi Evil Twin attack
- `saml_login_bypass.yaml` — SAML authentication bypass
- `azure_privesc.yaml` — Azure privilege escalation

---

### Phase 4 — Reasoning & Intelligence (v3.5 → v4.0)

**Goal**: LLM-driven planning with self-correction and context management.

| Enhancement | Implementation |
|-------------|----------------|
| Best-of-N planning | Generate N plans, self-evaluate, pick the best |
| Self-correction loop | Detect malformed LLM output, retry with hints |
| Reflection steps | LLM critiques its own output before execution |
| Context trimming | Auto-trim messages to fit context window |
| Tactical suggestions | Real-time next-action recommendations |

**Key decisions**:
- `reasoning_best_of_n` config controls planning quality
- `drift_require_self_critique` enables LLM self-review
- Context manager trims oldest messages first, preserving recent context

---

### Phase 5 — Autonomous Agent (v4.0 — Assassin's Blade)

**Goal**: Fire-and-forget autonomous pentest engagement.

| Module | Purpose |
|--------|---------|
| `core/autonomous.py` | State machine: recon → vuln → exploit → postex |
| `core/campaign.py` | Multi-target campaign manager with risk scoring |
| `core/injection_defense.py` | Prompt-injection sanitizer for LLM inputs |
| `core/msf_generator.py` | Metasploit .rc script auto-generator |
| `core/vector_memory.py` | ChromaDB/FAISS-backed session memory |
| `core/tool_installer.py` | Runtime tool installer (apt/pip) for missing tools |

**Key decisions**:
- Kill chain state machine (IDLE → RUNNING → PAUSED → STOPPING → COMPLETE/FAILED)
- Per-phase completion criteria (recon needs ports, exploit checks for shells)
- Adaptive retry escalation: retry → alternative → LLM-suggest → skip_phase
- Thread-safe pause/resume/stop with 2s timeout gates
- Engagement timeout (3600s) prevents runaway execution
- Fallback report generation when LLM is unavailable

---

### Phase 6 — Dashboard & Visualization (v4.0)

**Goal**: Real-time C2-style cockpit dashboard.

| Component | Description |
|-----------|-------------|
| Campaign panel | Multi-target concurrent runs with progress bars |
| Findings heatmap | Severity-coded grid of all discovered findings |
| Drift gauges | Confidence meters for output drift detection |
| Risk scoring | Cumulative risk across the entire campaign |
| Workflow graph | Interactive SVG step-chain visualizer |
| Tool reliability | Bar chart of tool success/failure rates |
| Memory panel | Vector memory search and session history |
| Tactical feed | Real-time next-action suggestions with one-click execution |
| Autonomous panel | Start/stop/pause/resume autonomous engagements |

**API endpoints**:
- REST: `/api/workflows`, `/api/autonomous/*`, `/api/campaigns/*`, `/api/memory/*`, `/api/findings/*`
- WebSocket: `tool_output`, `plan_update`, `autonomous_*`, `campaign_*`

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard (Flask)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │ Campaign │ │Workflow  │ │Autonomous│ │ Memory     │ │
│  │ Panel    │ │ Graph    │ │ Agent    │ │ Panel      │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
│       │            │            │              │         │
│  ─────┴────────────┴────────────┴──────────────┴─────── │
│                    Socket.IO (real-time)                 │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────┐
│                    Orchestrator                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │  LLM     │ │ Workflow │ │  Safety  │ │  Session   │ │
│  │ Backend  │ │ Engine   │ │  Gates   │ │  Manager   │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
│       │            │            │              │         │
│  ─────┴────────────┴────────────┴──────────────┴─────── │
│                    Execution Layer                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │  Tool    │ │   Task   │ │Parallel  │ │  Result    │ │
│  │ Registry │ │ Isolation│ │ Executor │ │  Cache     │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────┐
│              140+ Kali Linux Tools                      │
│  nmap nikto sqlmap hydra nuclei msfconsole gobuster ...│
└─────────────────────────────────────────────────────────┘
```

---

## File Structure

```
redteam-harness/
├── harness.py                    # Main entry point
├── config.yaml                   # Master configuration
├── requirements.txt              # Python dependencies
├── env.example                   # Environment variable template
├── SHA256SUMS                    # Integrity checksums
├── core/                         # Core engine (21 modules)
│   ├── __init__.py
│   ├── orchestrator.py           # Main controller
│   ├── llm_backend.py            # LLM adapter
│   ├── tool_registry.py          # 140+ tool definitions
│   ├── workflow_engine.py        # YAML workflow state machine
│   ├── workflow_generator.py     # LLM workflow generator
│   ├── task_isolation.py         # Sandboxed execution
│   ├── hardening.py              # Drift detection & integrity
│   ├── safety.py                 # Scope enforcement
│   ├── session.py                # Session persistence
│   ├── findings.py               # Finding extraction
│   ├── correlation.py            # Attack-path correlation
│   ├── parallel.py               # Parallel tool execution
│   ├── result_cache.py           # LRU result cache
│   ├── context_manager.py        # Context-window trimming
│   ├── tactics.py                # Tactical suggestions
│   ├── prioritizer.py            # Target prioritization
│   ├── task_scheduler.py         # Multi-target scheduler
│   ├── autonomous.py             # Autonomous agent
│   ├── campaign.py               # Campaign manager
│   ├── vector_memory.py          # ChromaDB/FAISS memory
│   ├── injection_defense.py      # Prompt injection defense
│   ├── msf_generator.py          # Metasploit .rc generator
│   └── tool_installer.py         # Runtime tool installer
├── dashboard/                    # Web dashboard
│   ├── server.py                 # Flask + SocketIO server
│   ├── templates/
│   │   └── index.html            # Dashboard UI
│   └── static/
│       ├── css/cockpit.css       # Dashboard styles
│       └── js/cockpit.js         # Dashboard JavaScript
├── tools/                        # Tool modules
│   ├── __init__.py
│   └── exploit.py                # Exploit framework
├── workflows/                    # Workflow templates
│   ├── __init__.py
│   └── templates/                # 20+ YAML templates
│       ├── *.yaml
├── tests/                        # Test suite
│   ├── __init__.py
│   ├── test_correlation_v5.py    # Correlation engine tests
│   └── test_parallel_v5.py       # Parallel execution tests
├── sessions/                     # Session data (gitignored)
├── output/                       # Report output (gitignored)
├── tasks/                        # Workflow task state (gitignored)
└── wheels/                       # Offline Python wheels (gitignored)
```

---

## Commit History

| Commit | Description |
|--------|-------------|
| `05fc49b` | Initial commit — RedTeam Harness v4.0 Assassin's Blade |
| `e753c98` | Update .gitignore with comprehensive coverage |
| `fb86a43` | Add SHA256 checksums, Kali tool installer, and updated .gitignore |
| `de26e45` | Add autonomous agent, campaign manager, injection defense, MSF generator, tool scoring, and vector memory |
| `7947eeb` | Enhance orchestrator, workflow engine, correlation engine, findings extractor, task scheduler, and hardening |
| `1f13e75` | Add campaign dashboard, workflow visualizer, tool reliability panel, memory panel, and tactical suggestions feed |
| `6dfae94` | Add Metasploit .rc auto-generator, parallel tool execution, tool scoring hooks, and updated config |
| `d46c2a2` | Add correlation engine and parallel execution test suites |
| `d889653` | Add missing __init__.py files, env.example, and clean imports |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| LLM Backend | llama-server (llama.cpp) / Ollama |
| Web Framework | Flask + Flask-SocketIO |
| Real-time | Socket.IO (WebSocket) |
| Workflow Engine | Custom YAML state machine |
| Vector Memory | ChromaDB (with FAISS fallback) |
| Task Isolation | subprocess + resource limits |
| Tool Ecosystem | 140+ Kali Linux tools |
| Packaging | pip wheels (offline installer) |

---

## Design Principles

1. **Offline-First**: Zero internet dependency. All tools, LLMs, and dependencies ship locally.
2. **Defense-in-Depth**: Injection defense, drift detection, scope enforcement, output sanitization.
3. **Graceful Degradation**: Falls back to rule-based execution when LLM is unavailable.
4. **Task Isolation**: Each tool runs in a sandboxed subprocess with timeout and resource limits.
5. **Exploit Chaining**: Workflow steps chain outputs into subsequent steps for multi-stage attacks.
6. **Campaign Awareness**: Multi-target concurrent execution with pooled findings and unified reporting.
