# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — API Reference v4.0
# 57 REST Routes (55 unique paths) · 15 WebSocket Handlers · Real-Time Event Bus
# ═══════════════════════════════════════════════════════════════

> **Server**: `dashboard/server.py` · **Served by**: Flask + Flask-SocketIO
> **Base URL**: `http://<host>:9999` (default; `harness.port` in `config.yaml`)
> **Content-Type**: `application/json` for all request/response bodies (except file upload/export)
> **Auth**: None — intended for loopback / authorized-lab use only. Bind to `0.0.0.0` only
>   on trusted networks. All tool execution inherits the harness's `safety` gates.
>
> **Count note**: The server defines **57 `@app.route` decorators across 55 unique paths** —
> `/api/campaigns` (GET + POST) and `/api/campaigns/<campaign_id>` (GET + DELETE) each share
> one path with two HTTP methods. All 55 paths are documented below; the two method pairs are
> listed separately under their shared path.

---

## Table of Contents

1. [Conventions](#conventions)
2. [System and Status](#1-system-and-status)
3. [Tools](#2-tools)
4. [LLM](#3-llm)
5. [Task and Prompt Processing](#4-task-and-prompt-processing)
6. [Sessions](#5-sessions)
7. [Target Prioritization](#6-target-prioritization)
8. [Autonomous Engagements (REST)](#7-autonomous-engagements-rest)
9. [Workflow Engine](#8-workflow-engine)
10. [Findings Correlation](#9-findings-correlation)
11. [Safety Policy](#10-safety-policy)
12. [Metasploit Auto-Exploit](#11-metasploit-auto-exploit)
13. [C2 Campaign Dashboard](#12-c2-campaign-dashboard)
14. [Vector Memory and RAG](#13-vector-memory-and-rag)
15. [WebSocket Protocol](#14-websocket-protocol)
16. [Server-to-Client Event Bus](#15-server-to-client-event-bus)

---

## Conventions

### Common error responses

| HTTP | Shape | Meaning |
|------|-------|---------|
| `400` | `{"error": "<message>"}` | Bad request — missing/empty required field |
| `403` | `{"error": "Path traversal blocked"}` | Workflow name path traversal rejected |
| `404` | `{"error": "..."}` | Resource not found (workflow, task, campaign, .rc script) |
| `500` | `{"error": "<message>"}` | Internal error (template load, archive import, campaign thread) |

### URL path parameters

- `<workflow_name>` — template name, with **or without** `.yaml` extension. Validated against
  `realpath` to block `../` traversal.
- `<task_id>` — format `<workflow_name>_<YYYYmmdd>_<HHMMSS>[_<hex4>]`. Workflow names contain
  underscores, so the server splits the trailing timestamp (optional hex suffix for
  concurrent runs).
- `<campaign_id>` — UUID string.
- `<target>` — host/IP string used as the vector-memory key.

### Response-shape fidelity note

Endpoint responses are of two kinds: **verified** (the handler's `jsonify(...)` is visible in
`dashboard/server.py`) and **representative** (the handler delegates to an orchestrator method
whose internals live in `core/orchestrator.py` — e.g. `/api/task`, `/api/autonomous/*`,
`/api/workflows/run`, `/api/status`). Representative examples show the *expected* fields but
are not guaranteed byte-for-byte; treat them as the contract shape, not a snapshot.

### Quick examples

```bash
# Run a workflow template
curl -X POST http://localhost:9999/api/workflows/run \
  -H 'Content-Type: application/json' \
  -d '{"workflow": "network_recon", "variables": {"target": "192.168.1.0/24"}}'

# Process a prompt through the LLM
curl -X POST http://localhost:9999/api/task \
  -H 'Content-Type: application/json' \
  -d '{"prompt": "Scan 192.168.1.10 for open ports"}'

# Direct tool execution
curl -X POST http://localhost:9999/api/tool/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool": "nmap_scan", "args": {"target": "192.168.1.10"}}'
```

---

## 1. System and Status

### `GET /` — Dashboard UI
Returns `index.html` (the single-page cockpit). No JSON.

### `GET /api/status` — Harness status
```
200 → Orchestrator.get_status()  # tools, llm, sessions, workflow state, counts
```

### `GET /api/cache/stats` — Result cache statistics
```
200 → ResultCache.get_stats()    # {entries, hits, misses, hit_rate, oldest, newest}
```

### `POST /api/cache/clear` — Clear the result cache
```
200 → {"cleared": true}
```

### `POST /api/tactics/suggest` — Tactical next-action suggestions
**Request:**
```json
{
  "findings": [{"severity": "high", "category": "vulnerability", "title": "...", "evidence": "..."}],
  "context": {"target": "192.168.1.10"}
}
```
**Response:**
```json
200 → {"suggestions": [{"tool": "nuclei_scan", "args": {...}, "confidence": 0.9, "reason": "..."}]}
```
Suggestions with `confidence >= tactics_auto_run_threshold (0.85)` are candidates for auto-run.

---

## 2. Tools

### `GET /api/tools` — All tools grouped by category
```
200 → {
  "recon":   [Tool.to_dict(), ...],
  "vuln":    [...],
  "web":     [...],
  ... (14 categories)
}
```
`Tool.to_dict()` ≈ `{name, binary, category, installed, description, args_schema}`.

### `GET /api/tools/installed` — Only installed tools
```
200 → [Tool.to_dict(), ...]   # flat list of tools whose binary resolves on PATH
```

### `GET /api/tools/quick-commands` — Quick commands from all tool modules
```
200 → [{"name": "...", "description": "...", "command": "...", "category": "..."}, ...]
```
Aggregated via `get_quick_commands()` across `ALL_TOOL_MODULES`.

### `GET /api/tools/attack-chains` — Preset attack chains
```
200 → [{"name": "...", "description": "...", "steps": [...]}, ...]
```
Aggregated via `get_preset_attack_chains()` across `ALL_TOOL_MODULES`.

---

## 3. LLM

### `GET /api/llm/status` — LLM backend status
```
200 → LLMBackend.get_status()   # {backend, base_url, model, connected, ...}
```

### `POST /api/llm/test` — Connection test
**Request:** `{}` (empty)
**Response:**
```json
200 → {"connected": true}
```

---

## 4. Task and Prompt Processing

### `POST /api/task` — Process a pentest prompt through the LLM
**Request:**
```json
{
  "prompt": "Scan 192.168.1.0/24 for open ports",
  "session_id": "optional-session-id",
  "skip_plan": false,
  "stream": false
}
```
**Response:**
```json
200 → {
  "final_response": {"llm_response": "...", "results": [{"tool": "...", "status": "success", ...}]},
  "plan": [...],
  "session_id": "..."
}
400 → {"error": "No prompt provided"}
```

### `POST /api/tool/execute` — Execute a single tool directly
**Request:**
```json
{
  "tool": "nmap_scan",
  "args": {"target": "192.168.1.10", "ports": "1-1000"},
  "session_id": "optional"
}
```
**Response:**
```json
200 → {"stdout": "...", "stderr": "...", "exit_code": 0, "duration_seconds": 12.4}
400 → {"error": "No tool specified"}
```

---

## 5. Sessions

### `GET /api/sessions` — List all sessions
```
200 → [{"id": "...", "name": "...", "created_at": "...", "messages_count": N}, ...]
```

### `GET /api/sessions/<session_id>` — Session summary
```
200 → SessionManager.get_summary(session_id)
```

### `GET /api/sessions/<session_id>/messages` — Full message history
```
200 → [{"role": "user|assistant", "content": "...", "timestamp": "..."}, ...]
```

---

## 6. Target Prioritization

### `POST /api/prioritize` — Rank targets by attackability (Phase 7)
**Request:**
```json
{
  "targets": [{"host": "192.168.1.10", "ports": [22, 445, 80]}, {"host": "192.168.1.20", "ports": [443]}],
  "findings": [{"target": "192.168.1.10", "severity": "critical", ...}]
}
```
**Response:**
```json
200 → [{"host": "...", "score": 87.5, "priority": 1, "factors": {"ports": 40, "vulns": 47.5}}, ...]
```

---

## 7. Autonomous Engagements (REST)

### `POST /api/autonomous` — Toggle autonomous mode
**Request:** `{"enabled": true}`
**Response:** `{"autonomous": true}`

### `POST /api/autonomous/start` — Start a fire-and-forget engagement
**Request:**
```json
{
  "targets": ["192.168.1.10", "192.168.1.20"],
  "objective": "Full penetration test"
}
```
**Response:**
```json
200 → {"started": true, "engagement_id": "...", "targets": [...], "objective": "..."}
400 → {"error": "No targets provided"}
```
Runs the kill chain **recon → vuln → exploit → postex** per target on a background thread,
with adaptive retry escalation. Progress streams via `autonomous_*` WebSocket events.

### `POST /api/autonomous/stop` — Stop engagement
```
200 → {"stopped": true, "state": "stopping"}
```

### `POST /api/autonomous/pause` — Pause engagement
```
200 → {"paused": true, "state": "paused"}
```

### `POST /api/autonomous/resume` — Resume paused engagement
```
200 → {"resumed": true, "state": "running"}
```

### `GET /api/autonomous/status` — Engagement status
```
200 → {
  "state": "running|paused|stopping|complete|failed|idle",
  "current_target": "...",
  "current_phase": "recon|vuln|exploit|postex",
  "targets_completed": 1,
  "targets_total": 3,
  "started_at": "...",
  "elapsed_seconds": 123,
  "priority_order": ["192.168.1.10", "192.168.1.20"],
  "targets_detail": {"192.168.1.10": {"priority_score": 10.0, "priority_tier": "hot", "phase_budget": {"exploit": 30}}}
}
```
`priority_order` lists targets by live priority (highest first). Each target's detail
includes `priority_score`, `priority_tier` (`hot`/`standard`/`chilled`/`neutral`), and the
dynamic per-phase `phase_budget` — hosts with critical/high findings get boosted budgets,
info-only hosts get chilled.

---

## 8. Workflow Engine

### `GET /api/workflows` — List all templates
```
200 → [{"name": "...", "category": "...", "description": "...", "steps_count": N}, ...]
```

### `POST /api/workflows/run` — Run a template with variables
**Request:**
```json
{
  "workflow": "network_recon",
  "variables": {"target": "192.168.1.0/24"},
  "resume": false
}
```
**Response:**
```json
200 → {
  "workflow": "network_recon",
  "status": "complete|partial|failed",
  "completed_steps": 5,
  "total_steps": 5,
  "root": "tasks/network_recon/20260825_123456/",
  "output_size_mb": 1.2,
  "chain_values": {"open_ports": "...", "web_servers": "..."},
  "steps": [{"step": "nmap_scan", "status": "success", "attempts": 1, "duration": 12.0}],
  "warnings": [...]
}
400 → {"error": "No workflow specified"}
```

### `GET /api/workflows/<workflow_name>/status` — Latest task status
```
200 → same shape as /api/workflows/run response (latest run of that template)
```

### `POST /api/workflows/generate` — LLM-generate a workflow
**Request:** `{"objective": "compromise the web tier and pivot to the database"}`
**Response:**
```json
200 → {
  "name": "generated_<slug>",
  "steps": [...],
  "validation_errors": [],
  "yaml": "..."
}
400 → {"error": "No objective provided"}
```

### `POST /api/workflows/auto` — Auto-workflow (generate + validate + save + execute)
**Request:**
```json
{
  "objective": "compromise the web tier and pivot to the database",
  "variables": {"target": "10.0.0.5"},
  "auto_execute": true
}
```
**Response:** full workflow-run result plus `"saved_template": true` when validation passes.
`auto_execute: false` only generates/validates/saves without running.

### `POST /api/workflows/run-multi` — Run template concurrently across targets
**Request:**
```json
{
  "workflow": "web_app_assessment",
  "targets": ["10.0.0.5", "10.0.0.6", "10.0.0.7"],
  "variables": {},
  "max_concurrent": 3
}
```
**Response:**
```json
200 → {
  "status": "complete|partial",
  "report_path": "tasks/multi_*/report.md",
  "pooled_findings": [{"target": "...", "severity": "...", ...}],
  "findings_summary": {"critical": 2, "high": 3, "medium": 1, "low": 0, "info": 0},
  "per_target": {"10.0.0.5": {"status": "complete", "steps_count": 5, "total_steps": 5}}
}
400 → {"error": "No workflow specified"} | {"error": "No targets specified"}
```

### `GET /api/workflows/graph/<path:workflow_name>` — Chain graph for visualizer
**Query param:** `?task_id=<task_id>` optional — merges a saved run's `state.json` to color nodes
by live status.
```
200 → {
  "nodes": [{"id": "nmap_scan", "label": "nmap_scan", "status": "success|pending|failed"}],
  "edges": [{"from": "nmap_scan", "to": "nikto_scan", "value": "chain.open_ports"}],
  "metadata": {"total_nodes": N, "total_edges": M, "workflow": "..."}
}
404 → {"error": "Workflow not found: <name>"}
403 → {"error": "Path traversal blocked"}
```

### `GET /api/workflows/<path:task_id>/state` — Task run state
```
200 → state.json  # {status, steps: [...], chain_values: {...}, variables: {...}, started, completed}
404 → {"error": "Task not found"}
```

### `GET /api/workflows/validate/<path:workflow_name>` — Mock-run validate template (Phase 6)
```
200 → {"valid": true, "warnings": [], "steps_validated": N}
404 → {"error": "Workflow not found: <name>"}
403 → {"error": "Path traversal blocked"}
```

### `GET /api/workflows/validate-all` — Validate every template (drift hardening)
```
200 → {"all_valid": true, "count": 27, "results": {"<template>.yaml": {"valid": true, ...}}}
```

### `GET /api/workflows/<path:task_id>/sandbox/<step_name>` — Step sandbox output
**Path note:** `step_name` is sanitized to `[a-zA-Z0-9_-]` before filesystem access.
```
200 → {
  "step": "nmap_scan",
  "stdout": "...",            # first 50,000 chars
  "stderr": "...",            # first 10,000 chars
  "log_excerpt": "...",       # matching workflow.log lines, last 50, max 5,000 chars
  "stdout_size": 12345,
  "stderr_size": 0
}
400 → {"error": "Invalid task_id"}
404 → {"error": "Task not found"}
```

### `GET /api/workflows/<path:task_id>/drift` — Drift metrics for a run (Phase 6)
```
200 → {
  "overall_confidence": 0.92,
  "steps": [{"step": "...", "drift_score": 0.05, "confidence": "high"}],
  "flagged_steps": []
}
400 → {"error": "Invalid task_id"}
404 → {"error": "Task not found"}
```

---

## 9. Findings Correlation

### `POST /api/correlate` — Correlate findings into attack paths
**Request:**
```json
{
  "findings": [
    {"title": "Open port 445/tcp (SMB)", "severity": "medium", "category": "recon",
     "evidence": "445/tcp open", "dedupe_key": "445/tcp-open", "source_tool": "nmap_scan"},
    {"title": "MS17-010 EternalBlue vulnerable", "severity": "critical", "category": "vulnerability",
     "evidence": "SMBv1 enabled", "dedupe_key": "ms17-010", "source_tool": "nmap_scan"}
  ]
}
```
**Response:**
```json
200 → {
  "paths": [{
    "title": "SMB / EternalBlue Lateral Movement Path",
    "severity": "critical",
    "score": 10,
    "confidence": 0.75,
    "kill_chain_progress": 1.0,
    "attack_techniques": [{"id": "T1210"}, {"id": "T1021.002"}],
    "findings": ["ms17-010", "445/tcp-open"],
    "remediation": ["Patch MS17-010", "Disable SMBv1", ...],
    "graph": {"nodes": [...], "edges": [...], "metadata": {"total_nodes": 6, "total_edges": 6}}
  }],
  "paths_count": 1
}
```

### `GET /api/workflows/<path:task_id>/correlation` — Correlate a saved task run
```
200 → same as POST /api/correlate, with findings pulled from the task's state.json
404 → {"error": "Task not found"}
```

---

## 10. Safety Policy

### `GET /api/safety` — Current safety configuration
```
200 → {
  "allowed_targets": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
  "blocked_targets": ["8.8.8.8", "1.1.1.1", "0.0.0.0"],
  "require_confirmation": ["hydra_brute", "sqlmap_scan", "msfvenom_payload", ...],
  "log_all_commands": true
}
```

---

## 11. Metasploit Auto-Exploit

### `POST /api/msf/generate` — Generate `.rc` script from nmap output
**Request:**
```json
{
  "nmap_output": "<raw nmap -oX or -oN output>",
  "lhost": "0.0.0.0",
  "lport": 4444,
  "payload": "",          // optional, e.g. "linux/x64/meterpreter/reverse_tcp"
  "objective": ""         // optional LLM guidance
}
```
**Response:**
```json
200 → {
  "rc_path": "output/msf_scripts/auto_<ts>.rc",
  "rc_content": "use exploit/...\nset RHOSTS ...\nrun\n",
  "generated": true,
  "summary": "Generated N exploit stages for M services"
}
400 → {"error": "No nmap output provided"}
```

### `POST /api/msf/execute` — Execute a saved `.rc` via msfconsole
**Request:**
```json
{"rc_path": "output/msf_scripts/auto_20260825.rc", "timeout": 600}
```
**Response:**
```json
200 → {"stdout": "...", "exit_code": 0, "duration_seconds": 45.2}
404 → {"error": "RC script not found"}
```

### `POST /api/msf/validate` — Validate `.rc` content
**Request:** `{"rc_content": "use exploit/...\n..."}`
**Response:**
```json
200 → {"valid": true, "warnings": ["No payload specified"]}
400 → {"error": "No RC content provided"}
```

### `GET /api/msf/list` — List generated `.rc` scripts
```
200 → [{"name": "auto_20260825.rc", "path": "output/msf_scripts/...", "size": 512}, ...]
```

---

## 12. C2 Campaign Dashboard

### `GET /api/campaigns` — List campaigns
```
200 → [{"id": "...", "name": "...", "targets": [...], "status": "created|running|complete|failed",
        "completed_targets": N, "findings_total": N, "risk_score": 12.3}, ...]
```

### `POST /api/campaigns` — Create campaign
**Request:**
```json
{
  "name": "Week-1 Engagement",
  "targets": ["10.0.0.5", "10.0.0.6"],
  "workflow": "web_app_assessment",
  "description": "optional"
}
```
**Response:**
```json
200 → {"id": "uuid", "name": "...", "targets": [...], "status": "created", "workflow": "..."}
400 → {"error": "No targets provided"}
```

### `GET /api/campaigns/<campaign_id>` — Full campaign state
```
200 → campaign dict incl. per-target {status, progress, findings[], drift_score}
404 → {"error": "Campaign not found"}
```

### `GET /api/campaigns/<campaign_id>/heatmap` — Findings heatmap grid
```
200 → {"targets": ["10.0.0.5", "10.0.0.6"],
       "severities": ["critical", "high", "medium", "low", "info"],
       "grid": [[counts...]]}
```

### `GET /api/campaigns/<campaign_id>/risk` — Risk scoring breakdown
```
200 → {"total": 36.5, "rating": "MEDIUM",
       "breakdown": {"severity_risk": 28.4, "criticality": 3.5, "coverage": 2.4, "chain_depth": 2.2}}
```

### `GET /api/campaigns/<campaign_id>/correlation` — Correlated attack paths
```
200 → {"paths": [...], "findings": [...], "paths_count": N}
      (empty path set when campaign has no findings)
404 → {"error": "Campaign not found"}
```

### `POST /api/campaigns/<campaign_id>/start` — Run campaign workflow on all targets
**Request:**
```json
{"workflow": "web_app_assessment", "variables": {}}
```
Executes in a **background thread**; emits `campaign_complete` when done.
**Response:**
```json
200 → {"campaign_id": "...", "status": "started", "workflow": "...", "targets": [...]}
400 → {"error": "No workflow specified"}
404 → {"error": "Campaign not found"}
```

### `DELETE /api/campaigns/<campaign_id>` — Remove campaign
```
200 → {"deleted": true, "id": "..."}
404 → {"error": "Campaign not found"}
```

---

## 13. Vector Memory and RAG

### `GET /api/memory/stats` — Memory statistics
```
200 → {"targets": N, "findings": N, "dimensions": 384, "last_write": "..."}
```

### `GET /api/memory/targets` — All stored targets
```
200 → [{"target": "192.168.1.10", "findings_count": 7, "last_seen": "..."}]
```

### `POST /api/memory/query` — Semantic search
**Request:**
```json
{"query": "SMB vulnerabilities", "top_k": 10, "target": "192.168.1.10"}
```
**Response:**
```json
200 → {"results": [{"text": "...", "score": 0.87, "severity": "critical", "target": "..."}],
       "count": 2}
400 → {"error": "No query provided"}
```

### `GET /api/memory/target/<target>` — All past findings for a target
```
200 → {"target": "192.168.1.10", "findings": [...], "count": N,
       "context_block": "compressed LLM context for this target"}
```

### `GET /api/memory/export` — Download memory as .zip
```
200 → application/zip (Content-Disposition: attachment; filename=redteam_memory_export.zip)
      Contains: index.json, vocab.json, vectors.npy, stats.json
```

### `POST /api/memory/import` — Upload memory .zip
**Request:** `multipart/form-data`, field name `file`
```
200 → {"imported": 3, "stats": {...}}
400 → {"error": "No file uploaded"} | {"error": "No valid memory files in archive"}
500 → {"error": "<message>"}
```

### `POST /api/memory/reset` — Wipe all memory
```
200 → {"reset": true}
```

---

## 14. WebSocket Protocol

> Connect via Socket.IO at the same origin (async mode: `threading`). After `connect`,
> the server immediately emits `status`. Client events use `emit("event", payload)`; the
> server replies with the event named in the **Response event** column.

### Client → Server events (15)

| # | Event | Payload (in) | Response event | Notes |
|---|-------|--------------|----------------|-------|
| 1 | `connect` | — | `status` | Auto-emitted on handshake |
| 2 | `disconnect` | — | — | |
| 3 | `send_task` | `{prompt, session_id?}` | `task_complete` | Streams `llm_chunk` events while thinking |
| 4 | `execute_tool` | `{tool, args?, session_id?}` | `tool_result` | |
| 5 | `execute_tactical` | `{tool, args?, session_id?}` | `tactical_result` | One-click tactical suggestion execution |
| 6 | `set_autonomous` | `{enabled: bool}` | `autonomous_changed` | Toggle autonomous mode |
| 7 | `autonomous_start` | `{targets[], objective?}` | `autonomous_started` | |
| 8 | `autonomous_stop` | — | `autonomous_stopped` | |
| 9 | `autonomous_pause` | — | `autonomous_paused` | |
| 10 | `autonomous_resume` | — | `autonomous_resumed` | |
| 11 | `autonomous_status` | — | `autonomous_status` | |
| 12 | `run_workflow` | `{workflow, variables?, resume?}` | `workflow_result` | |
| 13 | `run_multi_workflow` | `{workflow, targets[], variables?}` | `workflow_multi_result` | |
| 14 | `generate_workflow` | `{objective}` | `workflow_generated` | |
| 15 | `auto_workflow` | `{objective, variables?, auto_execute?}` | `auto_workflow_result` | |

### Error events

Any handler failure emits:
```json
{"message": "<error description>"}
```
on the `error` channel. Payload validation failures (missing prompt/tool/target/objective)
also emit `error` rather than HTTP status codes.

### Socket.IO client example

```javascript
// Browser (Socket.IO client served locally — no CDN)
const socket = io();

socket.on('status', (s) => console.log('harness status', s));
socket.on('tool_complete', (t) => console.log('tool done', t));
socket.on('error', (e) => console.error(e.message));

socket.emit('send_task', { prompt: 'Scan 192.168.1.10 for open ports' });
socket.emit('execute_tool', { tool: 'nmap_scan', args: { target: '192.168.1.10' } });
```

```python
# Python client
import socketio
sio = socketio.Client()
sio.connect('http://localhost:9999')
sio.emit('run_workflow', {'workflow': 'network_recon', 'variables': {'target': '10.0.0.0/24'}})
```

---

## 15. Server-to-Client Event Bus

Events the server **pushes** to all connected clients (from orchestrator callbacks):

### Core pipeline

| Event | Payload |
|-------|---------|
| `tool_start` | `{tool, args, target?}` |
| `tool_complete` | `{tool, status, duration_seconds, exit_code}` |
| `llm_thinking` | `{prompt}` |
| `llm_response` | `{response}` |
| `llm_chunk` | `{chunk}` — streaming token |
| `plan_generated` | `{plan: [...]}` |
| `report_generated` | `{report_path, summary}` |
| `error` | `{message}` |

### Workflow engine

| Event | Payload |
|-------|---------|
| `workflow_start` | `{workflow, target, total_steps}` |
| `workflow_complete` | `{workflow, target, status, completed_steps, total_steps, findings}` |

### Campaign dashboard

| Event | Payload |
|-------|---------|
| `campaign_update` | `{campaign_id, risk_score, completed, total, findings_total}` |
| `campaign_target_update` | `{campaign_id, target, data: {status, progress, total, findings_count}}` |
| `campaign_complete` | `{campaign_id, status, error?}` |

### Autonomous engagement

| Event | Payload |
|-------|---------|
| `autonomous_status_update` | `{state, current_target, current_phase, ...}` |
| `autonomous_phase_update` | `{target, phase, status}` |
| `autonomous_complete` | `{targets_completed, report_path}` |
| `autonomous_error` | `{target, phase, error}` |
| `autonomous_retry_escalation` | `{target, step, attempt, strategy: "retry|alternative|llm_suggest|skip_phase"}` |
| `autonomous_report` | `{report_path, findings_count}` |
| `autonomous_priority_update` | Live priority ranking — `{ranking: [{rank, target, score, tier, findings_count, severity_counts}], targets_count, engine}`. Emitted after each target engages; hot targets (critical/high findings) rank first and get boosted phase budgets, info-only targets sink and get chilled budgets |

---

## Quick reference — grouping by orchestrator subsystem

| Subsystem | REST group | WS group |
|-----------|-----------|----------|
| Core prompt loop | `/api/task`, `/api/tool/execute` | `send_task`, `execute_tool` |
| Tools | `/api/tools*` | — |
| LLM | `/api/llm/*` | — |
| Sessions | `/api/sessions*` | — |
| Autonomous | `/api/autonomous*` | `autonomous_*` + bus events |
| Workflows | `/api/workflows*` | `run_workflow`, `run_multi_workflow`, `generate_workflow`, `auto_workflow` |
| Correlation | `/api/correlate`, `.../correlation` | — |
| Campaigns | `/api/campaigns*` | `campaign_*` bus events |
| Memory | `/api/memory*` | — |
| MSF | `/api/msf/*` | — |
| Safety | `/api/safety` | — |
| Cache/Tactics | `/api/cache/*`, `/api/tactics/suggest` | `execute_tactical` |
