# 🎯 RedTeam Harness v4.0 — Assassin's Blade

> **140+ Kali Linux security tools. 7-phase optimization engine. 27 workflow templates. One local LLM piloting it all. 100% offline. Zero internet.**

RedTeam Harness is a fully offline penetration-testing cockpit that lets a locally-hosted LLM (llama-server or Ollama) plan attacks, execute tools, analyze results, chain exploits, correlate findings, and auto-generate reports — all on localhost, never phoning home.

---

## 🗡️ Architecture — 7-Phase Assassin's Blade

| Phase | Module | What it does |
|-------|--------|-------------|
| **P1** ⚡ | `.core/parallel.py` | Concurrent tool execution — N calls finish in ~max(duration), not sum |
| **P2** ⚡ | `.core/result_cache.py` | LRU cache keyed by tool+args hash — never re-run identical scans |
| **P3** 🎯 | `.core/context_manager.py` | Token budget sliding window, old-output compression, persistent facts |
| **P4** 🎯 | Orchestrator `_generate_best_plan()` | Best-of-N plan voting (temp 0.7 diversity) + post-engagement reflection |
| **P5** 💥 | `.core/tactics.py` | 21 tactical rules mapping findings → next actions, auto-run at confidence ≥ 0.85 |
| **P6** 🎯 | Workflow engine `validate_template()` | Mock-run validator, per-step drift scores, confidence tagging (high→uncertain) |
| **P7** 💥 | `.core/prioritizer.py` | Host attackability scoring (ports + vulns + exposure) → priority-ordered multi-target runs |

---

## 📦 Project Structure

```
redteam-harness/
├── harness.py                 # Main entry point (dashboard / CLI / workflows / generator)
├── install.sh                 # Single-script offline installer
├── setup.sh                   # Quick-start setup (legacy)
├── requirements.txt           # Python deps (Flask, SocketIO, PyYAML, requests, jinja2)
├── config.yaml                # LLM backend, tool paths, safety scope, assassin blade tuning
├── .gitignore                 # Ignores sessions/ output/ tasks/ wheels/ __pycache__
├── README.md                  # This file
│
├── core/                      # 18 modules — the brain of the harness
│   ├── orchestrator.py        # Central loop: plan → tool-call → execute → reflect → report
│   ├── llm_backend.py         # llama-server (OpenAI-compat) / Ollama adapter, streaming, GBNF
│   ├── tool_registry.py       # 140+ tool definitions across 14 Kali categories
│   ├── hardening.py           # Subprocess hardening, injection rejection, timeout enforcement
│   ├── session.py             # JSON-backed conversation memory + command log
│   ├── safety.py              # CIDR scope enforcement, blocked-lists, confirmation gates
│   ├── task_isolation.py      # Per-workflow sandbox: tasks/<name>/<timestamp>/{output,artifacts,logs,state.json}
│   ├── workflow_engine.py     # YAML state machine: interpolate vars, chain extracts, validate, checkpoint
│   ├── workflow_generator.py  # LLM-generated workflows from natural-language objectives
│   ├── task_scheduler.py      # Multi-target ThreadPoolExecutor with pooled findings + combined reports
│   ├── findings.py            # Regex-based auto-findings: credentials, vulns, misconfigs, info leaks
│   ├── correlation.py         # Rule-table attack-path linking + per-finding remediation
│   ├── parallel.py            # ParallelExecutor — concurrent tool calls
│   ├── result_cache.py        # LRU tool-result cache with TTL + stats
│   ├── context_manager.py     # Sliding-window context trimmer with persistent facts
│   ├── tactics.py             # Finding→action rule engine + auto-run thresholds
│   ├── prioritizer.py         # Port-weighted + vuln-severity host scoring
│   └── __init__.py            # Package marker
│
├── tools/                     # 14 tool-category modules (quick commands + attack chains)
│   ├── base.py                # BaseTool ABC
│   ├── __init__.py            # ALL_TOOL_MODULES export
│   ├── recon.py vuln.py web.py password.py wireless.py
│   ├── sniffing.py exploit.py forensics.py reversing.py
│   ├── social.py postex.py osint.py stress.py hardware.py
│
├── dashboard/                 # Flask + SocketIO web cockpit
│   ├── server.py              # REST API + WebSocket event handlers
│   ├── templates/index.html   # Single-page cockpit UI
│   └── static/
│       ├── css/cockpit.css    # Cyberpunk theme, HUD styling
│       └── js/cockpit.js      # WebSocket streaming, workflow modal, chain graph SVG
│
├── workflows/templates/       # 27 YAML workflow templates
│   ├── network_recon.yaml     smb_enum_exploit_chain.yaml    kerberoasting_chain.yaml
│   ├── web_app_assessment.yaml sql_injection_chain.yaml      nosql_injection_chain.yaml
│   ├── linux_privesc_chain.yaml  container_escape_chain.yaml  kubernetes_assessment.yaml
│   ├── adcs_abuse_chain.yaml  dcsync_chain.yaml              ntlm_relay_chain.yaml
│   ├── lateral_movement_pivot.yaml  asrep_roasting_chain.yaml
│   ├── password_hash_attack.yaml    oauth_saml_attack.yaml
│   ├── graphql_introspection_chain.yaml  api_abuse_chain.yaml
│   ├── wireless_wpa_chain.yaml  evil_twin_chain.yaml
│   ├── osint_footprinting.yaml   cloud_iam_enum.yaml
│   ├── ssrf_cloud_chain.yaml  xxe_exfil_chain.yaml           lfi_rce_chain.yaml
│   ├── docker_socket_abuse.yaml  jwt_forgery_chain.yaml
│
├── sessions/                  # Engagement conversation history (auto-created)
├── output/                    # Raw tool output (auto-created)
├── tasks/                     # Per-workflow sandbox runs (auto-created)
└── wheels/                    # Offline pip wheelhouse (optional, for air-gap)
```

---

## 🚀 Quick Start

```bash
cd redteam-harness
bash install.sh          # Single-script installer — detects tools, installs deps

python3 harness.py        # Launch dashboard at http://localhost:9999
python3 harness.py --cli  # Interactive CLI mode
python3 harness.py --check  # Tool audit

# CLI workflows
python3 harness.py --workflow network_recon --target 192.168.1.0/24
python3 harness.py --workflow network_recon --targets 10.0.0.1,10.0.0.2,10.0.0.3
python3 harness.py --generate "compromise the web tier and pivot to the database"
```

---

## ⚙️ Configuration (`config.yaml`)

```yaml
# LLM backend (localhost only — never phones home)
llm:
  backend: "llama-server"       # or "ollama"
  llama-server:
    host: "127.0.0.1"
    port: 8080
    model: "carnice-qwen3.6-moe-35b"
    temperature: 0.3

# Assassin's Blade tuning
assassins_blade:
  cache_max_size: 256           # LRU cache entries
  cache_ttl_seconds: 600        # 10-min cache expiry
  context_max_tokens: 32768     # Sliding window budget
  reasoning_best_of_n: 3        # Plan voting rounds
  reasoning_self_evaluate: true # Post-engagement reflection
  tactics_auto_run_threshold: 0.85
  drift_confidence_threshold: 0.7

# Safety scope
safety:
  allowed_targets: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
  blocked_targets: ["8.8.8.8", "1.1.1.1"]
  require_confirmation: [hydra_brute, hashcat_crack, sqlmap_scan, msfvenom_payload]
```

---

## 🧰 Tool Categories (140+ tools)

| Category | Count | Key tools |
|----------|-------|-----------|
| 🔍 Recon | 17 | nmap, masscan, httpx, amass, subfinder, dnsx, enum4linux, smbmap |
| ⚠️ Vuln | 11 | nuclei, wpscan, searchsploit, linpeas, snmpwalk, trivy, lynis |
| 🌐 Web | 17 | nikto, sqlmap, gobuster, ffuf, wfuzz, whatweb, katana, ZAP |
| 🔓 Password | 11 | hydra, john, hashcat, hashid, crunch, fcrackzip |
| 📡 Wireless | 7 | aircrack-ng, airodump-ng, reaver, bettercap, kismet |
| 👃 Sniffing | 6 | tcpdump, tshark, ettercap, responder, dsniff, mitm6 |
| 💥 Exploit | 9 | msfvenom, msfconsole, crackmapexec, impacket, chisel |
| 🔬 Forensics | 12 | binwalk, foremost, volatility, exiftool, steghide |
| 🔧 Reversing | 11 | radare2, gdb, objdump, apktool, jadx, yara |
| 🕵️ OSINT | 9 | whois, dig, theHarvester, recon-ng, sherlock, holehe |
| 🦾 PostEx | 10 | mimikatz, bloodhound, proxychains, socat, ligolo, certipy |
| 🎣 Social | 3 | SEToolkit, BeEF, GoPhish |
| ⚡ Stress | 4 | hping3, slowhttptest, ab, siege |
| 🔌 Hardware | 3 | minicom, flashrom, screen |

---

## 🔒 Offline-First Guarantee

| Component | Internet | Notes |
|-----------|----------|-------|
| Dashboard UI | ❌ No | All static assets local. No CDNs. No web fonts. System font stack. |
| WebSockets | ❌ No | Flask-SocketIO serves socket.io from local files |
| LLM Backend | ❌ No | `127.0.0.1:8080` (llama-server) or `127.0.0.1:11434` (Ollama) |
| Tool execution | ❌ No | All CLI tools run natively on the host |
| Python deps | ❌ No* | Pre-download to `./wheels/` on a connected machine, copy to air-gap |
| Fonts | ❌ No | DejaVu Sans Mono, Liberation Mono, system fallback |

\* *pip packages are ~10 MB total. The wheels directory fits on a USB stick alongside the harness.*

---

## 🔒 Air-Gapped / Offline Setup

```bash
# On an internet-connected machine:
cd redteam-harness
mkdir -p wheels
pip3 download -r requirements.txt -d ./wheels

# Copy the ENTIRE redteam-harness/ directory to the air-gapped host.
# On the air-gapped host:
cd redteam-harness
bash install.sh          # Auto-detects local wheels, installs without internet
python3 harness.py       # Ready — zero internet needed
```

---

## 📡 LLM Backend (Local Only)

The harness exclusively talks to `localhost` loopback addresses:

- **llama-server**: `http://127.0.0.1:8080` (OpenAI-compatible `/v1/chat/completions`)
- **Ollama**: `http://127.0.0.1:11434` (`/api/chat`)

Both support: streaming (SSE chunks), JSON schema enforcement (GBNF grammar), and prompt caching. No cloud APIs, no telemetry, no phoning home.

---

## 🔒 Safety Features

- **CIDR scope enforcement** — only target authorized IP ranges
- **Blocked target list** — hardcoded blocks for 8.8.8.8, 1.1.1.1, 0.0.0.0
- **Confirmation gates** — destructive tools (hydra, sqlmap, msfvenom) require explicit approval
- **Hardened subprocess** — list-mode execution, injection pattern rejection, timeout SIGTERM→SIGKILL
- **Per-workflow sandboxes** — `tasks/<name>/<timestamp>/` with size limits and per-step state.json
- **Full audit trail** — every tool invocation logged with args, exit code, duration
- **Path traversal hardening** — all workflow-name API routes validate against realpath

---

## 📚 Documentation

| Doc | What it covers |
|-----|----------------|
| [SECURITY.md](SECURITY.md) | Disclosure policy, threat model, hardening inventory, safe-usage scope |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test conventions, code standards, PR process |
| [RELEASING.md](RELEASING.md) | Signed-release checklist: GPG signing, SHA256SUMS, tags, verification |
| [docs/AIRGAP.md](docs/AIRGAP.md) | Full air-gap story: wheels bundle, tool installer caches, embedded KB |
| [API.md](API.md) | All REST endpoints + WebSocket handlers |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Complete development timeline & architecture decisions |

---

## 📜 License

For authorized security testing only. Users are responsible for compliance with all applicable laws.