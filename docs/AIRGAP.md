# 🔒 Air-Gap Deployment — RedTeam Harness (Assassin's Blade)

The harness is designed to be **100% operational on a host with zero internet
connectivity** — from first boot to a completed engagement. Every component
either ships embedded, is pre-bundled by you, or talks only to localhost.

This document is the full story: what needs what, how to move the bundle, and
how to verify an air-gapped deployment.

---

## 1. The offline matrix

| Component | Offline strategy | Details |
|-----------|------------------|---------|
| **Python dependencies** | Pre-downloaded `wheels/` bundle | `pip3 download -r requirements.txt -d ./wheels` on a connected host; `install.sh` installs with `--no-index --find-links` |
| **LLM backend** | Runs locally | llama-server on `127.0.0.1:8080` or Ollama on `127.0.0.1:11434` — never a cloud API |
| **Kali security tools** | Native host tools + offline installer | See §3 — `core/tool_installer.py` caches apt/pip/Go/manual downloads for reuse |
| **CVE / ATT&CK knowledge** | Embedded in `core/knowledge_base.py` | ~37 CVEs, 74 ATT&CK techniques, exploit signatures, remediation playbooks — all in the source file, zero network |
| **Vector memory** | Local JSON/embeddings | `core/vector_memory.py` persists findings on-disk |
| **Dashboard** | Fully static assets | No CDNs, no web fonts, no external JS — system font stack |
| **Telemetry** | **None** | The harness never phones home. No analytics, no update checks, no cloud calls |

---

## 2. Building the bundle (on a connected host)

```bash
# From the repo root:
rm -rf wheels && mkdir -p wheels
pip3 download -r requirements.txt -d ./wheels

# Regenerate the integrity manifest
find . -name '*.py' -not -path './.git/*' -not -path '*/__pycache__/*' \
  -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
ls wheels/*.whl | xargs sha256sum >> SHA256SUMS

# If releasing (optional but recommended): sign it
gpg --detach-sign --armor --output SHA256SUMS.asc SHA256SUMS
```

**The bundle is the entire repo directory** — source, `wheels/`, `SHA256SUMS`.
It fits on a USB stick (wheels are ~10 MB).

---

## 3. Transferring to the air-gapped host

```bash
# Copy the WHOLE directory (preserve permissions + symlinks)
rsync -av --exclude='.git' --exclude='__pycache__' \
  ./redteam-harness/ operator@airgap-host:/opt/redteam-harness/
```

> ⚠️ Copy the directory **including `wheels/`**. Missing wheels = the installer
> falls back to network pip, which defeats the purpose.

### On the air-gapped host

```bash
cd /opt/redteam-harness

# 1. Integrity check (manifest, if you shipped one)
sha256sum -c SHA256SUMS --quiet && echo "files intact"    # + gpg --verify if signed

# 2. Install — picks up ./wheels automatically, no internet needed
bash install.sh

# 3. Full self-check
bash install.sh --verify        # wheels count, no sdists, py_compile, SHA256SUMS

# 4. Boot
python3 harness.py              # dashboard on http://localhost:9999
```

---

## 4. The tool installer (mid-engagement, offline)

`core/tool_installer.py` lets the LLM fetch and install missing Kali tools
during an engagement — with all downloads **cached locally** for reuse:

```
~/.cache/redteam-harness/
├── apt/            # .deb packages (apt-get download)
├── go-binaries/    # Go-built binaries from GitHub releases
├── pip-wheels/     # pip packages
└── manual/         # script/binary downloads
```

**Air-gap procedure:**

1. On a connected host, warm the cache:
   `python3 harness.py --check` lists missing tools; pre-download what you'll
   need, or run the installer once per tool to populate the cache.
2. Copy `~/.cache/redteam-harness/` to the air-gapped host (same path).
3. The installer reuses cached artifacts — it never *needs* the network if the
   artifact is present.

Installed binaries land in `~/.local/bin` (on PATH).

---

## 5. The embedded knowledge base

`core/knowledge_base.py` ships the entire offline corpus **in the source**:

- **37 curated CVEs** (Log4Shell, EternalBlue, BlueKeep, ProxyLogon, Dirty Pipe,
  PrintNightmare, regreSSHion, xz backdoor, …) with severity, affected
  software, exploit signatures, remediation steps + shell commands
- **74 MITRE ATT&CK techniques** across all 14 enterprise tactics, with
  detection + mitigation guidance
- **106+ exploit signatures** (regex) compiled at import for instant grounding

`KnowledgeBase()` builds a TF-IDF retrieval index in memory (sklearn when
present, pure-stdlib keyword fallback otherwise) — **no downloads, no updates,
no network**. The LLM grounds exploit suggestions and remediation steps in this
verified corpus during engagements.

> New CVEs ship with the next release — the KB is deliberately versioned with
> the code, not fetched at runtime.

---

## 6. The LLM backend (local-only)

The harness talks exclusively to loopback:

```yaml
# config.yaml
llm:
  backend: llama-server        # or ollama
  base_url: http://127.0.0.1:8080   # llama-server (OpenAI-compatible)
  # ollama → http://127.0.0.1:11434
```

Start it on the air-gapped host from local models. The `launch-gguf.sh`
launcher in this machine's home directory (outside the repo) boots a local
GGUF via llama-server — any equivalent llama-server/Ollama launch script
works. Both backends support streaming, JSON/GBNF schema enforcement, and
prompt caching.

---

## 7. Verification checklist (post-deploy)

- [ ] `sha256sum -c SHA256SUMS --quiet` passes (manifest present)
- [ ] `bash install.sh --verify` → "All verification checks passed — air-gap ready"
- [ ] `python3 harness.py --check` lists expected tools, no network errors
- [ ] `curl -s http://127.0.0.1:9999/` serves the dashboard from local assets
- [ ] LLM backend responds on its loopback URL (no cloud)
- [ ] `getent hosts` never contacted: firewall-deny outbound, harness still runs
