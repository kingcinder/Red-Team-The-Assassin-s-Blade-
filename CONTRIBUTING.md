# 🤝 Contributing — RedTeam Harness (Assassin's Blade)

Thanks for wanting to make the harness sharper. This guide covers setup,
conventions, testing, and the PR process.

---

## Quick Start (development)

```bash
# 1. Clone + install deps (offline-friendly — uses ./wheels if present)
git clone git@github.com:kingcinder/Red-Team-The-Assassin-s-Blade-.git
cd Red-Team-The-Assassin-s-Blade-
mkdir -p wheels
pip3 download -r requirements.txt -d ./wheels   # only needed on a connected host
bash install.sh                                  # picks wheels automatically

# 2. Run the full verification (the same gates CI / maintainers use)
python3 tests/smoke_imports.py
for t in tests/test_*.py; do python3 "$t" || echo "FAIL $t"; done
node --check dashboard/static/js/cockpit.js
```

Requirements: **Python 3.10+**, **Node.js** (for the JS syntax gate), the
offline wheels in `./wheels/` (or network access once).

---

## Test Conventions

The suite is **17 standalone test files** — each is a runnable script, no
pytest required:

```bash
python3 tests/test_knowledge_base.py     # offline KB: lookup/retrieval/grounding
python3 tests/test_injection_defense.py  # 50+ adversarial sanitization vectors
python3 tests/test_correlation_v5.py     # attack paths, remediation, ATT&CK
python3 tests/test_attack_matrix.py      # tactic×technique heatmap
python3 tests/test_workflow_chaining.py  # auto-workflow generation + chaining
python3 tests/test_tool_scorer.py        # reliability scoring (deadlock-guarded)
# ... plus 10 more covering campaigns, replay, parallel exec, prioritizers
```

**Rules:**

1. **Every feature ships with a test.** New module → new `tests/test_<module>.py`.
   New behavior in an existing module → extend its suite.
2. **Tests must be hermetic** — no network, no real LLM, no mutating the
   operator's environment beyond temp dirs (use `tempfile`).
3. **The full set must pass before merge**, plus:
   - `python3 -c "import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('core/*.py')+glob.glob('dashboard/*.py')+glob.glob('tools/*.py')]"`
   - `node --check dashboard/static/js/cockpit.js`
4. **No bare `except:`** — always `except Exception as e:` with a log line.
5. **No dead imports** — the reviewer will reject unused `from typing import ...`
   leftovers. Run the AST sweep from `RELEASING.md` before submitting.

---

## Code Standards

- **Style**: PEP 8, 4-space indent, `"""` docstrings on every public
  class/function. Match the surrounding module's voice (this repo documents
  heavily — keep it that way).
- **Logging**: use the module logger (`logger = logging.getLogger("redteam.<mod>")`),
  never `print()` in `core/`.
- **Type hints**: use `typing.Dict/List/Optional/Any` (stdlib; no pydantic).
  Remove any hint you don't actually use.
- **Offline-only**: no network imports (`requests` is allowed *only* in
  `core/tool_installer.py` for the optional installer path — everything else
  must work air-gapped).
- **Injection discipline**: any string that can be influenced by tool output or
  remote hosts MUST pass through `core/injection_defense.sanitize_tool_output()`
  before reaching the LLM. This is the #1 review focus.

### Adding a tool

1. Add the definition to the relevant `tools/<category>.py` module
   (`name`, `description`, `args_template`, `category`).
2. Register it in `core/tool_registry.py`'s category table.
3. Add a test that runs the tool's `--help`/`--check` path (not a live target).

### Adding a workflow template

1. Create `workflows/templates/<name>.yaml` following the schema in
   `core/workflow_engine.py` (steps, gates, extracts, chaining).
2. Run the mock-validator: `python3 harness.py --workflow <name> --check`.
3. Add a test that loads + validates the template.

---

## Pull Request Process

1. **Branch from `main`** — `git checkout -b feat/your-change`.
2. Make your change with tests (see above).
3. Run the full gate (tests + compile + JS) locally.
4. Push and open a PR with a clear description:
   - What + why (one short paragraph each)
   - How it was tested
   - Any behavior changes an operator should know about
5. **CI will re-run the full suite.** The reviewer may request fixes —
   address them, don't dismiss.
6. Squash-merge with a conventional message
   (`feat:`, `fix:`, `chore:`, `test:`, `docs:`, `perf:`).

### Review checklist (for maintainers)

- [ ] New/changed behavior is test-covered
- [ ] No bare excepts, no dead imports, no debug prints
- [ ] All LLM-facing text sanitized via `injection_defense`
- [ ] Tool args run in list mode; no `shell=True`
- [ ] Offline guarantee preserved (no new hard network deps)
- [ ] Full suite + compile + JS gates pass

---

## Commit Hygiene

Follow the existing history style:

```text
feat: add <capability>
fix: correct <bug>
perf: speed up <hot path>
test: add coverage for <module>
chore: housekeeping — <details>
docs: document <subject>
```

Include a `Generated with Codebuff 🤖 / Co-Authored-By` footer only when the
work was AI-assisted (as past commits do).
