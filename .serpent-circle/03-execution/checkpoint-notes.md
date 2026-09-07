# Execution Checkpoints

- Generated cache cleanup completed.
- Focused validation passed: 38 tests.
- Compile check passed.

## v7.0 Mech-Unit — P0–P6 executed (2026-09-06)

- Baseline: 44 pre-existing v6.x dirty files committed as `ba020bb` (operator-authorized).
- P1: `core/mech/` intents, probes, resolver, compiler, state, events — 68 tests green.
- P2: executor (hardened tool path only), 6 wireless manifests in `attacks/`,
  vuln_graph loader/scorer, MechUnit facade, `--mech` CLI (list/probe/compile/run/
  resume/status/next-moves) — Gate P2 green, no-LLM compile `runnable: true`.
- P3: TACTICAL_RULES upgraded with graph fields (old keys intact), scoring +
  cycle detection + explanations, 6 network/host/web manifests, cross-domain
  edges + ATT&CK refs — Gate P3 green (113 mech + 310 legacy).
- P4: `dashboard/blueprints/mech.py` (12 routes) + SocketIO relay, cockpit
  Mech-Unit tab (TARGETS → INTENT WALL → RUN CONSOLE), API.md section 16 — Gate P4 green.
- P5: advisors.py (feature-flagged OFF, bounded 512-token, sanitized), config
  `mech:` section + `mode: mech` shipped default, autonomous bridge behind
  explicit mode flag (legacy path untouched, class-level defaults keep
  `__new__`-built test agents working), README/DEVELOPMENT/SECURITY docs — Gate P5 green.
- P6: audit-trail parity, SECURITY threat-model rows, air-gap unchanged,
  `scripts/validate_mech_manifests.py` green, full verification matrix
  441/441, secret scan CLEAN.
- Release prep done: docs version-bumped to v7.0.0 (DEVELOPMENT header + PART 1
  timeline entry, API.md, README). Tag v7.0.0 / push / SHA256SUMS+sign left to
  operator (needs gpg key + network, per RELEASING.md).
- Cleaned (operator-approved): 6 pre-existing dead imports in v6.x code
  (`hardening.py:re`, `model_manager.py:json,Path`, `prompt_builder.py:os`,
  `auth.py:g`, `generate_manifest.py:hashlib` removed;
  `vector_memory.py` future-import kept with `# noqa` marker — it is
  load-bearing for lazily-imported `np`/`TfidfVectorizer` annotations, not a
  true dead import). RELEASING dead-code sweep now prints CLEAN repo-wide.
- Still open: `rockyou.txt` (~133 MB, wordlists/) was folded into baseline
  `ba020bb` — flag if the repo should stop tracking it (gitignore + filter-branch).
- Whole v7.0 delta committed per operator choice.
