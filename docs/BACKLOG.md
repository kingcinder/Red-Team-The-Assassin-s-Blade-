# 🗃️ Backlog — RedTeam Harness (Assassin's Blade)

Ideas explicitly deferred from shipped work, with reasons. This file is the
bucket the v7.0 Mech-Unit manifest promises for anything that is *not* the
current plan (`docs/MECH_UNIT_REFACTOR_MANIFEST.md` §5: "new ideas go to
`docs/BACKLOG.md`, not this plan").

Nothing here is scheduled. Entries graduate to a plan only when an operator
picks them up.

---

## v8 candidates (named by the v7.0 manifest)

- **Multi-radio orchestrated attacks** — v7 explicitly targets one adapter
  at a time (manifest §2 Non-Goals). Multi-adapter coordination (monitor +
  injection on separate radios, parallel capture across channels) is the
  natural v8 capability.
- **Mesh / distributed deployment** — multiple harness nodes cooperating on
  one engagement (shared plan state, distributed captures).

## Deferred with reasons (Serpent Circle, 2026-09-08)

- **Legacy `core/` restructuring** — the flat 36-module namespace
  (`orchestrator.py`, `autonomous.py`, `tactics.py`, …) is the established
  design; v7.0 manifest §2 keeps it; structural rewrites need operator
  consent and a large blast radius for no measured gain.
- **Dashboard JS framework migration** — repo decision register #4 stands:
  vanilla JS + SocketIO, no build step, no CDN.
- **LLM advisor expansion** — the advisory path (`core/mech/advisors.py`) is
  already bounded and sanitized; the zero-LLM default stands. Deeper advisor
  capability needs an operator decision on backend requirements.
- **First-compile manifest parse cache** — the parse-once-per-instance
  behavior is correct; a process-wide cache would only matter for
  multi-tenant use, which this repo doesn't have.

## Funnels from future circles

As later Serpent Circle runs defer work, entries land here with a date and
reason. See `docs/superpowers/plans/` for executed plans.