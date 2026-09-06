# Serpent Circle — chain plan (REAL RUN)

Generated: 2026-08-28T02:12:59.812710+00:00
Target repo: `/home/cody/Documents/redteam-harness`
Mode: REAL RUN — the chain executes for real upon invocation; commit and push are part of the run.

## Stage 1 — Brainstorm (architecture + performance)
Chains: improve-codebase-architecture → python-performance-optimization →
multi-language perf audit → synthesize.

1. Run improve-codebase-architecture over the repo; capture the deepening-opportunities report.
2. Profile Python hot paths (cProfile / memory profilers) per python-performance-optimization.
3. Audit every non-Python language below per references/perf-optimization.md.
4. Synthesize into the most powerful/elegant/effective form.
Output: `01-design/design.md` — feeds Stage 2.

### Languages detected
104  python
    50  json
    40  other
    32  yaml
     9  markdown
     3  shell
     2  javascript
     1  css
     1  html

## Stage 2 — writing-plans
Consumes: `01-design/design.md`. Produces a step-by-step plan with review
checkpoints: `02-plan/plan.md`. Feeds Stage 3.

## Stage 3 — executing-plans
Consumes: `02-plan/plan.md`. Executes with checkpoints; validates against the
repo's own gates (test suites / typechecks / lints). Feeds Stage 4.

## Stage 4 — systematic-debugging
Consumes: failing tests / regressions from Stage 3. Root-cause each failure
(reproduce → isolate → fix → verify). Feeds Stage 5.

## Stage 5 — Cleanup
Dead code, bloat, and tidying per the candidate scan below; document every
change in the repo docs (README / BUGFIX_HISTORY). Output: `05-cleanup/CHANGES.md`.
Feeds Stage 6.

### Bloat / dead-code candidates
--- dead/legacy dirs ---
--- backup / junk files ---
workflows/templates/__pycache__/__init__.cpython-312.pyc
dashboard/blueprints/__pycache__/msf.cpython-312.pyc
dashboard/blueprints/__pycache__/core.cpython-312.pyc
dashboard/blueprints/__pycache__/replay.cpython-312.pyc
dashboard/blueprints/__pycache__/workflows.cpython-312.pyc
dashboard/blueprints/__pycache__/campaigns.cpython-312.pyc
dashboard/blueprints/__pycache__/__init__.cpython-312.pyc
dashboard/blueprints/__pycache__/memory_kb.cpython-312.pyc
--- empty files ---
--- duplicate-name copies ---
--- oversized files (>1MB) ---
wheels/gevent-26.8.0-cp312-cp312-manylinux_2_28_x86_64.whl

## Stage 6 — Commit + push
Consumes: the tidy working tree. Conventional commit; push proceeds to the
configured remote as part of the real run (the invocation is the standing
authorization). If no remote exists, stop after the commit and report.
--dry-run never pushes.
