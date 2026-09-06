# Serpent Circle Design Audit

## Scope
The repository is a Python Flask/Socket.IO harness with a browser cockpit, YAML workflow templates, a command-builder/tool registry, and a llama-server backend.

## Measured state
- 104 Python files, 2 JavaScript files, 32 YAML files, and 3 shell scripts.
- Existing worktree contains 44 user changes; those changes are treated as pre-existing and are not rewritten by this audit.
- 30 workflow templates are present.
- Generated `__pycache__` artifacts were removed.
- `wheels/gevent-26.8.0-cp312-cp312-manylinux_2_28_x86_64.whl` is a large intentional dependency artifact and remains in place.

## Priority findings
1. Preserve the existing registry → command builder → subprocess seam; it is explicit and testable.
2. Preserve the workflow engine's state/checkpoint seam; validate malformed templates at the boundary.
3. Preserve the dashboard's API-driven interface and metadata flow; avoid duplicating server state in the browser.
4. Keep llama-server request normalization and tool-call parsing localized in the LLM backend/orchestrator seam.

## Performance audit
No performance rewrite is justified without a representative workload. Python execution is dominated by subprocess and LLM/network I/O; browser code is dashboard rendering and polling. No profiler evidence supports changing those paths in this cleanup pass.

## Decision
No speculative architecture or performance changes. The only verified cleanup is removal of generated cache artifacts and documentation of the measured state. Further code changes require a reproducible failing behavior or benchmark.
