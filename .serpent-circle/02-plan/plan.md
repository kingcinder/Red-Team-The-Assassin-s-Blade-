# Renovation Plan

1. Inventory repository state and changed ownership.
2. Remove generated Python cache artifacts only.
3. Run focused tests for command construction, interfaces, autonomous boundaries, workflows, and llama compatibility.
4. Run the full test suite and compile checks.
5. Record results and leave unrelated user changes untouched.

## Checkpoints
- After cleanup: no project `__pycache__` directories remain.
- After validation: focused and full tests pass.
- Before handoff: `git diff --check` passes and no unrelated source files are changed by this pass.
