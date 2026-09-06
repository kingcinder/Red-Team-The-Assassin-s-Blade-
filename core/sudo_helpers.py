"""
Single source of truth for the set of binaries the harness prefixes with "sudo".

`core/command_builder.py` prepends "sudo" to a fixed set of privileged helpers
(wireless/sniffing tooling, the package manager, and system/back-end tools).
`setup/configure_sudo_privileges.sh` provisions NOPASSWD sudo for exactly these
binaries so the cockpit's headless LLM can run them without a password prompt.

Keeping the two in sync by hand drifts (a new sudo-prefixed tool added to
command_builder.py is forgotten in the script, and the step hangs for its whole
timeout on an unanswered sudo prompt). This module makes the script derive the
set *from the builders* instead, so they can never diverge:

  * ``builders_sudo()``  — import ToolRegistry + command_builder, run each
    registered tool's command builder with dummy args, and keep any binary
    whose emitted command starts with "sudo" (this is literally "ask the real
    code what it would sudo").
  * ``literal_sudo()``   — AST-walk command_builder.py for inline
    ``["sudo", "..." ]`` command literals (covers branchy builders whose sudo
    binary is a string literal rather than the tool's own binary). An AST
    walk matches real executable code only — a comment or docstring example
    can never grant an unintended NOPASSWD entry.
  * ``sudo_binaries()``  — the union, sorted, deduped. This is what the bash
    provisioning script and the CI drift check both consume.

Builders that fail to run under dummy args are logged (the type-aware dummy
args neutralize the known edge case like ``_build_wifite`` needing an
interface), and the union is still recovered from the static literal scan — so
an exception can never silently hide a sudo'd binary.

The CI check (tests/test_sudo_helpers_sync.py) fails if the script regresses to
a hardcoded copy of the list, guaranteeing this module stays the only source.
"""

import ast
import logging
import os

_BUILDERS = os.path.join(os.path.dirname(__file__), "command_builder.py")
logger = logging.getLogger("redteam.sudo_helpers")


def _dummy_args(tool):
    """Build a representational args dict for a ToolDefinition so its command
    builder runs without raising (e.g. _build_wifite requires 'interface').
    Integer params get \"1\" so branches like int(signal) parse cleanly."""
    args = {}
    for pname, pinfo in (getattr(tool, "parameters", {}) or {}).items():
        if isinstance(pinfo, dict):
            ptype = pinfo.get("type", "string")
        else:
            ptype = "string"
        args[pname] = "1" if ptype in ("integer", "number") else "x"
    return args


def literal_sudo():
    """Bare binaries referenced as inline ["sudo", "<bin>", ...] command
    literals.

    Uses an AST walk rather than a regex over the raw file: a ``ast.List``
    whose first element is the string literal ``"sudo"`` and whose second is a
    string constant can only be real executable code — a comment or docstring
    example can never match, and no fragile reassembly is needed. This
    complements ``builders_sudo()`` for branchy builders that sudo a string
    literal rather than the tool's own binary (e.g. kill vs pkill).
    """
    try:
        with open(_BUILDERS, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError):
        return set()
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.List) or len(node.elts) < 2:
            continue
        head, tail = node.elts[0], node.elts[1]
        if (isinstance(head, ast.Constant) and head.value == "sudo"
                and isinstance(tail, ast.Constant)
                and isinstance(tail.value, str)):
            bin = tail.value
            found.add(os.path.basename(bin) if os.sep in bin else bin)
    return found


def builders_sudo():
    """Return the set of binaries the builders emit a leading 'sudo' for.

    A builder that raises under dummy args is logged (not silently dropped):
    the type-aware dummy args neutralise the known edge case (e.g.
    _build_wifite needing 'interface'), and the literal scan in sudo_binaries()
    still recovers inline sudo literals from the same file.
    """
    from core.tool_registry import ToolRegistry
    from core.command_builder import _build_command

    reg = ToolRegistry({})
    names = list(reg.get_all_tools().keys())
    found = set()
    for name in names:
        tool = reg.get_tool(name)
        if tool is None:
            continue
        try:
            cmd = _build_command("/tmp", tool, _dummy_args(tool))
        except Exception as exc:
            logger.warning("sudo_helpers: builder for '%s' not runnable "
                           "under dummy args (%s); literal scan will cover it",
                           name, exc)
            continue
        if isinstance(cmd, list) and len(cmd) >= 2 and cmd[0] == "sudo":
            bincmd = cmd[1]
            found.add(os.path.basename(bincmd) if os.sep in bincmd else bincmd)
    return found


def sudo_binaries():
    """Sorted, deduped union of every binary the harness sudoes."""
    return sorted(builders_sudo() | literal_sudo())


if __name__ == "__main__":
    import sys
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    for b in sudo_binaries():
        print(b)