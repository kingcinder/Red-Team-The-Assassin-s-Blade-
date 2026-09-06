"""
CI drift-check for the passwordless-sudo provisioning surface.

`core/sudo_helpers.py` is the single source of truth for the binaries the
harness prefixes with "sudo". `setup/configure_sudo_privileges.sh` derives its
HELPERS set from it. This test fails CI if:

  * the script ever regresses to a hardcoded copy of the list (the auto-derive
    wiring is missing), or
  * the script's curated FALLBACK_HELPERS falls out of sync with the builders
    (a tool removed/renamed in command_builder.py but still listed, or a list
    entry that no longer resolves to a real sudo'd binary), or
  * a builder stopped producing its expected sudo binary.

This is the regression guard for the live-run bug where `wifite` was missing
from the provisioning list — a new sudo-prefixed tool must never again be
forgotten.
"""

import os
import re
import sys

REPO = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, REPO)
from core.sudo_helpers import sudo_binaries  # noqa: E402

SCRIPT = os.path.join(REPO, "setup", "configure_sudo_privileges.sh")


def _extract_fallback_helpers():
    """Parse FALLBACK_HELPERS=( ... ) out of the provisioning script.

    Parsed line-by-line (not with `(.*?)`) so a `)` inside a trailing
    comment like `(v6.x system category)` can't truncate the capture.
    """
    with open(SCRIPT, encoding="utf-8") as fh:
        src = fh.read()
    start = src.find("FALLBACK_HELPERS=(")
    assert start != -1, "FALLBACK_HELPERS=() not found in configure_sudo_privileges.sh"
    body = src[start:].split("\n", 1)[1]
    lines = body.split("\n")
    items = []
    for ln in lines:
        if re.match(r"^\s*\)", ln):
            break
        # drop bash comments, split on whitespace
        items.extend(re.sub(r"#.*", "", ln).split())
    return items


def _script_auto_derives():
    """True if the script actually calls core/sudo_helpers for HELPERS."""
    with open(SCRIPT, encoding="utf-8") as fh:
        src = fh.read()
    return "sudo_binaries" in src or "sudo_helpers" in src


def test_script_derives_from_sudo_helpers():
    assert _script_auto_derives(), (
        "configure_sudo_privileges.sh no longer calls core/sudo_helpers to "
        "derive its helper list — check that the single-source wiring is intact."
    )


def test_fallback_is_subset_of_builder_sudo():
    """FALLBACK_HELPERS must not list binaries the builders no longer 'sudo'.

    This is intentionally ONE-directional (fallback ⊆ derived), not symmetric:
    a NEW sudo-prefixed tool added to command_builder.py is picked up
    automatically at runtime by the script's derivation, so it does NOT need to
    (and should NOT) be hand-added to the fallback. Requiring the reverse would
    force a manual fallback edit for every new tool — reintroducing exactly the
    drift this feature exists to kill.
    """
    derived = set(sudo_binaries())
    fallback = set(_extract_fallback_helpers())
    extra = fallback - derived
    assert not extra, (
        "FALLBACK_HELPERS lists binaries the builders no longer 'sudo': "
        f"{sorted(extra)}. Remove them so the builders stay the only source."
    )


def test_core_helpers_present():
    derived = set(sudo_binaries())
    for core in ("airmon-ng", "airodump-ng", "hcxdumptool", "wifite",
                 "reaver", "aireplay-ng", "tcpdump", "systemctl",
                 "iptables", "apt-get"):
        assert core in derived, f"expected sudo'd helper missing: {core}"


def test_script_resolves_paths_with_type_P():
    """The script must resolve helper paths with `type -P`, never `command -v`.

    Regression guard for a live bug: `command -v kill` returns the bare
    builtin name "kill" (no slash), which is invalid in sudoers and made
    visudo reject the drop-in on every run. `type -P` (bash, PATH-only)
    skips builtins/aliases/functions and returns an absolute path, so the
    drop-in always contains absolute commands.
    """
    with open(SCRIPT, encoding="utf-8") as fh:
        src = fh.read()
    # Scan only real code, not prose: strip comments (and blank lines) the
    # same way _extract_fallback_helpers does, so an explanatory comment that
    # mentions `command -v` can't trip the check.
    code_only = "\n".join(
        re.sub(r"#.*", "", ln) for ln in src.split("\n") if ln.strip()
    )
    # resolve_binary must use type -P, and the code must not fall back to
    # command -v for helper/path resolution anywhere.
    assert re.search(r"resolve_binary\(\)[^{]*\{[^{}]*type -P", code_only), (
        "resolve_binary() must use `type -P` to avoid builtin bare-name paths."
    )
    assert "command -v" not in code_only, (
        "configure_sudo_privileges.sh must not use `command -v` for path "
        "resolution — a bash builtin (e.g. kill) resolves to a bare name that "
        "visudo rejects. Use `type -P`."
    )


if __name__ == "__main__":
    # CI runs `python3 tests/test_*.py` (plain-script runner).
    test_script_derives_from_sudo_helpers()
    test_fallback_is_subset_of_builder_sudo()
    test_core_helpers_present()
    test_script_resolves_paths_with_type_P()
    print("\n=== SUDO-HELPERS SYNC (CI drift check) PASSED ===")