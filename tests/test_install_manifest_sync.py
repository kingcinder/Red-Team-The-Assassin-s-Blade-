"""
CI drift-check for the air-gap provisioning surface (single source of truth).

`core/install_manifest.py` is the single source of truth that reconciles the
two sets of external binaries the harness provisions against
`core/tool_registry.py`:

  * sudo'd helpers  — sourced from the command builders (sudo_helpers)
  * installable tools — sourced from the tool-installer recipes

This test fails CI if the components drift:

  * an install recipe key resolves to NO registered binary (a ghost tool the
    registry no longer exposes — typo, or a tool removed/renamed), or
  * the provisioning script regresses to a hardcoded copy of the surface
    instead of deriving it from install_manifest, or
  * a sudo'd helper the builders emit disappears from the surface.

This is the guard that a tool added to `core/tool_registry.py` is picked up by
both the sudo provisioning script and the CI environment matrix automatically.
"""
import os
import re
import sys

REPO = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, REPO)

from core.install_manifest import (  # noqa: E402
    installable_binaries,
    provisioning_binaries,
    registered_binaries,
    stale_recipe_keys,
    sudo_binaries,
)

SCRIPT = os.path.join(REPO, "setup", "configure_sudo_privileges.sh")


def _script_auto_derives():
    """True if the script actually calls core/install_manifest to derive."""
    with open(SCRIPT, encoding="utf-8") as fh:
        src = fh.read()
    return "install_manifest" in src and "sudo_binaries" in src


def test_script_derives_from_install_manifest():
    assert _script_auto_derives(), (
        "configure_sudo_privileges.sh no longer derives its helper set from "
        "core/install_manifest — a tool added to the registry won't be picked "
        "up by provisioning. Restore the single-source wiring."
    )


def test_no_stale_recipe_keys():
    """Every install recipe must resolve to a registered tool binary.

    A recipe whose key matches neither a registered binary nor a documented
    binary→key alias is a ghost entry. If CI fails here, either fix the recipe
    key or add/remove it — do NOT paper over it by editing this test.
    """
    stale = stale_recipe_keys()
    assert not stale, (
        "INSTALL_RECIPES has keys that resolve to no registered binary "
        f"(ghost tools): {stale}. Update the recipe key/alias in "
        "core/tool_installer.py or remove the stale recipe."
    )


def test_sudo_helpers_are_provisioned():
    """The script must provision every binary the builders inline-sudo."""
    derived = set(sudo_binaries())
    surface = set(provisioning_binaries())
    missing = derived - surface
    assert not missing, (
        f"sudo'd helper(s) missing from the provisioning surface: {sorted(missing)}"
    )


def test_core_surface_present():
    """Spot-check the derived surface includes representative helpers."""
    surface = set(provisioning_binaries())
    for probe in ("airmon-ng", "hcxdumptool", "wifite", "systemctl",
                  "apt-get", "hashcat", "subfinder"):
        assert probe in surface, f"expected provisioning binary missing: {probe}"


def test_installable_is_subset_of_registered():
    """Every installable binary the recipes cover must be a registered tool."""
    reg = set(registered_binaries())
    inst = set(installable_binaries())
    assert inst <= reg, f"installable binaries not in registry: {sorted(inst - reg)}"


if __name__ == "__main__":
    # CI runs `python3 tests/test_*.py` (plain-script runner).
    test_script_derives_from_install_manifest()
    test_no_stale_recipe_keys()
    test_sudo_helpers_are_provisioned()
    test_core_surface_present()
    test_installable_is_subset_of_registered()
    print("\n=== INSTALL-MANIFEST SYNC (CI drift check) PASSED ===")