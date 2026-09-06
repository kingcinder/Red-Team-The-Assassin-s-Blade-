"""
Single source of truth for the harness's air-gapped provisioning surface.

The harness references two parallel sets of external binaries:

  * **Sudo'd helpers** — binaries `core/command_builder.py` prefixes with
    "sudo", which `setup/configure_sudo_privileges.sh` grants NOPASSWD to so
    the cockpit's headless LLM can run them. Source of truth:
    `core/sudo_helpers.py` (``sudo_binaries()``).
  * **Installable tools** — binaries the tool installer can fetch when
    missing (`core/tool_installer.py` → ``INSTALL_RECIPES``). The recipes are
    keyed by recipe name, which is not always the binary the registry exposes,
    so lookups go through ``recipe_for()`` / ``has_recipe()``.

This module reconciles *both* against `core/tool_registry.py` — the canonical
list of every tool the harness knows about — so a tool added to the registry
is automatically visible to the sudo provisioning script, the CI environment
matrix, and the installer recipe sync check. It never owns a copy of the
lists; it *derives* them, so drift is impossible by construction:

  * ``registered_binaries()`` — every non-empty binary the registry exposes.
  * ``installable_binaries()`` — registered binaries that have an install
    recipe regardless of recipe-key naming (alias-aware).
  * ``stale_recipe_keys()``    — recipe keys that resolve to NO registered
    binary (typo, or a tool that was removed from the registry but whose
    recipe lingers). CI fails on these.
  * ``provisioning_binaries()`` — union of sudo'd helpers + installable tools
    (the full external-binary surface an air-gapped box must provision).
"""
import os
import sys

# Set the source of truth for registered binaries at call time so the manifest
# always reflects the live registry even if tools are added programmatically.
def registered_binaries():
    """Sorted set of every non-empty binary the tool registry exposes."""
    from core.tool_registry import ToolRegistry
    reg = ToolRegistry({})
    return sorted({t.binary for t in reg.get_all_tools().values() if t.binary})


def installable_binaries():
    """Registered binaries that have an install recipe (alias-aware)."""
    from core.tool_installer import recipe_for
    reg_bins = registered_binaries()
    return sorted(b for b in reg_bins if recipe_for(b))


def stale_recipe_keys():
    """Recipe keys that do not resolve to any registered binary.

    A recipe whose key matches neither a registered binary nor a documented
    binary→key alias is a stale entry: the tool it would install was removed
    or renamed in the registry. tests/test_install_manifest_sync.py fails CI
    on these so the recipe table can never silently reference a ghost tool.
    """
    from core.tool_installer import INSTALL_RECIPES, RECIPE_BINARY_ALIASES
    reg_bins = set(registered_binaries())
    recipe_keys = set(INSTALL_RECIPES.keys())
    # A recipe key is valid if it IS a registered binary, or if it's the
    # lookup target (value) of a binary→key alias (e.g. recipe key
    # "proxychains4" is reached from registered binary "proxychains").
    aliased = set(RECIPE_BINARY_ALIASES.values())
    valid = {k for k in recipe_keys if k in reg_bins or k in aliased}
    return sorted(recipe_keys - valid)


def sudo_binaries():
    """Sudo'd helper binaries, re-exported so the provisioning script and CI
    consume one module (install_manifest) for the whole external-binary
    surface instead of importing core.sudo_helpers directly."""
    from core.sudo_helpers import sudo_binaries as _sudo_binaries
    return _sudo_binaries()


def provisioning_binaries():
    """Union of sudo'd helpers + installable tools — the full air-gap surface.

    A binary that must exist on a provisioned host is either something the
    harness runs with sudo (sourced from the builders via sudo_helpers) or
    something the installer can fetch when missing (sourced from the recipes).

    Note: this manifest only *derives* what is already registered + reciped.
    A brand-new tool added to the registry still needs a hand-written install
    recipe (its repo/package/method cannot be derived from the registry), and
    a sudo'd helper must flow through a builder — this module reconciles and
    guards those sources; it cannot conjure recipe content.
    """
    return sorted(set(sudo_binaries()) | set(installable_binaries()))


if __name__ == "__main__":
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    for b in provisioning_binaries():
        print(b)