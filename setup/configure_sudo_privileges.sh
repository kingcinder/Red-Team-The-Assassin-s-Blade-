#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — Passwordless sudo provisioning (baked-in root)
# Grants the harness's privileged helpers NOPASSWD sudo so the LLM
# driving the cockpit can run wireless/sniffing/install tools without
# an interactive password prompt (headless subprocess = no TTY, so an
# unanswered sudo prompt would otherwise block every privileged call).
#
#   Scoped least-privilege: only the exact binaries the harness already
#   prefixes with "sudo" (command_builder.py + tool_installer.py) gain
#   passwordless root. Everything else still prompts as usual.
#
#   ⚠ Caveat: NOPASSWD on interactive-capable binaries such as tcpdump,
#   bettercap and apt-get/dpkg is *effectively* full root (e.g. `tcpdump -w
#   /etc/sudoers`, `dpkg` hooks, `apt` scripts). This is intended for an
#   unrestricted pentest cockpit whose SafetyEngine is a pass-through — but
#   do not treat it as true least-privilege isolation.
#
# Usage:
#   sudo bash setup/configure_sudo_privileges.sh [username] [--apply|--verify|--remove]
#     (no arg / --apply)  idempotently install the NOPASSWD drop-in
#     --verify            show current drop-in + dry-run validity
#     --remove            remove the drop-in we installed
#   Run ONCE as any sudoer. Idempotent: safe to run again.
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

DROPIN="/etc/sudoers.d/redteam-harness"
MARKER="redteam-harness"

# ── Parse mode (anywhere) + resolve the real user (SUDO_USER survives root) ──
MODE="--apply"
ARGS=()
for a in "$@"; do
    case "$a" in
        --apply|--verify|--remove) MODE="$a" ;;
        --*) echo "✗ Unknown flag: $a" >&2; exit 2 ;;
        *) ARGS+=("$a") ;;
    esac
done
if [[ ${#ARGS[@]} -ge 1 ]]; then
    USER_NAME="${ARGS[0]}"
else
    USER_NAME="${SUDO_USER:-${USER:-}}"
fi
# If the single positional arg was the invoking user only (no explicit mode),
# ensure a bare username defaults to --apply as before.
USER_NAME="$(echo "$USER_NAME" | xargs)"  # trim
if [[ -z "$USER_NAME" || "$USER_NAME" == "root" ]]; then
    echo "✗ Cannot bind passwordless sudo to user '${USER_NAME:-<empty>}'." >&2
    echo "  Usage: sudo bash setup/configure_sudo_privileges.sh <username>" >&2
    exit 1
fi
if ! id "$USER_NAME" >/dev/null 2>&1; then
    echo "✗ No such user: $USER_NAME" >&2
    exit 1
fi

# ── We must be root to write /etc/sudoers.d ──
if [[ "$(id -u)" -ne 0 ]]; then
    echo "✗ Must run with sudo:  sudo bash setup/configure_sudo_privileges.sh $USER_NAME $MODE" >&2
    exit 1
fi

# ── The helper binaries the harness prefixes with "sudo" ──
# Derived automatically from the command builders + tool-installer recipes via
# core/install_manifest (itself the single source of truth over
# core/command_builder.py, core/tool_installer.py and core/tool_registry.py),
# so a NEW sudo-prefixed or installable tool added to the registry is picked
# up with no manual edit here. FALLBACK_HELPERS below is the documented set
# used only when the derivation can't run in this environment;
# tests/test_sudo_helpers_sync.py + tests/test_install_manifest_sync.py fail CI
# if the code and the provisioning list ever drift.
FALLBACK_HELPERS=(
    tcpdump airodump-ng aireplay-ng airmon-ng
    reaver hcxdumptool wifite tshark bettercap ettercap
    # system/backend-manipulation tools invoked with sudo (v6.x system category)
    systemctl ip sysctl iptables hostnamectl chown kill pkill
)
# Package manager (tool_installer.py uses sudo apt-get / sudo dpkg)
PKG_TOOLS=()
for b in apt-get dpkg apt; do type -P "$b" >/dev/null 2>&1 && PKG_TOOLS+=("$b"); done

# ── Derive HELPER NAMES from the command builders (single source of truth) ──
HELPERS=()
_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
if [[ -n "$_REPO_ROOT" ]] && \
   _derived="$(cd "$_REPO_ROOT" 2>/dev/null && python3 -c 'import sys; sys.path.insert(0, ".");
from core.install_manifest import sudo_binaries
print(" ".join(sudo_binaries()))' 2>/dev/null)" && [[ -n "$_derived" ]]; then
    read -r -a HELPERS <<< "$_derived"
elif [[ -n "$_REPO_ROOT" ]]; then
    # Derivation unavailable (missing deps / odd env): fall back to the curated
    # list, but the CI drift check still guards against staleness.
    echo "  ⚠ install_manifest derivation failed — using FALLBACK_HELPERS" >&2
    read -r -a HELPERS <<< "${FALLBACK_HELPERS[*]}"
fi

resolve_binary() {
    # return absolute path for a binary name, or empty if absent.
    # Use `type -P` (bash, PATH-only) rather than `command -v`: for a bash
    # builtin like `kill` or `pwd`, `command -v` prints the bare name (no
    # slash), which is invalid in sudoers — a bare command is rejected by
    # visudo. `type -P` skips builtins/aliases/functions and returns only the
    # executable path, so sudoers always gets an absolute path.
    local pth; pth="$(type -P "$1" 2>/dev/null || true)"
    [[ -n "$pth" ]] && echo "$pth" || true
}

# ── Resolve helper paths; drop missing ones with a warning ──
PASSWD_LINES=()
for h in "${HELPERS[@]}"; do
    p="$(resolve_binary "$h")"
    if [[ -n "$p" ]]; then
        # Defense in depth: sudoers only accepts absolute paths. If a bare
        # (non-absolute) name ever slips through — e.g. a builtin resolved by
        # a future `command -v`-style regression — refuse it loudly instead of
        # letting visudo reject the whole drop-in and trigger removal.
        if [[ "$p" != /* ]]; then
            echo "  ⚠ refusing bare (non-absolute) path for $h: $p" >&2
            continue
        fi
        PASSWD_LINES+=("$p")
    else
        echo "  ⚠ helper not installed locally, skipping NOPASSWD for: $h"
    fi
done
for b in "${PKG_TOOLS[@]}"; do
    p="$(resolve_binary "$b")"
    if [[ -n "$p" ]]; then
        # Same absolute-path guard as the HELPER loop above.
        if [[ "$p" != /* ]]; then
            echo "  ⚠ refusing bare (non-absolute) path for $b: $p" >&2
            continue
        fi
        PASSWD_LINES+=("$p")
    fi
done

if [[ "${#PASSWD_LINES[@]}" -eq 0 ]]; then
    echo "✗ No privileged helpers resolved — nothing to grant." >&2
    exit 1
fi

if [[ "$MODE" == "--verify" ]]; then
    echo "=== Passwordless sudo status for user '$USER_NAME' ==="
    if [[ -f "$DROPIN" ]]; then
        echo "  ✓ drop-in present: $DROPIN"
        echo "──────────────────────────────────────────────"
        cat "$DROPIN"
        echo "──────────────────────────────────────────────"
    else
        echo "  ✗ no drop-in installed yet"
    fi
    echo ""
    echo "  Dry-run validity (visudo -c -f):"
    if [[ -f "$DROPIN" ]] && visudo -c -f "$DROPIN" >/dev/null 2>&1; then
        echo "  ✓ $DROPIN parses cleanly"
    else
        echo "  ⚠ $DROPIN missing or invalid"
    fi
    # Non-privileged proof: did the actual user get NOPASSWD?
    if sudo -n -l -U "$USER_NAME" 2>/dev/null | grep -q NOPASSWD; then
        echo "  ✓ user '$USER_NAME' has NOPASSWD entries"
    else
        echo "  ✗ user '$USER_NAME' shows no NOPASSWD"
    fi
    exit 0
fi

if [[ "$MODE" == "--remove" ]]; then
    if [[ -f "$DROPIN" ]]; then
        rm -f "$DROPIN"
        echo "  ✓ removed $DROPIN"
    else
        echo "  · nothing to remove"
    fi
    exit 0
fi

# ── Build the drop-in ──
{
    echo "# Managed by RedTeam Harness — setup/configure_sudo_privileges.sh"
    echo "# Scoped NOPASSWD sudo for the exact binaries the harness invokes with 'sudo'."
    echo "# Allows the LLM-driven cockpit to run privileged tools headlessly (no TTY)."
    echo "# Least privilege: only these binaries; everything else still prompts."
    printf '%s ALL=(ALL) NOPASSWD: %s\n' "$USER_NAME" "$(IFS=,; echo "${PASSWD_LINES[*]}")"
} > "$DROPIN"

# sudoers requires 0440 perms or it's ignored
chmod 0440 "$DROPIN"
chown root:root "$DROPIN"

# ── Validate before we trust it (a broken sudoers locks the box) ──
if ! visudo -c -f "$DROPIN" >/dev/null 2>&1; then
    echo "✗ visudo rejected $DROPIN — removing to keep sudo safe." >&2
    rm -f "$DROPIN"
    exit 1
fi

echo "=== Passwordless sudo provisioned for user '$USER_NAME' ==="
echo "  drop-in       : $DROPIN"
echo "  granted       : NOPASSWD for $(IFS=,; echo "${PASSWD_LINES[*]}")"
if sudo -n -l -U "$USER_NAME" 2>/dev/null | grep -q NOPASSWD; then
    echo "  ✓ verified — user '$USER_NAME' now has scoped passwordless sudo"
else
    echo "  ⚠ installed but not yet reflected; new shells will pick it up"
fi
echo ""
echo "  Idempotent: safe to re-run.  Remove with:"
echo "    sudo bash setup/configure_sudo_privileges.sh --remove"