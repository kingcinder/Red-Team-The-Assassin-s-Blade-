#!/bin/bash
# RedTeam Harness shortcut — update
# Bundled wrapper shortcut; delegates to the lifecycle wrapper.
# Works from the repo (./redteam-update.sh) or via ~/.local/bin symlink.
set -euo pipefail
_SRC="${BASH_SOURCE[0]}"
if command -v readlink >/dev/null 2>&1 && _RESOLVED="$(readlink -f "$_SRC" 2>/dev/null)" && [ -n "$_RESOLVED" ]; then
    _SRC="$_RESOLVED"
fi
exec bash "$(cd "$(dirname "$_SRC")" && pwd)/redteam.sh" update "$@"