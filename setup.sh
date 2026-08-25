#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — Quick Setup (delegates to install.sh)
# For the full installer with tool detection + validation, run:
#   bash install.sh
# ═══════════════════════════════════════════════════════════════
echo "RedTeam Harness v4.0 — redirecting to install.sh..."
exec bash "$(dirname "$0")/install.sh" "$@"