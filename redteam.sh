#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — install / update / uninstall / run wrapper
#
# Convenience wrapper bundling the four lifecycle actions, with
# per-action shortcut shims living next to this script:
#   redteam-install.sh   redteam-uninstall.sh
#   redteam-update.sh    redteam-run.sh
#
# Usage:
#   bash redteam.sh <verb> [options]
#
#   install [--tools] [--sudo] [--shortcuts] [--verify]
#       Install Python deps + runtime dirs (delegates to install.sh).
#         --tools       also run the 85+ Kali tools installer (needs sudo)
#         --sudo        also provision scoped passwordless sudo (needs sudo)
#         --shortcuts   also link shortcuts into ~/.local/bin
#         --verify      also run install.sh --verify (air-gap readiness)
#   update
#       git pull --ff-only, then reinstall Python deps
#   uninstall [--yes] [--keep-data]
#       Stop harness processes, uninstall Python deps, remove runtime
#       data (sessions/ output/ tasks/), unlink shortcuts, remove the
#       scoped-sudo drop-in. The repo checkout itself is left in place.
#         --yes         skip the confirmation prompt
#         --keep-data   keep sessions/ output/ tasks/
#   run [harness args...]
#       Launch harness.py (default: dashboard on :9999). Extra args pass
#       through, e.g. run --cli | run --mech doctor | run --check
#   shortcuts [--remove]
#       Link redteam + the four verb shims into ~/.local/bin so they
#       work from anywhere (--remove unlinks them).
#   help
#       This text.
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

# ── Resolve the real script path (works via a ~/.local/bin symlink) ──
_SRC="${BASH_SOURCE[0]}"
if command -v readlink >/dev/null 2>&1 && _RESOLVED="$(readlink -f "$_SRC" 2>/dev/null)" && [ -n "$_RESOLVED" ]; then
    _SRC="$_RESOLVED"
fi
HARNESS_DIR="$(cd "$(dirname "$_SRC")" && pwd)"
cd "$HARNESS_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail() { echo -e "${RED}  ✗${NC} $1"; }
info() { echo -e "${CYAN}  ·${NC} $1"; }

PICK_PYTHON() {
    local py
    # `python` last: it's the Windows launcher name, but on some Linux
    # boxes it points at Python 2 — the version gate below rejects that.
    for py in python3 python3.12 python3.11 python3.10 python; do
        if command -v "$py" >/dev/null 2>&1 && \
           "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            PYTHON="$py"
            return 0
        fi
    done
    fail "Python 3.10+ required. Install it first."
    return 1
}

# ═══════════════════════════════════════════════════════════════
# install marker (.installed-version)
# Records which checkout state (commit + requirements hash) the Python
# deps were installed from, so update and other checkouts can detect
# dependency drift. Gitignored: machine-local state, never committed.
# ═══════════════════════════════════════════════════════════════
MARKER="$HARNESS_DIR/.installed-version"

req_hash() {
    local h
    h="$(sha256sum requirements.txt 2>/dev/null | cut -d' ' -f1)"
    if [ -z "$h" ]; then
        h="$(python3 -c 'import hashlib;print(hashlib.sha256(open("requirements.txt","rb").read()).hexdigest())' 2>/dev/null || true)"
    fi
    [ -n "$h" ] && echo "$h" || echo unknown
}

write_marker() {
    local commit reqhash
    commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    reqhash="$(req_hash)"
    cat > "$MARKER" <<EOF
# RedTeam Harness install marker — written by redteam.sh
# Records which checkout state the Python deps were installed from,
# so update/other checkouts can detect dependency drift.
commit=$commit
requirements_sha256=$reqhash
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
    ok "wrote install marker $MARKER (commit ${commit:0:12}, requirements $reqhash)"
}

report_drift() {
    local marker_commit marker_reqhash cur_commit cur_reqhash drift=0 shown
    if [ ! -f "$MARKER" ]; then
        warn "no install marker ($MARKER) — cannot compare installed deps against this checkout"
        return 0
    fi
    marker_commit="$(sed -n 's/^commit=//p' "$MARKER" | head -1)"
    marker_reqhash="$(sed -n 's/^requirements_sha256=//p' "$MARKER" | head -1)"
    cur_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    cur_reqhash="$(req_hash)"
    if [ -n "$marker_commit" ] && [ "$marker_commit" != unknown ] && [ "$cur_commit" != unknown ] && [ "$marker_commit" != "$cur_commit" ]; then
        warn "installed deps are from commit ${marker_commit:0:12}; this checkout is at ${cur_commit:0:12}"
        drift=1
    fi
    if [ -n "$marker_reqhash" ] && [ "$marker_reqhash" != unknown ] && [ "$cur_reqhash" != unknown ] && [ "$marker_reqhash" != "$cur_reqhash" ]; then
        warn "requirements.txt hash differs from install time — Python deps may be stale (update reinstalls them)"
        drift=1
    fi
    if [ "$drift" = 0 ]; then
        shown="${marker_commit:0:12}"
        [ -z "$shown" ] && shown="<unrecorded>"
        ok "install marker matches this checkout (commit $shown) — no dependency drift"
    else
        info "running 'update' pulls + reinstalls deps and refreshes the marker"
    fi
    return 0
}

# One-line stale-deps warning for `run` (silent when the marker is
# absent or matches this checkout). Emitted to stderr: run() execs the
# harness right after, and bash does not flush its stdout buffer across
# exec when stdout is a pipe.
drift_warning() {
    local marker_commit marker_reqhash cur_commit cur_reqhash
    [ -f "$MARKER" ] || return 0
    marker_commit="$(sed -n 's/^commit=//p' "$MARKER" | head -1)"
    marker_reqhash="$(sed -n 's/^requirements_sha256=//p' "$MARKER" | head -1)"
    cur_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    cur_reqhash="$(req_hash)"
    if { [ -n "$marker_commit" ] && [ "$marker_commit" != unknown ] && [ "$cur_commit" != unknown ] && [ "$marker_commit" != "$cur_commit" ]; } || \
       { [ -n "$marker_reqhash" ] && [ "$marker_reqhash" != unknown ] && [ "$cur_reqhash" != unknown ] && [ "$marker_reqhash" != "$cur_reqhash" ]; }; then
        warn "installed deps predate this checkout (see .installed-version) — run: bash redteam.sh update" >&2
    fi
}

# ═══════════════════════════════════════════════════════════════
# install
# ═══════════════════════════════════════════════════════════════
install() {
    local run_tools=0 run_sudo=0 run_links=0 run_verify=0
    for a in "$@"; do
        case "$a" in
            --tools)     run_tools=1 ;;
            --sudo)      run_sudo=1 ;;
            --shortcuts) run_links=1 ;;
            --verify)    run_verify=1 ;;
            *) fail "unknown flag: $a"; return 2 ;;
        esac
    done

    info "Installing RedTeam Harness..."
    bash install.sh
    [ "$run_verify" = 1 ] && bash install.sh --verify
    if [ "$run_tools" = 1 ]; then
        info "Installing Kali security tools (sudo required)..."
        bash install_kali_tools.sh
    fi
    if [ "$run_sudo" = 1 ]; then
        info "Provisioning scoped passwordless sudo (sudo required)..."
        sudo bash setup/configure_sudo_privileges.sh
    fi
    [ "$run_links" = 1 ] && shortcuts
    write_marker

    ok "install complete — launch with: bash redteam.sh run"
}

# ═══════════════════════════════════════════════════════════════
# update
# ═══════════════════════════════════════════════════════════════
update() {
    info "Updating RedTeam Harness from the repo..."
    if [ ! -d .git ]; then
        fail "'update' only works on a git clone — no .git found here"
        return 1
    fi
    report_drift
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        warn "working tree has uncommitted changes — pull may refuse if they conflict"
    fi

    local before after
    before="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    if ! git pull --ff-only; then
        fail "git pull failed — stash or commit local changes, then re-run: bash redteam.sh update"
        return 1
    fi
    after="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    if [ "$before" = "$after" ]; then
        ok "already up to date"
    else
        info "New commits since your last update:"
        git log --oneline --no-decorate "$before..$after" 2>/dev/null | sed 's/^/    /' || true
    fi

    info "Reinstalling Python dependencies (requirements may have changed)..."
    bash install.sh
    write_marker
    ok "update complete — run: bash redteam.sh run"
}

# ═══════════════════════════════════════════════════════════════
# uninstall
# ═══════════════════════════════════════════════════════════════
uninstall() {
    local force=0 keep_data=0
    for a in "$@"; do
        case "$a" in
            --yes)       force=1 ;;
            --keep-data) keep_data=1 ;;
            *) fail "unknown flag: $a"; return 2 ;;
        esac
    done
    PICK_PYTHON

    local pids npkgs pkgs
    pids="$(pgrep -f 'harness\.py' 2>/dev/null || true)"
    local nproc=0
    [ -n "$pids" ] && nproc="$(printf '%s\n' "$pids" | wc -l | tr -d ' ')"
    pkgs=""
    npkgs=0
    if [ -f requirements.txt ]; then
        pkgs="$(grep -vE '^\s*(#|$)' requirements.txt | sed -E 's/[<>=!~].*$//' | tr -d ' ' | sort -u)"
        [ -n "$pkgs" ] && npkgs="$(printf '%s\n' "$pkgs" | grep -c . || true)"
    fi

    if [ "$force" != 1 ]; then
        echo ""
        echo "This will:"
        echo "  · stop ${nproc} running harness process(es)"
        echo "  · pip-uninstall ${npkgs} Python package(s) from requirements.txt"
        if [ "$keep_data" = 1 ]; then
            echo "  · KEEP sessions/ output/ tasks/ (--keep-data)"
        else
            echo "  · delete runtime data: sessions/ output/ tasks/"
        fi
        echo "  · unlink ~/.local/bin shortcuts (if linked)"
        [ -f /etc/sudoers.d/redteam-harness ] && echo "  · remove the scoped-passwordless-sudo drop-in (needs sudo)"
        echo "  · leave the repo checkout itself (incl. config.yaml) untouched"
        read -r -p "Proceed? [y/N] " ans
        case "$ans" in
            y|Y|yes|YES) ;;
            *) info "aborted — nothing changed"; return 0 ;;
        esac
    fi

    # 1. Stop running harness instances
    if [ -n "$pids" ]; then
        info "stopping harness processes: $(printf '%s\n' "$pids" | tr '\n' ' ')"
        kill $pids 2>/dev/null || true
        sleep 1
        if pgrep -f 'harness\.py' >/dev/null 2>&1; then
            warn "some processes did not exit cleanly — sending SIGKILL"
            pkill -9 -f 'harness\.py' 2>/dev/null || true
        fi
    else
        info "no running harness processes"
    fi

    # 2. Unlink shortcuts
    shortcuts --remove || true

    # 3. Uninstall Python deps (only the ones actually installed)
    if [ -n "$pkgs" ]; then
        info "uninstalling: $(printf '%s\n' "$pkgs" | tr '\n' ' ')"
        local pipflags=""
        "$PYTHON" -m pip install --help 2>/dev/null | grep -q break-system-packages && pipflags="--break-system-packages"
        for pkg in $pkgs; do
            if "$PYTHON" -m pip show "$pkg" >/dev/null 2>&1; then
                if "$PYTHON" -m pip uninstall -y $pipflags "$pkg" >/dev/null 2>&1; then
                    ok "uninstalled $pkg"
                else
                    warn "failed to uninstall $pkg (skipping)"
                fi
            fi
        done
    fi

    # 4. Runtime data
    if [ "$keep_data" != 1 ]; then
        for d in sessions output tasks; do
            if [ -d "$d" ]; then rm -rf "$d"; info "removed $d/"; fi
        done
    else
        info "kept sessions/ output/ tasks/ (--keep-data)"
    fi

    # 5. Scoped-sudo drop-in
    if [ -f /etc/sudoers.d/redteam-harness ]; then
        if sudo -n true 2>/dev/null; then
            sudo bash setup/configure_sudo_privileges.sh --remove && \
                ok "removed passwordless-sudo drop-in" || warn "drop-in removal failed"
        else
            warn "drop-in present at /etc/sudoers.d/redteam-harness — remove manually with:"
            warn "  sudo bash setup/configure_sudo_privileges.sh --remove"
        fi
    fi

    ok "uninstall complete — the repo checkout was left in place"
}

# ═══════════════════════════════════════════════════════════════
# run
# ═══════════════════════════════════════════════════════════════
run() {
    PICK_PYTHON
    drift_warning
    exec "$PYTHON" harness.py "$@"
}

# ═══════════════════════════════════════════════════════════════
# doctor
# ═══════════════════════════════════════════════════════════════
doctor() {
    local failures=0 pyver mcommit mtime shown
    echo ""
    echo -e "${BOLD}RedTeam Harness — lifecycle doctor${NC}"
    echo "─────────────────────────────────────────────"

    echo -e "${BOLD}[1/5] Python & core deps${NC}"
    if PICK_PYTHON; then
        pyver="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null)"
        ok "python: $PYTHON ($pyver)"
        if "$PYTHON" -c 'import flask, flask_socketio, yaml, requests, jinja2, psutil, gevent, dateutil' >/dev/null 2>&1; then
            ok "core runtime imports OK"
        else
            fail "core runtime imports FAIL — run: bash redteam.sh install"
            failures=$((failures + 1))
        fi
    else
        fail "no Python 3.10+ found — install Python, then run: bash redteam.sh install"
        failures=$((failures + 1))
    fi

    echo -e "${BOLD}[2/5] Install marker (.installed-version)${NC}"
    if [ -f "$MARKER" ]; then
        mcommit="$(sed -n 's/^commit=//p' "$MARKER" | head -1)"
        mtime="$(sed -n 's/^installed_at=//p' "$MARKER" | head -1)"
        shown="${mcommit:0:12}"
        [ -z "$shown" ] && shown="<unrecorded>"
        ok "marker present: commit $shown, installed ${mtime:-<unknown>}"
        report_drift
    else
        warn "no marker — deps not installed via redteam.sh yet (run: bash redteam.sh install)"
    fi

    echo -e "${BOLD}[3/5] Checkout${NC}"
    if [ -d .git ]; then
        ok "git: $(git branch --show-current 2>/dev/null) @ $(git rev-parse --short HEAD 2>/dev/null)"
        if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
            warn "working tree has uncommitted changes"
        else
            ok "working tree clean"
        fi
    else
        warn "not a git checkout (update/drift checks unavailable)"
    fi

    echo -e "${BOLD}[4/5] Tool readiness${NC}"
    local t found=0 total=0 missing=""
    for t in nmap masscan nikto sqlmap gobuster hydra john hashcat \
             aircrack-ng airodump-ng aireplay-ng reaver hcxdumptool wifite \
             tcpdump tshark bettercap kismet netexec msfconsole; do
        total=$((total + 1))
        if command -v "$t" >/dev/null 2>&1; then
            found=$((found + 1))
        else
            missing="$missing $t"
        fi
    done
    if [ "$found" -eq "$total" ]; then
        ok "all $total probed security tools present"
    else
        warn "$found/$total probed security tools present"
        info "missing:$missing"
    fi

    echo -e "${BOLD}[5/5] Environment${NC}"
    local dirs_ok=1 d
    for d in sessions output tasks; do
        [ -d "$d" ] || dirs_ok=0
    done
    if [ "$dirs_ok" = 1 ]; then ok "runtime dirs present (sessions/ output/ tasks/)"; else warn "runtime dirs missing — run: bash redteam.sh install"; fi
    if [ -f /etc/sudoers.d/redteam-harness ]; then
        ok "scoped-sudo drop-in present (/etc/sudoers.d/redteam-harness)"
    else
        info "no scoped-sudo drop-in (optional — provision with: bash redteam.sh install --sudo)"
    fi
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 2 http://127.0.0.1:8080/v1/models >/dev/null 2>&1; then
            ok "LLM backend: llama-server on :8080"
        elif curl -s --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            ok "LLM backend: Ollama on :11434"
        else
            info "no LLM backend detected (optional — Mech-Unit runs without one)"
        fi
    else
        info "curl not found — skipping LLM backend check"
    fi

    echo "─────────────────────────────────────────────"
    if [ "$failures" -eq 0 ]; then
        ok "doctor: all critical checks passed — launch with: bash redteam.sh run"
        return 0
    fi
    fail "doctor: $failures critical check(s) failed — fix with: bash redteam.sh install"
    return 1
}

# ═══════════════════════════════════════════════════════════════
# shortcuts
# ═══════════════════════════════════════════════════════════════
SHORTCUT_NAMES="redteam redteam-install redteam-uninstall redteam-update redteam-run"

shortcuts() {
    local bindir="${HOME}/.local/bin"
    local name src
    if [ "${1:-}" = "--remove" ]; then
        local n=0
        for name in $SHORTCUT_NAMES; do
            if [ -L "$bindir/$name" ]; then rm -f "$bindir/$name"; n=$((n + 1)); fi
        done
        if [ "$n" -gt 0 ]; then ok "removed $n shortcut(s) from $bindir"; else info "no shortcuts linked — nothing to remove"; fi
        return 0
    fi
    mkdir -p "$bindir"
    for name in $SHORTCUT_NAMES; do
        src="$HARNESS_DIR/$name.sh"
        if [ ! -f "$src" ]; then warn "missing $src — skipping"; continue; fi
        ln -sfn "$src" "$bindir/$name"
    done
    ok "linked shortcuts into $bindir"
    info "available from anywhere: redteam <verb> · redteam-install · redteam-uninstall · redteam-update · redteam-run"
    info "(ensure $bindir is on your PATH — most distros include it)"
}

# ═══════════════════════════════════════════════════════════════
# help
# ═══════════════════════════════════════════════════════════════
help() {
    cat <<'EOF'
RedTeam Harness — lifecycle wrapper

Usage:
  bash redteam.sh <verb> [options]

Verbs:
  install [--tools] [--sudo] [--shortcuts] [--verify]
      Install Python deps + runtime dirs (delegates to install.sh).
        --tools       also run the 85+ Kali tools installer (needs sudo)
        --sudo        also provision scoped passwordless sudo (needs sudo)
        --shortcuts   also link shortcuts into ~/.local/bin
        --verify      also run install.sh --verify (air-gap readiness)
  update
      git pull --ff-only, then reinstall Python deps
  doctor
      One-screen health report: Python + core deps, install marker &
      drift, checkout state, tool readiness, sudo drop-in, LLM backend.
      Exits non-zero if a critical check fails.
  uninstall [--yes] [--keep-data]
      Stop harness processes, uninstall Python deps, remove runtime data
      (sessions/ output/ tasks/), unlink shortcuts, remove the scoped-sudo
      drop-in. The repo checkout itself is left in place.
  run [harness args...]
      Launch harness.py (default: dashboard on :9999). Extra args pass
      through, e.g. run --cli | run --mech doctor | run --check
  shortcuts [--remove]
      Link redteam + the four verb shims into ~/.local/bin so they work
      from anywhere (--remove unlinks them).
  help
      This text.

  doctor
      One-screen health report: Python + core deps, install marker &
      drift, checkout state, tool readiness, sudo drop-in, LLM backend.
      Exits non-zero if a critical check fails.

Shortcut shims in the repo:
  ./redteam-install.sh  ./redteam-uninstall.sh  ./redteam-update.sh  ./redteam-run.sh

Examples:
  bash redteam.sh install --tools --sudo --shortcuts   # full first-time setup
  bash redteam.sh update                               # pull + reinstall deps
  bash redteam.sh run --mech doctor                    # cockpit health check
  bash redteam.sh uninstall --yes                      # non-interactive removal
EOF
}

# ═══════════════════════════════════════════════════════════════
# main
# ═══════════════════════════════════════════════════════════════
VERB="${1:-help}"
shift || true
case "$VERB" in
    install)   install "$@" ;;
    update)    update ;;
    doctor)    doctor ;;
    uninstall) uninstall "$@" ;;
    run)       run "$@" ;;
    shortcuts) shortcuts "${1:-}" ;;
    help|-h|--help) help ;;
    *) fail "unknown verb: $VERB (try: bash redteam.sh help)"; exit 2 ;;
esac