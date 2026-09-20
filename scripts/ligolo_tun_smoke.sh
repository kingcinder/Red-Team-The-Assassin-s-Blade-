#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# ligolo_tun_smoke.sh — sudo-gated END-TO-END pivot verification
#
# The unprivileged smoke (verified 2026-09-19) proved: proxy listens →
# agent joins → control channel ESTABLISHED. This script finishes the
# job at the TUN layer, which requires root:
#
#   1. LISTEN        proxy (root, -selfcert) listening on 127.0.0.1:11601
#   2. AGENT-JOINED  agent (user) dials in, session registers
#   3. SESSION       console: select the agent session (via PTY — the
#                    session picker is a TUI, so we drive it with a pty)
#   4. TUN-CREATED   console: ifconfig — ligolo creates the 'ligolo'/tun
#                    interface and installs the agent-side routes
#                    (this is ligolo's "ifinit"; the tunnel forwards
#                    immediately — there is no separate 'start' command
#                    in current ligolo-ng; the console's own `help` is
#                    captured to the log for the exact command set)
#   5. TRAFFIC-VIA-TUN  curl http://240.0.0.1:8318/ — ligolo's magic IP
#                    for the agent's loopback — must return our marker
#                    served by the "test target" http.server
#
# Usage:   bash scripts/ligolo_tun_smoke.sh          (self-elevates)
#          sudo -E bash scripts/ligolo_tun_smoke.sh  (already root)
# Cleanup: all spawned processes are killed on exit; workdirs under
#          /tmp/ligolo-tun-smoke-*/ are KEPT — the console transcript and
#          driver log there are the debugging record for failed runs.
# ═══════════════════════════════════════════════════════════════════════
set -u

# ── sudo gate ─────────────────────────────────────────────────────────
# TUN interface creation needs CAP_NET_ADMIN: re-exec self with sudo
# unless already root (or SMOKE_SKIP_SUDO=1 for driver unit-testing).
if [ "$EUID" -ne 0 ] && [ "${SMOKE_SKIP_SUDO:-0}" != "1" ]; then
    echo "[*] TUN creation requires root — re-executing with sudo…"
    exec sudo -E bash "$0" "$@"
fi

ORIG_USER="${SUDO_USER:-$USER}"
ORIG_HOME="$(getent passwd "$ORIG_USER" | cut -d: -f6)"

LIGOLO_BIN="${LIGOLO_BIN:-$ORIG_HOME/redteam-tools/bin/ligolo}"
AGENT_BIN="${AGENT_BIN:-$(command -v agent || echo "$ORIG_HOME/go/bin/agent")}"
PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:11601}"
TARGET_PORT="${TARGET_PORT:-8318}"
MARKER="LIGOLO-TUN-SMOKE-OK-$(date +%s)"

for f in "$LIGOLO_BIN" "$AGENT_BIN"; do
    if [ ! -x "$f" ]; then
        echo "[FAIL] missing binary: $f"
        exit 1
    fi
done

WORK="$(mktemp -d /tmp/ligolo-tun-smoke-XXXXXX)"
mkdir -p "$WORK/www"
echo "<html><body>$MARKER</body></html>" > "$WORK/www/index.html"

cleanup() {
    # best-effort: console exit, then kill stragglers, drop workdir
    [ -n "${DRIVER_PID:-}" ] && kill "$DRIVER_PID" 2>/dev/null
    pkill -u "$ORIG_USER" -x agent 2>/dev/null
    pkill -u "$ORIG_USER" -f "http.server $TARGET_PORT" 2>/dev/null
    ip link del ligolo 2>/dev/null   # remove leftover TUN if the proxy died hard
    echo "[*] console transcript: $WORK/proxy-console.log"
    echo "[*] proxy stderr:       $WORK/proxy-stderr.log"
}
trap cleanup EXIT

# ── "test target": HTTP server on the agent side (as the invoking user) ──
sudo -u "$ORIG_USER" nohup python3 -m http.server "$TARGET_PORT" \
    --bind 127.0.0.1 --directory "$WORK/www" \
    > "$WORK/target.log" 2>&1 &
sleep 1
if curl -s --max-time 5 "http://127.0.0.1:$TARGET_PORT/" | grep -q "$MARKER"; then
    echo "[OK]   TARGET-UP   (127.0.0.1:$TARGET_PORT serving marker)"
else
    echo "[FAIL] TARGET-UP   — target server did not start; see $WORK/target.log"
    exit 1
fi

# ── agent (as the invoking user — it needs no privileges) ──────────────
sudo -u "$ORIG_USER" nohup "$AGENT_BIN" \
    -connect "$PROXY_ADDR" -ignore-cert -retry \
    > "$WORK/agent.log" 2>&1 &
sleep 1

# ── proxy + console driver (root; needs CAP_NET_ADMIN for the TUN) ─────
LIGOLO_BIN="$LIGOLO_BIN" PROXY_ADDR="$PROXY_ADDR" WORK="$WORK" \
MARKER="$MARKER" TARGET_PORT="$TARGET_PORT" ORIG_USER="$ORIG_USER" \
python3 - <<'DRIVER' 2>&1 | tee "$WORK/driver.log"
import os, pty, select, subprocess, sys, time, urllib.request

work = os.environ["WORK"]
ligolo = os.environ["LIGOLO_BIN"]
proxy_addr = os.environ["PROXY_ADDR"]
marker = os.environ["MARKER"]
port = os.environ["TARGET_PORT"]
results = []

def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'OK' if ok else 'FAIL'}] {name}  {detail}", flush=True)

master, slave = pty.openpty()
proc = subprocess.Popen(
    [ligolo, "-selfcert", "-laddr", proxy_addr],
    stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
    cwd=work, close_fds=True, preexec_fn=os.setsid,
)
os.close(slave)
console = open(os.path.join(work, "proxy-console.log"), "wb")

def expect(patterns, timeout=45):
    """Read the pty until one of `patterns` appears; return (idx, buffer)."""
    buf = b""
    deadline = time.time() + timeout
    pats = [p.encode() for p in patterns]
    while time.time() < deadline:
        r, _, _ = select.select([master], [], [], 1.0)
        if master not in r:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        console.write(chunk)
        console.flush()
        for i, p in enumerate(pats):
            if p in buf:
                return i, buf
    return -1, buf

def send(s):
    os.write(master, s.encode())

try:
    # 1. LISTEN
    i, buf = expect(["Listening on"], 30)
    record("LISTEN", i == 0, "proxy listening on " + proxy_addr)

    # 2. AGENT-JOINED
    i, buf = expect(["Agent joined"], 30)
    record("AGENT-JOINED", i == 0, "agent session registered")

    # capture the console's own command set for the record
    send("help\r")
    expect(["ligolo-ng »", "»"], 10)

    # 3. SESSION — promptui picker needs the pty; Enter selects the first
    send("session\r")
    expect(["Specify a session", "session"], 15)
    time.sleep(1)
    send("\r")
    expect(["»"], 20)          # back at the console prompt = selected

    # 4. TUN-CREATED — `ifconfig` initializes the interface + routes
    send("ifconfig\r")
    i, buf = expect(
        ["Ifconfig done", "Route added", "Interface 'ligolo'", "tun"],
        45,
    )
    record("TUN-CREATED", i != -1,
           "ifconfig output matched pattern %d" % i)

    # 5. TRAFFIC-VIA-TUN — 240.0.0.1 is ligolo's magic IP for the agent's
    #    loopback; our target serves the marker from the agent side.
    ok, detail = False, "no response"
    for attempt in range(3):
        try:
            body = urllib.request.urlopen(
                f"http://240.0.0.1:{port}/", timeout=10).read().decode()
            if marker in body:
                ok, detail = True, f"marker returned via TUN (attempt {attempt + 1})"
                break
            detail = "response mismatch: " + body[:80]
        except Exception as e:
            detail = f"attempt {attempt + 1}: {e}"
            time.sleep(2)
    record("TRAFFIC-VIA-TUN", ok, detail)

finally:
    try:
        send("exit\r")
    except Exception:
        pass
    time.sleep(1)
    try:
        proc.terminate()
    except Exception:
        pass
    console.close()

sys.exit(0 if all(ok for _, ok, _ in results) else 1)
DRIVER
DRIVER_RC=${PIPESTATUS[0]}

# ── summary ────────────────────────────────────────────────────────────
echo "═══ smoke summary ═══"
cat "$WORK/driver.log"
if [ "$DRIVER_RC" -eq 0 ]; then
    echo "═══ RESULT: PASS — pivot verified end to end including TUN traffic ═══"
else
    echo "═══ RESULT: FAIL (driver rc=$DRIVER_RC) — transcripts: $WORK/ ═══"
fi
exit "$DRIVER_RC"
