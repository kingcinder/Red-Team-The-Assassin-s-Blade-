"""RedTeam Harness — Mech-Unit TARGETS bridge (v7.0 P4.3).

Deterministic target discovery for the cockpit's TARGETS grid: runs an
airodump scan through the hardened runner, parses APs, and persists scan
hints into capture_state so plan resolvers inherit them. Zero LLM.
"""
import os
import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("redteam.mech.targets")

# Re-exported so callers (and tests) can patch the interface inventory
# through this module's namespace.
from core.mech.probes import list_interfaces  # noqa: E402

# airodump-ng CSV AP-table data row: starts with a 17-char MAC, then ", "
# (v7.1 fix: the old pattern demanded whitespace after the MAC, which real
# comma-separated airodump output never contains — zero rows ever parsed).
_ROW_RE = re.compile(r"^([0-9A-Fa-f:]{17})\s*,")


def parse_airodump_csv(csv_text: str) -> List[Dict[str, Any]]:
    """Parse airodump-ng's .csv output into AP records.

    airodump writes two tables: APs (BSSID, power, beacons, #IV, LAN, ...,
    ESSID) then stations. We take the AP table up to the blank separator.
    """
    aps: List[Dict[str, Any]] = []
    in_ap_table = True
    for line in csv_text.splitlines():
        line = line.rstrip()
        if not line.strip():
            in_ap_table = False
            continue
        if not in_ap_table:
            break
        if line.upper().startswith("BSSID"):
            continue
        row_m = _ROW_RE.match(line)
        if not row_m:
            continue
        bssid = row_m.group(1)
        cols = [c.strip() for c in line.split(",")]
        # csv layout: BSSID, First time seen, Last time seen, channel, Speed,
        # Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP,
        # ID-length, ESSID, Key  → power is column 8 (0-indexed)
        try:
            power = int(cols[8])
        except (IndexError, ValueError):
            power = -100
        record: Dict[str, Any] = {"bssid": bssid, "power": power,
                                  "clients": 0, "wps": False}
        if len(cols) >= 14:
            record["channel"] = cols[3]
            record["encryption"] = cols[5]
            record["essid"] = cols[13] or ""
        aps.append(record)
    return aps


def _pick_interface(orchestrator, requested: Optional[str]) -> Optional[str]:
    if requested:
        return requested
    capture_state = getattr(orchestrator, "capture_state", None)
    if capture_state is not None:
        try:
            return capture_state.get()
        except Exception:
            return None
    return None


def scan_wireless(orchestrator, interface: Optional[str] = None,
                  duration: int = 10) -> Dict[str, Any]:
    """Run one airodump sweep and return AP records for the TARGETS grid.

    Writes to the mech sandbox, parses the CSV, and stores scan hints in
    capture_state (interface/channel/bssid) for plan resolvers. Deterministic
    — no LLM anywhere on this path.
    """
    runner = getattr(orchestrator, "runner", None)
    if runner is None:
        return {"ok": False, "error": "no hardened runner available"}

    iface = _pick_interface(orchestrator, interface)
    if not iface:
        return {"ok": False,
                "error": "no capture interface selected — pick one in the "
                         "cockpit first (Model/capture selector)"}

    from core.mech.probes import run_probe
    monitor_probe = run_probe("wireless_adapter_monitor_capable", [])
    if not monitor_probe.ok:
        return {"ok": False,
                "error": monitor_probe.reason or "no monitor-capable adapter",
                "fix": monitor_probe.fix}

    from core.state_store import ensure_dir
    scan_dir = ensure_dir("./tasks/mech/_scans")

    # 1. Ensure monitor mode (deterministic; idempotent when already active).
    runner.execute("monitor_mode_enable", {"interface": iface},
                   timeout=30, sandbox_output_dir=scan_dir)

    # 1b. Rebind to the monitor vhost (v7.1): airmon-style enables often
    # RENAME the interface (wlan0 → wlan0mon). Sweeping the dead managed
    # name was the classic first-run failure. Fall back to the operator's
    # name when no monitor-typed interface appears.
    iface_used = iface
    try:
        monitors = [it["name"] for it in list_interfaces() if it.get("monitor")]
    except Exception:
        monitors = []
    if monitors and iface not in monitors:
        iface_used = monitors[0]
        logger.info("scan rebind: %s → monitor vhost %s", iface, iface_used)

    # 2. Sweep — on the rebound (monitor) interface.
    prefix = os.path.join(scan_dir, "targets")
    result = runner.execute(
        "airodump_capture",
        {"interface": iface_used, "channel": "0", "capture_file": prefix},
        timeout=max(5, duration),
        sandbox_output_dir=scan_dir)

    # 2b. A blocked/failed sweep is a scan failure, NOT an empty scan — the
    # TARGETS grid must show an error, not a successful "0 targets" result.
    # (A healthy sweep that legitimately finds no APs still returns ok:True
    # with count 0; only a run that could not execute is an error.)
    if result.get("blocked") or result.get("exit_code", 0) != 0:
        reason = result.get("block_reason") or result.get("stderr") or \
            result.get("stdout") or "airodump sweep failed"
        return {
            "ok": False,
            "interface": iface, "interface_used": iface_used,
            "error": f"airodump sweep failed: {str(reason)[:300]}",
        }

    # 3. Parse whichever artifact airodump produced.
    csv_path = None
    for candidate in (f"{prefix}-01.csv", f"{prefix}.csv"):
        if os.path.isfile(candidate):
            csv_path = candidate
            break
    aps: List[Dict[str, Any]] = []
    if csv_path:
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            aps = parse_airodump_csv(f.read())

    # 4. Persist the strongest AP as scan hints (resolver inheritance).
    capture_state = getattr(orchestrator, "capture_state", None)
    if capture_state is not None and aps:
        best = max(aps, key=lambda a: a.get("power", -999))
        try:
            capture_state.set(iface_used)
            capture_state.set_scan(
                channel=str(best.get("channel") or ""),
                bssid=best.get("bssid") or "")
        except Exception:
            logger.debug("capture_state scan-hint write failed", exc_info=True)

    return {
        "ok": True, "interface": iface, "interface_used": iface_used,
        "duration": duration,
        "targets": aps, "count": len(aps),
        "stdout_excerpt": (result.get("stdout") or "")[:500],
    }
