"""
RedTeam Harness — Mech-Unit Capability Probes (v7.0 P1.2)

Deterministic host-capability checks that gate plan compilation. A probe
never asks the LLM and never mutates the system — it only *reports*:

    ProbeResult(ok, reason, fix, detail)

Probes are the reason an operator with zero tool knowledge can still
succeed: before a plan compiles, the Mech-Unit proves the host can run it
and, when it can't, says exactly what is missing and how to fix it.

Registry (extensible):
    wireless_adapter_monitor_capable — a monitor-mode-capable radio exists
    tools_present                    — named binaries resolve on PATH
    wordlist_available               — named wordlist files exist
    interface_exists                 — a named network interface exists
    running_as_root                  — effective UID is 0
"""
import os
import shutil
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("redteam.mech.probes")

_SYS_NET = "/sys/class/net"


@dataclass
class ProbeResult:
    """Structured result of one capability probe."""
    probe: str
    ok: bool
    missing: List[str] = field(default_factory=list)
    reason: str = ""
    fix: str = ""
    detail: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "probe": self.probe, "ok": self.ok, "missing": list(self.missing),
            "reason": self.reason, "fix": self.fix, "detail": dict(self.detail),
        }


# ── system inspection helpers (thin, testable) ──────────────────────────

def list_interfaces(sys_net: str = _SYS_NET) -> List[Dict]:
    """Inventory network interfaces from /sys/class/net.

    Each entry: {name, wireless, monitor, up}. Best-effort — missing sysfs
    yields [] rather than raising (containers, unusual kernels).
    """
    out: List[Dict] = []
    try:
        names = sorted(os.listdir(sys_net))
    except OSError:
        return out
    for name in names:
        base = os.path.join(sys_net, name)
        wireless = os.path.isdir(os.path.join(base, "wireless")) or \
            os.path.exists(os.path.join(base, "phy80211"))
        monitor = False
        if wireless:
            # mac80211 monitor vhosts carry a monitor type flag in operstate
            # caveats aside, the presence of <if>/monitor_interface or a
            # "<phy>" 80211 link plus wireless dir is our best offline signal.
            try:
                with open(os.path.join(base, "type")) as f:
                    # ARPHRD_IEEE80211_RADIOTAP (803) / ARPHRD_IEEE80211 (802)
                    monitor = f.read().strip() in ("802", "803")
            except OSError:
                monitor = False
        try:
            operstate = open(os.path.join(base, "operstate")).read().strip()
        except OSError:
            operstate = "unknown"
        out.append({
            "name": name, "wireless": wireless, "monitor": monitor,
            "up": operstate in ("up", "unknown"),
        })
    return out


def monitor_capable_interfaces(interfaces: Optional[List[Dict]] = None) -> List[str]:
    """Interface names that look monitor-capable (wireless phys)."""
    inv = interfaces if interfaces is not None else list_interfaces()
    return [it["name"] for it in inv if it.get("wireless")]


# ── probe implementations ────────────────────────────────────────────────

def probe_wireless_adapter_monitor_capable(params: List[str]) -> ProbeResult:
    del params  # probe takes no parameters
    capable = monitor_capable_interfaces()
    if capable:
        return ProbeResult(
            probe="wireless_adapter_monitor_capable", ok=True,
            reason=f"monitor-capable adapter(s): {', '.join(capable)}",
            fix="",
            detail={"interfaces": capable})
    return ProbeResult(
        probe="wireless_adapter_monitor_capable", ok=False,
        missing=["monitor-capable wireless adapter"],
        reason="no wireless interface with monitor-mode capability found",
        fix="connect a monitor-mode-capable adapter (e.g. Atheros AR9271 / "
            "Realtek RTL8812AU) or verify its driver is loaded (iw dev)",
        detail={"interfaces": [it["name"] for it in list_interfaces()]})


def probe_tools_present(params: List[str]) -> ProbeResult:
    if not params:
        return ProbeResult(
            probe="tools_present", ok=False, missing=["probe 'with' list"],
            reason="tools_present probe declared without a 'with' list",
            fix="add 'with: [tool1, tool2]' to the precondition")
    missing = [t for t in params if shutil.which(t) is None]
    if missing:
        return ProbeResult(
            probe="tools_present", ok=False, missing=missing,
            reason=f"missing binaries: {', '.join(missing)}",
            fix=f"install: sudo apt install {' '.join(missing)} (or run "
                f"install_kali_tools.sh)",
            detail={"checked": list(params)})
    return ProbeResult(
        probe="tools_present", ok=True,
        reason=f"all {len(params)} required binaries present",
        detail={"checked": list(params)})


def probe_wordlist_available(params: List[str]) -> ProbeResult:
    if not params:
        return ProbeResult(
            probe="wordlist_available", ok=False, missing=["probe 'with' list"],
            reason="wordlist_available probe declared without a 'with' list",
            fix="add 'with: [/path/to/wordlist]' to the precondition")
    missing = [p for p in params if not os.path.isfile(p)]
    if missing:
        return ProbeResult(
            probe="wordlist_available", ok=False, missing=missing,
            reason=f"missing wordlist file(s): {', '.join(missing)}",
            fix="place the wordlist at the listed path (air-gap: copy from "
                "the wheels/USB bundle) or point the manifest at another",
            detail={"checked": list(params)})
    return ProbeResult(
        probe="wordlist_available", ok=True,
        reason=f"all {len(params)} wordlist(s) present",
        detail={"checked": list(params)})


def probe_interface_exists(params: List[str]) -> ProbeResult:
    if not params:
        return ProbeResult(
            probe="interface_exists", ok=False, missing=["probe 'with' list"],
            reason="interface_exists probe declared without a 'with' list",
            fix="add 'with: [wlan0mon]' to the precondition")
    missing = [p for p in params
               if not os.path.exists(os.path.join(_SYS_NET, p))]
    if missing:
        return ProbeResult(
            probe="interface_exists", ok=False, missing=missing,
            reason=f"interface(s) not present: {', '.join(missing)}",
            fix="check `ip link` — the interface may need airmon-ng first",
            detail={"checked": list(params)})
    return ProbeResult(
        probe="interface_exists", ok=True,
        reason=f"all {len(params)} interface(s) present",
        detail={"checked": list(params)})


def probe_running_as_root(params: List[str]) -> ProbeResult:
    del params
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        return ProbeResult(probe="running_as_root", ok=True,
                           reason="effective UID is 0")
    return ProbeResult(
        probe="running_as_root", ok=False, missing=["root privileges"],
        reason="wireless capture and many exploit tools need root",
        fix="restart the harness with sudo, or use setup/"
            "configure_sudo_privileges.sh for scoped elevation")


PROBE_REGISTRY: Dict[str, Callable[[List[str]], ProbeResult]] = {
    "wireless_adapter_monitor_capable": probe_wireless_adapter_monitor_capable,
    "tools_present": probe_tools_present,
    "wordlist_available": probe_wordlist_available,
    "interface_exists": probe_interface_exists,
    "running_as_root": probe_running_as_root,
}


def probe_names() -> List[str]:
    return sorted(PROBE_REGISTRY)


def run_probe(name: str, params: Optional[List[str]] = None) -> ProbeResult:
    """Run one probe by name. Unknown probe names fail with a clear fix —
    a typo in a manifest must be visible on the intent wall, not silently ok."""
    fn = PROBE_REGISTRY.get(name)
    if fn is None:
        return ProbeResult(
            probe=name, ok=False, missing=[f"unknown probe '{name}'"],
            reason=f"no probe named '{name}' is registered",
            fix=f"valid probes: {', '.join(probe_names())}")
    try:
        return fn(params or [])
    except Exception as exc:  # a probe must never take the harness down
        logger.warning("probe %s crashed: %s", name, exc)
        return ProbeResult(
            probe=name, ok=False, missing=[name],
            reason=f"probe crashed: {exc}",
            fix="report this — the probe should degrade, never crash")
