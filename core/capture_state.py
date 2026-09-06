"""
RedTeam Harness — Capture Interface State Store (v6.3)

Backs the cockpit's localStorage persistence with a server-side mirror so
API / CLI / autonomous paths that bypass the cockpit still default wireless
and sniffing tools to the adapter the operator last used.

The cockpit keeps its own localStorage copy for instant UI restore; this
module is the source of truth for *execution*. `execute_direct()` consults
it to fill blank/missing `{{interface}}` args, and explicit picks made by
any path (cockpit, API, CLI, autonomous) are persisted here so the last-used
adapter survives dashboard reloads, harness restarts, and non-cockpit callers.
"""
import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("redteam.capture_state")

STATE_FILENAME = "capture_interface.json"

# Categories that always want an interface even if the tool doesn't declare
# the param explicitly (defense in depth for tools whose params are dynamic).
IFACE_CATEGORIES = {"wireless", "sniffing"}

# Params that count as "no interface supplied" (blank, missing, or an
# unfilled {{placeholder}} that made it through template substitution).
_PLACEHOLDER = "{{"


class CaptureStateStore:
    """Thread-safe JSON-backed store for the last-used capture interface."""

    def __init__(self, session_dir: str = "./sessions"):
        self._path = os.path.join(session_dir, STATE_FILENAME)
        self._lock = threading.Lock()

    # ── persistence ────────────────────────────────────────────────────
    def _read(self) -> Dict[str, Any]:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("capture_state: could not read %s: %s", self._path, exc)
            return {}

    @staticmethod
    def _clean(value: Any) -> Optional[str]:
        """Return the trimmed string value, or None if blank/non-string."""
        if not isinstance(value, str):
            return None
        cleaned = value.strip()
        return cleaned or None

    def _write(self, payload: Dict[str, Any]) -> bool:
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            return True
        except OSError as exc:
            logger.warning("capture_state: could not write %s: %s", self._path, exc)
            return False

    def get(self) -> Optional[str]:
        """Return the last-used capture interface, or None."""
        with self._lock:
            return self._clean(self._read().get("interface"))

    def set(self, interface: str) -> bool:
        """Persist an explicit capture-interface pick. No-ops on blanks."""
        name = self._clean(interface) if interface is not None else None
        if not name:
            return False
        with self._lock:
            payload = self._read()
            payload["interface"] = name
            payload["updated_at"] = time.time()
            return self._write(payload)

    def clear(self) -> bool:
        """Drop the stored state (e.g. explicit user reset)."""
        with self._lock:
            try:
                if os.path.exists(self._path):
                    os.remove(self._path)
                return True
            except OSError as exc:
                logger.warning("capture_state: could not clear %s: %s", self._path, exc)
                return False

    # ── scan context (v6.3.1) ─────────────────────────────────────────
    def get_scan(self) -> Dict[str, Any]:
        """Return the last airodump scan hints {channel, bssid} or {}."""
        with self._lock:
            data = self._read()
            result = {}
            channel = self._clean(data.get("channel"))
            bssid = self._clean(data.get("bssid"))
            if channel:
                result["channel"] = channel
            if bssid:
                result["bssid"] = bssid
            return result

    def set_scan(self, channel: str = None, bssid: str = None) -> bool:
        """Persist {channel, bssid} hints from the last airodump scan."""
        channel = self._clean(channel) if channel is not None else None
        bssid = self._clean(bssid) if bssid is not None else None
        if not channel and not bssid:
            return False
        with self._lock:
            payload = self._read()
            if channel:
                payload["channel"] = channel
            if bssid:
                payload["bssid"] = bssid
            payload["updated_at"] = time.time()
            payload.setdefault("interface", payload.get("interface"))
            return self._write(payload)


# ── pure defaulting logic (unit-testable without a store) ──────────────
def needs_interface(category: str, parameters: Optional[Dict[str, Any]]) -> bool:
    """True when a tool invocation should receive interface defaulting.

    Wireless/sniffing categories always qualify; any other tool that
    declares an `interface` parameter qualifies too.
    """
    if category in IFACE_CATEGORIES:
        return True
    return bool(parameters) and "interface" in parameters


def _is_blank(value: Any) -> bool:
    """True when an arg is missing, empty, or an unfilled {{placeholder}}."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip() or _PLACEHOLDER in value
    return False


def default_interface_arg(
    args: Dict[str, Any],
    category: str,
    parameters: Optional[Dict[str, Any]],
    last_used: Optional[str],
) -> tuple[Dict[str, Any], bool]:
    """Fill a blank/missing interface arg from `last_used`.

    Returns (effective_args, defaulted) where `defaulted` is True only when
    an interface was actually injected. Explicit (non-blank) picks are left
    untouched so the caller persists them upstream.
    """
    args = dict(args or {})
    if not needs_interface(category, parameters):
        return args, False
    if not _is_blank(args.get("interface")):
        return args, False
    if last_used:
        args["interface"] = last_used
        return args, True
    return args, False


# Adapter-typed params that can carry a scan hint (channel/bssid). Only
# channel is EVER auto-injected on the backend — bssid identifies a specific
# AP, which is an active targeting decision, so it stays a *suggested hint*.
HINT_CATEGORIES = {"wireless", "sniffing"}


def _param_declared(parameters: Optional[Dict[str, Any]], name: str) -> bool:
    return bool(parameters) and name in parameters


def default_sniff_args(
    args: Dict[str, Any],
    category: str,
    parameters: Optional[Dict[str, Any]],
    last_used: Optional[str],
    scan_hints: Optional[Dict[str, Any]] = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Extend interface defaulting to the other adapter-typed params.

    For wireless/sniffing tools (or any tool declaring the params):
      - inject the persisted interface when blank/missing (as before);
      - inject a channel hint from the last airodump scan when the tool
        declares `channel` and the operator left it blank;
      - NEVER auto-inject bssid (an explicit targeting call); it is only
        exposed via the returned `hints` for the cockpit to suggest.

    Returns (effective_args, injected) where `injected` is a dict of what
    was filled ("interface", "channel"). Input dict is never mutated.
    """
    args = dict(args or {})
    injected: Dict[str, Any] = {}

    if needs_interface(category, parameters) and _is_blank(args.get("interface")) \
            and last_used:
        args["interface"] = last_used
        injected["interface"] = last_used

    if category in HINT_CATEGORIES and _param_declared(parameters, "channel") \
            and _is_blank(args.get("channel")):
        channel = (scan_hints or {}).get("channel")
        if channel:
            args["channel"] = channel
            injected["channel"] = channel

    return args, injected
