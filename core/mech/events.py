"""
RedTeam Harness — Mech-Unit Event Bus (v7.0 P1.6)

Typed events emitted by the executor and relayed to the cockpit. The
SocketIO channel mapping is defined here in one place (API.md documents the
schema) so dashboard wiring can never invent a channel name.

Ordering guarantee: every emission carries a monotonically increasing
sequence number per bus instance — the cockpit timeline sorts on `seq`,
so event order is stable even when callbacks run on different threads.
"""
import threading
import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger("redteam.mech.events")

# ── canonical event names ────────────────────────────────────────────────
PLAN_STATE = "plan_state"          # plan state transitions
STEP_STARTED = "step_started"      # a step begins (with attempt number)
STEP_COMPLETE = "step_complete"    # a step succeeded
STEP_FAILED = "step_failed"        # a step failed (before fallback/retry)
STEP_SKIPPED = "step_skipped"      # when: condition false
STEP_RETRY = "step_retry"          # a retry is scheduled
STEP_FALLBACK = "step_fallback"    # a fallback replaces a failed step
STEP_TIMEOUT = "step_timeout"      # a tool was killed on timeout (v7.1)
FINDING = "finding"                # a finding was extracted
NEXT_MOVES = "next_moves"          # VULN-GRAPH capitalization suggestions
PLAN_COMPLETE = "plan_complete"
PLAN_ABORTED = "plan_aborted"

# SocketIO channels: every mech event relays to "mech_<event>".
SOCKETIO_PREFIX = "mech_"


def socketio_channel(event: str) -> str:
    """The SocketIO channel for a mech event (single mapping point)."""
    return SOCKETIO_PREFIX + event


ALL_EVENTS = (
    PLAN_STATE, STEP_STARTED, STEP_COMPLETE, STEP_FAILED, STEP_SKIPPED,
    STEP_RETRY, STEP_FALLBACK, STEP_TIMEOUT, FINDING, NEXT_MOVES,
    PLAN_COMPLETE, PLAN_ABORTED,
)


class EventBus:
    """Thread-safe typed pub/sub with sequence numbers."""

    def __init__(self):
        self._subs: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {
            e: [] for e in ALL_EVENTS}
        self._seq = 0
        self._lock = threading.Lock()

    def subscribe(self, event: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        if event not in self._subs:
            raise ValueError(
                f"unknown mech event '{event}' — valid: {', '.join(ALL_EVENTS)}")
        self._subs[event].append(callback)

    def emit(self, event: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        """Emit an event to subscribers; returns the enriched payload.

        The enriched payload carries: event, seq, and the caller's fields.
        Subscriber exceptions are logged, never propagated — one bad
        dashboard handler must not kill an engagement.
        """
        if event not in self._subs:
            raise ValueError(
                f"unknown mech event '{event}' — valid: {', '.join(ALL_EVENTS)}")
        with self._lock:
            self._seq += 1
            seq = self._seq
        enriched = {"event": event, "seq": seq, **(payload or {})}
        for cb in self._subs.get(event, []):
            try:
                cb(enriched)
            except Exception as exc:
                logger.warning("mech event subscriber error (%s): %s", event, exc)
        return enriched

    def sequence(self) -> int:
        with self._lock:
            return self._seq
