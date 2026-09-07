"""
RedTeam Harness — Mech-Unit Plan State (v7.0 P1.5)

Plan state machine + atomic persistence + resume.

States: COMPILED → RUNNING ⇄ PAUSED → DONE | FAILED | ABORTED

Every mutation is persisted atomically to <plan_dir>/state.json via
core.state_store.atomic_write_json, so a crash (kill -9, power loss) never
corrupts the run record and any plan can be resumed from its last
persisted step boundary.
"""
import os
import enum
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.state_store import atomic_write_json, read_json

logger = logging.getLogger("redteam.mech.state")


class PlanState(str, enum.Enum):
    COMPILED = "compiled"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"
    ABORTED = "aborted"


class StepState(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"      # when: condition false
    FALLBACK = "fallback"    # replaced by a fallback step


# Legal transitions (state machine discipline, mirrors autonomous.py style)
_PLAN_TRANSITIONS = {
    PlanState.COMPILED: {PlanState.RUNNING, PlanState.ABORTED},
    PlanState.RUNNING: {PlanState.PAUSED, PlanState.DONE, PlanState.FAILED,
                        PlanState.ABORTED},
    PlanState.PAUSED: {PlanState.RUNNING, PlanState.ABORTED},
    PlanState.DONE: set(),
    PlanState.FAILED: set(),
    PlanState.ABORTED: set(),
}


@dataclass
class StepRecord:
    """Persisted record of one step execution."""
    step: str
    state: str = StepState.PENDING.value
    attempts: int = 0
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    output_file: str = ""
    error: str = ""
    finding: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step, "state": self.state, "attempts": self.attempts,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "output_file": self.output_file, "error": self.error,
            "finding": self.finding,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "StepRecord":
        return StepRecord(
            step=d.get("step", ""), state=d.get("state", StepState.PENDING.value),
            attempts=d.get("attempts", 0), exit_code=d.get("exit_code"),
            duration_seconds=d.get("duration_seconds"),
            output_file=d.get("output_file", ""), error=d.get("error", ""),
            finding=d.get("finding", ""))


@dataclass
class PlanRunState:
    """The full persisted run state of one plan."""
    plan_id: str
    intent_id: str
    plan_dir: str
    state: str = PlanState.COMPILED.value
    current_step: str = ""
    step_order: List[str] = field(default_factory=list)
    records: Dict[str, StepRecord] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""
    error: str = ""

    # ── transitions ──────────────────────────────────────────────────
    def _transition(self, new: PlanState) -> None:
        cur = PlanState(self.state)
        if new not in _PLAN_TRANSITIONS[cur]:
            raise ValueError(
                f"illegal plan state transition {cur.value} → {new.value}")
        self.state = new.value

    def start(self) -> None:
        self._transition(PlanState.RUNNING)
        import time
        self.started_at = self.started_at or time.strftime("%Y-%m-%dT%H:%M:%S")

    def pause(self) -> None:
        self._transition(PlanState.PAUSED)

    def resume(self) -> None:
        self._transition(PlanState.RUNNING)

    def complete(self) -> None:
        self._transition(PlanState.DONE)
        import time
        self.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    def fail(self, error: str) -> None:
        self._transition(PlanState.FAILED)
        self.error = error
        import time
        self.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    def abort(self) -> None:
        self._transition(PlanState.ABORTED)
        import time
        self.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    # ── step bookkeeping ─────────────────────────────────────────────
    def set_step_order(self, names: List[str]) -> None:
        self.step_order = list(names)
        for name in names:
            self.records.setdefault(name, StepRecord(step=name))

    def mark_step_started(self, name: str) -> None:
        rec = self.records[name]
        rec.state = StepState.RUNNING.value
        rec.attempts += 1
        self.current_step = name

    def mark_step_complete(self, name: str, exit_code: int,
                           duration: float, output_file: str = "",
                           finding: str = "") -> None:
        rec = self.records[name]
        rec.state = StepState.SUCCESS.value
        rec.exit_code = exit_code
        rec.duration_seconds = duration
        rec.output_file = output_file
        rec.finding = finding
        self.current_step = ""

    def mark_step_failed(self, name: str, error: str,
                         exit_code: Optional[int] = None,
                         duration: float = 0.0) -> None:
        rec = self.records[name]
        rec.state = StepState.FAILED.value
        rec.error = error
        rec.exit_code = exit_code
        rec.duration_seconds = duration
        self.current_step = ""

    def mark_step_interrupted(self, name: str) -> None:
        """Step was mid-flight when the plan was aborted/paused — no outcome
        is recorded; the attempt count is kept as evidence."""
        rec = self.records[name]
        rec.state = StepState.PENDING.value
        self.current_step = ""

    def mark_step_skipped(self, name: str) -> None:
        self.records[name].state = StepState.SKIPPED.value

    def mark_step_fallback(self, name: str) -> None:
        self.records[name].state = StepState.FALLBACK.value

    def add_fallback_record(self, name: str) -> None:
        self.records.setdefault(name, StepRecord(step=name))
        if name not in self.step_order:
            self.step_order.append(name)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)

    def next_pending_step(self) -> Optional[str]:
        """First step in order not yet terminal — the resume point."""
        terminal = {StepState.SUCCESS.value, StepState.FAILED.value,
                    StepState.SKIPPED.value, StepState.FALLBACK.value}
        for name in self.step_order:
            if self.records[name].state not in terminal:
                return name
        return None

    # ── persistence ──────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id, "intent_id": self.intent_id,
            "plan_dir": self.plan_dir, "state": self.state,
            "current_step": self.current_step,
            "step_order": list(self.step_order),
            "records": {k: v.to_dict() for k, v in self.records.items()},
            "findings": list(self.findings),
            "started_at": self.started_at, "ended_at": self.ended_at,
            "error": self.error,
        }

    def save(self) -> str:
        path = os.path.join(self.plan_dir, "state.json")
        atomic_write_json(path, self.to_dict())
        return path

    @staticmethod
    def load(plan_dir: str) -> Optional["PlanRunState"]:
        data = read_json(os.path.join(plan_dir, "state.json"))
        if not data:
            return None
        st = PlanRunState(
            plan_id=data.get("plan_id", ""), intent_id=data.get("intent_id", ""),
            plan_dir=data.get("plan_dir", plan_dir),
            state=data.get("state", PlanState.COMPILED.value),
            current_step=data.get("current_step", ""),
            step_order=list(data.get("step_order", [])),
            findings=list(data.get("findings", [])),
            started_at=data.get("started_at", ""),
            ended_at=data.get("ended_at", ""),
            error=data.get("error", ""))
        for name, rec in data.get("records", {}).items():
            st.records[name] = StepRecord.from_dict(rec)
        return st

    # ── view ─────────────────────────────────────────────────────────
    def summary(self) -> Dict[str, Any]:
        done = sum(1 for r in self.records.values() if r.state in
                   (StepState.SUCCESS.value, StepState.SKIPPED.value,
                    StepState.FALLBACK.value, StepState.FAILED.value))
        return {
            "plan_id": self.plan_id, "intent_id": self.intent_id,
            "state": self.state, "current_step": self.current_step,
            "steps_total": len(self.step_order), "steps_done": done,
            "findings_count": len(self.findings),
            "started_at": self.started_at, "ended_at": self.ended_at,
            "error": self.error,
        }
