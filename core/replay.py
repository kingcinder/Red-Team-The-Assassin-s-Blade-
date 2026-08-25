"""
RedTeam Harness — Engagement Replay System (v4.2)

Loads a completed engagement's persisted session data (messages + tool_log,
or a self-contained campaign replay bundle) and replays the exact sequence
of LLM decisions and tool executions for post-engagement analysis and
training-data generation.

Design:
  - Every persisted message/tool entry is normalized into a chronological
    ReplayEvent timeline (decision → execution → result grouping).
  - Assistant messages that carry tool-call JSON are "decisions"; the
    tool_log entries they spawned are matched back to them by
    (tool, args) signature so each step shows cause → effect.
  - Supports step-wise navigation (next/prev/seek), full analysis stats,
    markdown transcripts, and OpenAI-compatible training-export JSONL for
    fine-tuning a local model to pilot the harness.
  - 100% offline — everything is read from local JSON files.

Usage:
    replay = EngagementReplay.from_file("sessions/engage_xxx.json")
    replay.seek(0); replay.next()  # step through the timeline
    stats = replay.analyze()
    replay.export_training("out.jsonl")
"""
import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Iterator

logger = logging.getLogger("redteam.replay")

# ── Event types ──
EV_DECISION = "decision"        # LLM assistant message (may carry tool calls)
EV_EXECUTION = "execution"      # a tool execution from tool_log
EV_RESULT = "result"            # a tool_result message fed back to the LLM
EV_SYSTEM = "system"            # system message (phase transitions, nudges)
EV_USER = "user"                # user prompt
EV_FINDING = "finding"          # a recorded finding


# ═══════════════════════════════════════════════════════════════
# TOOL-CALL PARSING (mirrors orchestrator._parse_tool_calls)
# ═══════════════════════════════════════════════════════════════
def parse_tool_calls(text: str) -> List[Dict[str, Any]]:
    """Extract tool calls from an LLM response string.

    Handles {"tool_call": {...}}, {"tool_calls": [...]}, and bare
    {"tool": ..., "args": {...}} — the same three formats the
    orchestrator accepts.
    """
    if not text:
        return []
    data = _extract_json(text)
    if not data:
        return []
    tool_calls: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if "tool_call" in data and isinstance(data["tool_call"], dict):
            tc = data["tool_call"]
            if "tool" in tc:
                tool_calls.append({"tool": tc["tool"], "args": tc.get("args", {})})
        elif "tool" in data and isinstance(data.get("args", {}), dict):
            tool_calls.append({"tool": data["tool"], "args": data.get("args", {})})
        if "tool_calls" in data and isinstance(data["tool_calls"], list):
            for tc in data["tool_calls"]:
                if isinstance(tc, dict) and "tool" in tc:
                    tool_calls.append({"tool": tc["tool"],
                                       "args": tc.get("args", {})})
    # Deduplicate (preserve order, keep first)
    seen = set()
    unique = []
    for tc in tool_calls:
        key = (tc["tool"], json.dumps(tc.get("args", {}), sort_keys=True))
        if key not in seen:
            seen.add(key)
            unique.append(tc)
    return unique


def _extract_json(text: str) -> Optional[Any]:
    """Robust JSON extraction from arbitrary LLM text."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _sig(tool: str, args: Any) -> str:
    """Canonical (tool, args) signature for matching executions to decisions."""
    try:
        return f"{tool}:{json.dumps(args or {}, sort_keys=True, default=str)}"
    except Exception:
        return f"{tool}:{str(args)}"


def _ts_key(ts: Any, fallback: int) -> tuple:
    """Normalize a timestamp into a sortable key (never raises)."""
    if not ts:
        return (1, fallback)
    try:
        return (0, datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp())
    except Exception:
        return (1, fallback)


class ReplayEvent:
    """A single normalized event in the engagement timeline."""

    __slots__ = ("type", "ts", "seq", "step_index", "data")

    def __init__(self, etype: str, ts: Any, seq: int, step_index: int,
                 data: Dict[str, Any]):
        self.type = etype
        self.ts = ts
        self.seq = seq          # global chronological order
        self.step_index = step_index  # which decision-step it belongs to
        self.data = data

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "ts": self.ts, "seq": self.seq,
                "step_index": self.step_index, "data": self.data}


class EngagementReplay:
    """
    Replays a single engagement session.

    Data sources (auto-detected on load):
      - Session JSON: {"messages": [...], "tool_log": [...], "findings": [...]}
      - Task state.json: {"steps": [...], "findings": [...]}
      - Campaign bundle: {"type": "autonomous_campaign", "targets": {...}}
    """

    def __init__(self):
        self.session_id: str = ""
        self.meta: Dict[str, Any] = {}
        self._events: List[ReplayEvent] = []
        self._steps: List[Dict[str, Any]] = []
        self._cursor = -1
        self._messages: List[Dict[str, Any]] = []
        self._tool_log: List[Dict[str, Any]] = []
        self._findings: List[Dict[str, Any]] = []

    # ─────────────────────────────────────────────────────────────
    # CONSTRUCTORS
    # ─────────────────────────────────────────────────────────────
    @classmethod
    def from_file(cls, path: str) -> "EngagementReplay":
        """Load a replay from a session JSON / state.json / bundle file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Replay source not found: {path}")
        with open(path) as f:
            data = json.load(f)
        r = cls()
        r._ingest(data)
        r.meta["source_file"] = path
        r._finalize()
        return r

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngagementReplay":
        r = cls()
        r._ingest(data)
        r._finalize()
        return r

    def _ingest(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Replay source must be a JSON object")

        # Campaign bundle (autonomous) — embed per-target sessions
        if data.get("type") == "autonomous_campaign":
            self.session_id = data.get("campaign_id", data.get("id", "campaign"))
            self.meta = {k: v for k, v in data.items()
                         if k not in ("targets", "sessions", "messages",
                                      "tool_log", "findings")}
            # Merge all per-target messages/tool_log into one interleaved pool
            for target, tdata in (data.get("targets") or {}).items():
                for m in tdata.get("messages", []):
                    m = dict(m)
                    m.setdefault("target", target)
                    self._messages.append(m)
                for tl in tdata.get("tool_log", []):
                    tl = dict(tl)
                    tl.setdefault("target", target)
                    self._tool_log.append(tl)
                for f in tdata.get("findings", []):
                    f = dict(f)
                    f.setdefault("target", target)
                    self._findings.append(f)
            return

        # Standard session / state file
        self.session_id = str(data.get("id", data.get("session_id", "")))
        self.meta = {k: v for k, v in data.items()
                     if k not in ("messages", "tool_log", "findings", "steps")}
        self._messages = list(data.get("messages", []) or [])
        self._tool_log = list(data.get("tool_log", []) or [])

        # Task state.json variant: steps carry tool_calls + results
        # (orchestrator) OR workflow-engine keys (tool_name/args/output/status).
        for s in data.get("steps", []) or []:
            # Orchestrator-style step: explicit tool_calls + results
            for tc in s.get("tool_calls", []) or []:
                self._tool_log.append({
                    "tool": tc.get("tool", ""),
                    "args": tc.get("args", {}),
                    "result": {"exit_code": 0 if s.get("status") == "success" else 1,
                               "stdout_preview": (s.get("summary", "") or "")[:500],
                               "duration": s.get("duration", 0)},
                    "timestamp": s.get("timestamp"),
                })
            # Workflow-engine style step: single tool with args + output
            if not s.get("tool_calls") and s.get("tool_name"):
                self._tool_log.append({
                    "tool": s.get("tool_name", ""),
                    "args": s.get("args", {}),
                    "result": {
                        "exit_code": 0 if s.get("status") == "success" else 1,
                        "stdout_preview": str(s.get("output", s.get("summary", "")))[:500],
                        "duration": s.get("duration", 0),
                        "status": s.get("status", ""),
                    },
                    "timestamp": s.get("timestamp"),
                })
            self._messages.append({"role": "assistant",
                                   "content": s.get("llm_response", ""),
                                   "timestamp": s.get("timestamp")})
            for r in s.get("results", []) or []:
                self._messages.append({"role": "tool_result",
                                       "content": f"[TOOL: {r.get('tool', '')}] {r.get('summary', '')}",
                                       "timestamp": s.get("timestamp")})
            for f in s.get("findings", []) or []:
                self._findings.append(f)

        self._findings = list(data.get("findings", []) or [])

    # ─────────────────────────────────────────────────────────────
    # TIMELINE RECONSTRUCTION
    # ─────────────────────────────────────────────────────────────
    def _finalize(self) -> None:
        """Rebuild the decision→execution→result timeline."""
        # 1. Normalize all raw messages into ordered candidates
        msg_events: List[Dict[str, Any]] = []
        for i, m in enumerate(self._messages):
            role = (m.get("role") or "system").lower()
            content = str(m.get("content", "") or "")
            msg_events.append({
                "kind": "msg", "role": role, "content": content,
                "ts": m.get("timestamp"),
                "raw": m,
            })

        # 2. Normalize tool executions
        exec_events: List[Dict[str, Any]] = []
        for i, tl in enumerate(self._tool_log):
            res = tl.get("result", {}) or {}
            if not isinstance(res, dict):
                res = {}
            exit_code = res.get("exit_code")
            # Fallback: infer from a tool_result message later if missing
            exec_events.append({
                "kind": "exec", "tool": tl.get("tool", ""),
                "args": tl.get("args", {}),
                "exit_code": exit_code,
                "stdout_preview": res.get("stdout_preview", ""),
                "duration": res.get("duration"),
                "status": res.get("status",
                                  "success" if exit_code == 0 else "error"),
                "ts": tl.get("timestamp"),
                "target": tl.get("target", ""),
            })

        # 3. Match executions to their spawning decisions by signature.
        #    Iterate messages in order; when an assistant message contains
        #    tool calls, greedily consume matching executions from the pool.
        exec_pool = list(exec_events)
        used = set()
        decisions: List[Dict[str, Any]] = []

        for me in msg_events:
            if me["role"] == "assistant":
                calls = parse_tool_calls(me["content"])
                matched = []
                if calls:
                    want = [_sig(c.get("tool", ""), c.get("args", {}))
                            for c in calls]
                    for idx, ex in enumerate(exec_pool):
                        if idx in used:
                            continue
                        if _sig(ex["tool"], ex["args"]) in want:
                            matched.append(ex)
                            used.add(idx)
                            if len(matched) == len(want):
                                break
                decisions.append({"msg": me, "calls": calls,
                                  "executions": matched})
            else:
                decisions.append({"msg": me, "calls": [], "executions": []})

        # 4. Build final chronological event list with step grouping.
        events: List[ReplayEvent] = []
        step_index = -1
        seq = 0
        unmatched_execs = [e for i, e in enumerate(exec_pool) if i not in used]

        for d in decisions:
            role = d["msg"]["role"]
            if role == "assistant":
                # Each LLM assistant turn is its own decision-step (bump on
                # tool-call JSON or any non-empty content); tool_result and
                # executions attach to the step that spawned them.
                if d["calls"] or (d["msg"]["content"] and d["msg"]["content"].strip()):
                    step_index += 1
                ev_type = EV_DECISION
            elif role == "system":
                ev_type = EV_SYSTEM
            elif role == "tool_result":
                ev_type = EV_RESULT
            else:
                ev_type = EV_USER

            events.append(ReplayEvent(ev_type, d["msg"]["ts"], seq, step_index,
                                      {"role": role,
                                       "content": d["msg"]["content"],
                                       "target": d["msg"].get("target", "")}))
            seq += 1
            for ex in d["executions"]:
                events.append(ReplayEvent(EV_EXECUTION, ex["ts"], seq, step_index, {
                    "tool": ex["tool"], "args": ex["args"],
                    "exit_code": ex["exit_code"],
                    "stdout_preview": ex["stdout_preview"],
                    "duration": ex["duration"], "status": ex["status"],
                    "target": ex.get("target", ""),
                }))
                seq += 1

        # Clamp pre-decision system/user events to step 0 so the API
        # payload never exposes negative step indices.
        if events and events[0].step_index < 0:
            for e in events:
                if e.step_index < 0:
                    e.step_index = 0
                else:
                    break

        # 5. Unmatched executions (direct/tactical auto-runs) → own events
        for ex in unmatched_execs:
            events.append(ReplayEvent(EV_EXECUTION, ex["ts"], seq, step_index, {
                "tool": ex["tool"], "args": ex["args"],
                "exit_code": ex["exit_code"],
                "stdout_preview": ex["stdout_preview"],
                "duration": ex["duration"], "status": ex["status"],
                "target": ex.get("target", ""), "unmatched": True,
            }))
            seq += 1

        # 6. Findings as events (chronologically by timestamp)
        for f in self._findings:
            events.append(ReplayEvent(EV_FINDING, f.get("timestamp"), seq,
                                      step_index, f))
            seq += 1

        # 7. Stable sort by timestamp (fall back to seq for missing ts)
        events.sort(key=lambda e: _ts_key(e.ts, e.seq))
        # Reassign clean sequential indices
        for i, e in enumerate(events):
            e.seq = i
        self._events = events

        # 8. Build step summaries
        self._steps = []
        current = None
        for e in events:
            if e.type == EV_DECISION:
                current = {
                    "index": len(self._steps),
                    "ts": e.ts,
                    "decision": e.data.get("content", ""),
                    "tool_calls": parse_tool_calls(e.data.get("content", "")),
                    "executions": [],
                    "results": [],
                    "analysis": "",
                    "target": e.data.get("target", ""),
                }
                self._steps.append(current)
            elif current is not None:
                if e.type == EV_EXECUTION:
                    current["executions"].append(e.data)
                elif e.type == EV_RESULT:
                    current["results"].append(e.data.get("content", ""))
                elif e.type == EV_DECISION:
                    pass
                elif e.type == EV_SYSTEM and current and not current.get("analysis"):
                    current["analysis"] = e.data.get("content", "")
        self._cursor = -1

    # ─────────────────────────────────────────────────────────────
    # NAVIGATION
    # ─────────────────────────────────────────────────────────────
    @property
    def events(self) -> List[ReplayEvent]:
        return self._events

    @property
    def steps(self) -> List[Dict[str, Any]]:
        return self._steps

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def step_count(self) -> int:
        return len(self._steps)

    @property
    def position(self) -> int:
        return self._cursor

    def reset(self) -> "EngagementReplay":
        self._cursor = -1
        return self

    def next(self) -> Optional[ReplayEvent]:
        """Advance one event. Returns the event or None at the end."""
        if self._cursor + 1 >= len(self._events):
            return None
        self._cursor += 1
        return self._events[self._cursor]

    def prev(self) -> Optional[ReplayEvent]:
        """Rewind one event."""
        if self._cursor <= 0:
            return None
        self._cursor -= 1
        return self._events[self._cursor]

    def seek(self, index: int) -> Optional[ReplayEvent]:
        """Jump to an event by sequence index (clamped)."""
        if not self._events:
            return None
        self._cursor = max(0, min(index, len(self._events) - 1))
        return self._events[self._cursor]

    def current(self) -> Optional[ReplayEvent]:
        if 0 <= self._cursor < len(self._events):
            return self._events[self._cursor]
        return None

    def iter_events(self) -> Iterator[ReplayEvent]:
        """Yield every event in order without moving the cursor."""
        for e in self._events:
            yield e

    # ─────────────────────────────────────────────────────────────
    # ANALYSIS
    # ─────────────────────────────────────────────────────────────
    def analyze(self) -> Dict[str, Any]:
        """Aggregate post-engagement statistics."""
        execs = [e.data for e in self._events if e.type == EV_EXECUTION]
        decisions = [e for e in self._events if e.type == EV_DECISION]
        tool_usage: Dict[str, Dict[str, Any]] = {}
        for ex in execs:
            t = ex.get("tool", "?")
            d = tool_usage.setdefault(t, {"count": 0, "success": 0, "error": 0,
                                          "total_duration": 0.0})
            d["count"] += 1
            if ex.get("status") in ("success", None):
                d["success"] += 1
            else:
                d["error"] += 1
            d["total_duration"] += float(ex.get("duration") or 0)

        # Findings by severity
        sev_counts: Dict[str, int] = {}
        targets: Dict[str, Any] = {}
        for f in self._findings:
            sev = str(f.get("severity", "info")).lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            tgt = f.get("target", f.get("host", "")) or "?"
            if tgt not in targets:
                targets[tgt] = {"findings": 0, "critical": 0, "high": 0}
            targets[tgt]["findings"] += 1
            if sev in ("critical", "high"):
                targets[tgt][sev] = targets[tgt].get(sev, 0) + 1

        # Phase transitions detected from system messages
        transitions = []
        for e in self._events:
            if e.type == EV_SYSTEM:
                content = e.data.get("content", "")
                m = re.search(r"(?:Phase transition|Engagement Phase:)\s*[→: ]*\s*([A-Z]+)",
                              content, re.IGNORECASE)
                if m:
                    phase = m.group(1).upper()
                    if not transitions or transitions[-1]["phase"] != phase:
                        transitions.append({"phase": phase, "ts": e.ts})

        timestamps = [e.ts for e in self._events if e.ts]
        duration_s = None
        if len(timestamps) >= 2:
            try:
                t0 = datetime.fromisoformat(str(timestamps[0]).replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(str(timestamps[-1]).replace("Z", "+00:00"))
                duration_s = max(0, (t1 - t0).total_seconds())
            except Exception:
                duration_s = None

        return {
            "session_id": self.session_id,
            "events": len(self._events),
            "decisions": len(decisions),
            "steps": len(self._steps),
            "tool_executions": len(execs),
            "tools_used": len(tool_usage),
            "tool_usage": tool_usage,
            "findings": len(self._findings),
            "findings_by_severity": sev_counts,
            "targets": targets,
            "phase_transitions": transitions,
            "duration_seconds": duration_s,
            "success_rate": (round(sum(d["success"] for d in tool_usage.values()) /
                                   max(1, len(execs)) * 100, 1) if execs else None),
            "meta": {k: v for k, v in self.meta.items()
                     if not isinstance(v, (dict, list))},
        }

    # ─────────────────────────────────────────────────────────────
    # TRAINING EXPORT
    # ─────────────────────────────────────────────────────────────
    def export_training(self, out_path: Optional[str] = None,
                        format: str = "jsonl") -> List[Dict[str, Any]]:
        """
        Export the engagement as LLM fine-tuning data.

        format="jsonl": OpenAI-compatible tool-call conversation records —
          system prompt, user prompts, assistant decisions with tool_calls,
          and tool results. Ideal for fine-tuning a local model to pilot
          the harness.
        format="pairs": simple instruction/response pairs (decision text).
        """
        records: List[Dict[str, Any]] = []
        if format == "pairs":
            instruction = self.meta.get("objective", "")
            if not instruction:
                instruction = next((e.data.get("content", "") for e in self._events
                                    if e.type == EV_USER), "")
            for s in self._steps:
                if s.get("decision", "").strip():
                    records.append({"instruction": instruction,
                                    "input": "", "output": s["decision"]})
        else:
            sys_prompt = next((e.data.get("content", "") for e in self._events
                               if e.type == EV_SYSTEM), "")
            for s in self._steps:
                messages: List[Dict[str, Any]] = []
                if sys_prompt:
                    messages.append({"role": "system", "content": sys_prompt})
                if self.meta.get("objective"):
                    messages.append({"role": "user",
                                     "content": self.meta["objective"]})
                # One assistant message carrying BOTH the decision content
                # and its tool_calls (OpenAI-compatible fine-tuning shape),
                # followed by tool-role result messages.
                tool_calls = []
                for i, ex in enumerate(s.get("executions", [])):
                    tool_calls.append({
                        "id": f"call_{s['index']}_{i}",
                        "type": "function",
                        "function": {
                            "name": ex.get("tool", ""),
                            "arguments": json.dumps(ex.get("args", {})),
                        },
                    })
                assistant_msg: Dict[str, Any] = {
                    "role": "assistant",
                    "content": s.get("decision", ""),
                }
                if tool_calls:
                    assistant_msg["tool_calls"] = tool_calls
                messages.append(assistant_msg)
                for i, ex in enumerate(s.get("executions", [])):
                    messages.append({
                        "role": "tool",
                        "tool_call_id": f"call_{s['index']}_{i}",
                        "content": (ex.get("stdout_preview", "") or "")[:2000],
                    })
                if messages:
                    records.append({"messages": messages})

        if out_path:
            with open(out_path, "w") as f:
                for rec in records:
                    f.write(json.dumps(rec) + "\n")
            logger.info(f"Training export: {len(records)} records → {out_path}")
        return records

    # ─────────────────────────────────────────────────────────────
    # TRANSCRIPT
    # ─────────────────────────────────────────────────────────────
    def render_transcript(self, max_chars_per_output: int = 800) -> str:
        """Render the full engagement as a readable markdown transcript."""
        lines = [
            f"# Engagement Replay — {self.session_id or 'unknown'}",
            "",
        ]
        if self.meta.get("objective"):
            lines.append(f"**Objective**: {self.meta['objective']}")
            lines.append("")
        for e in self._events:
            d = e.data
            if e.type == EV_DECISION:
                content = d.get("content", "")
                if content.strip():
                    lines.append(f"### Step {e.step_index} — LLM Decision")
                    lines.append("")
                    lines.append(content.strip()[:max_chars_per_output])
                    lines.append("")
            elif e.type == EV_EXECUTION:
                exit_icon = "✅" if e.data.get("status") in ("success", None) else "❌"
                lines.append(f"- {exit_icon} **{d.get('tool', '?')}** "
                             f"args=`{json.dumps(d.get('args', {}), default=str)[:120]}` "
                             f"exit={d.get('exit_code')} "
                             f"({d.get('duration', '?')}s)"
                             + (f" target={d['target']}" if d.get("target") else ""))
                if d.get("stdout_preview"):
                    preview = str(d["stdout_preview"])[:300].replace("\n", " ")
                    lines.append(f"  ↳ {preview}")
            elif e.type == EV_RESULT:
                content = str(d.get("content", ""))[:200]
                if content.strip():
                    lines.append(f"  *result*: {content}")
            elif e.type == EV_SYSTEM:
                content = str(d.get("content", ""))[:200]
                if content.strip():
                    lines.append(f"> **SYSTEM**: {content}")
            elif e.type == EV_USER:
                content = str(d.get("content", ""))[:300]
                if content.strip():
                    lines.append(f"**USER**: {content}")
            elif e.type == EV_FINDING:
                lines.append(f"- 📌 FINDING [{str(d.get('severity', 'info')).upper()}] "
                             f"{d.get('title', d.get('summary', ''))}")
            lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Full serializable replay payload (for dashboard/API)."""
        return {
            "session_id": self.session_id,
            "meta": self.meta,
            "events": [e.to_dict() for e in self._events],
            "steps": self._steps,
            "analysis": self.analyze(),
            "transcript": self.render_transcript(),
        }
