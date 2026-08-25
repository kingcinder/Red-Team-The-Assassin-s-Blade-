"""
RedTeam Harness — Engagement Replay Tests (v4.2)

Validates the replay engine: timeline reconstruction, decision→execution
matching, navigation, analysis, training export, transcript rendering,
and campaign-bundle ingestion.
"""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.replay import (  # noqa: E402
    EngagementReplay,
    parse_tool_calls,
    EV_DECISION, EV_EXECUTION, EV_RESULT, EV_SYSTEM, EV_USER, EV_FINDING,
)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def build_session(messages, tool_log=None, findings=None, **meta):
    """Build a minimal session dict with timestamps."""
    return {
        "id": meta.get("id", "engage_test"),
        "name": meta.get("name", "Test Engagement"),
        "created": "2026-08-25T10:00:00",
        "messages": messages,
        "tool_log": tool_log or [],
        "findings": findings or [],
        "state": "complete",
    }


# ═══════════════════════════════════════════════════════════════
# 1. Tool-call parsing (three formats)
# ═══════════════════════════════════════════════════════════════
def test_parse_tool_calls():
    print("\n── parse_tool_calls ──")
    # Single legacy
    calls = parse_tool_calls('{"tool_call": {"tool": "nmap_scan", "args": {"target": "1.2.3.4"}}}')
    check("single tool_call", len(calls) == 1 and calls[0]["tool"] == "nmap_scan")
    # Batch
    calls = parse_tool_calls('{"tool_calls": [{"tool": "a", "args": {}}, {"tool": "b", "args": {}}]}')
    check("batch tool_calls", len(calls) == 2)
    # Bare
    calls = parse_tool_calls('{"tool": "nikto_scan", "args": {"target": "x"}}')
    check("bare tool", len(calls) == 1 and calls[0]["tool"] == "nikto_scan")
    # Text with JSON block
    calls = parse_tool_calls('Analysis text\n```json\n{"tool_call": {"tool": "whois_lookup", "args": {}}}\n```\nMore text')
    check("json block", len(calls) == 1 and calls[0]["tool"] == "whois_lookup")
    # Dedup
    calls = parse_tool_calls('{"tool_call": {"tool": "x", "args": {}}, "tool_calls": [{"tool": "x", "args": {}}]}')
    check("dedup", len(calls) == 1)
    # Plain analysis → none
    calls = parse_tool_calls("The scan is complete. No vulnerabilities found.")
    check("plain analysis → none", calls == [])


# ═══════════════════════════════════════════════════════════════
# 2. Timeline reconstruction + decision→execution matching
# ═══════════════════════════════════════════════════════════════
def test_timeline_and_matching():
    print("\n── timeline reconstruction ──")
    messages = [
        {"role": "system", "content": "You are a pentester.", "timestamp": "2026-08-25T10:00:00"},
        {"role": "user", "content": "Scan 1.2.3.4", "timestamp": "2026-08-25T10:00:01"},
        {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {"target": "1.2.3.4"}}}',
         "timestamp": "2026-08-25T10:00:02"},
        {"role": "tool_result", "content": "[TOOL: nmap_scan] 22/tcp open",
         "timestamp": "2026-08-25T10:00:03"},
        {"role": "assistant", "content": "Found port 22. Engagement complete.",
         "timestamp": "2026-08-25T10:00:04"},
    ]
    tool_log = [
        {"tool": "nmap_scan", "args": {"target": "1.2.3.4"},
         "result": {"exit_code": 0, "stdout_preview": "22/tcp open ssh",
                    "duration": 1.2, "status": "success"},
         "timestamp": "2026-08-25T10:00:03"},
    ]
    session = build_session(messages, tool_log)
    replay = EngagementReplay.from_dict(session)

    types = [e.type for e in replay.events]
    check("event types order", types == [EV_SYSTEM, EV_USER, EV_DECISION, EV_EXECUTION, EV_RESULT, EV_DECISION],
          f"got {types}")
    check("event count", replay.event_count == 6)
    check("step count", replay.step_count == 2)

    # Execution matched to its decision step
    exec_events = [e for e in replay.events if e.type == EV_EXECUTION]
    check("execution matched to decision", len(exec_events) == 1
          and exec_events[0].step_index == 0, f"step_index={exec_events[0].step_index if exec_events else None}")
    check("execution payload", exec_events and exec_events[0].data["tool"] == "nmap_scan"
          and exec_events[0].data["exit_code"] == 0)


# ═══════════════════════════════════════════════════════════════
# 3. Navigation
# ═══════════════════════════════════════════════════════════════
def test_navigation():
    print("\n── navigation ──")
    messages = [
        {"role": "assistant", "content": "Decision one", "timestamp": "t1"},
        {"role": "assistant", "content": "Decision two", "timestamp": "t2"},
        {"role": "assistant", "content": "Decision three", "timestamp": "t3"},
    ]
    replay = EngagementReplay.from_dict(build_session(messages))
    check("initial position", replay.position == -1)
    ev = replay.next()
    check("next() → event 0", ev is not None and ev.seq == 0 and replay.position == 0)
    ev = replay.seek(2)
    check("seek(2)", ev is not None and ev.seq == 2)
    ev = replay.prev()
    check("prev() → event 1", ev is not None and ev.seq == 1)
    replay.reset()
    check("reset", replay.position == -1)
    # Iterate all
    count = sum(1 for _ in replay.iter_events())
    check("iter_events count", count == 3)
    # End of replay
    replay.seek(2)
    check("next at end → None", replay.next() is None)
    # Out-of-range seek clamps
    ev = replay.seek(999)
    check("seek clamps high", ev is not None and ev.seq == 2)
    ev = replay.seek(-5)
    check("seek clamps low", ev is not None and ev.seq == 0)


# ═══════════════════════════════════════════════════════════════
# 4. Analysis
# ═══════════════════════════════════════════════════════════════
def test_analysis():
    print("\n── analysis ──")
    messages = [
        {"role": "assistant", "content": '{"tool_call": {"tool": "a", "args": {}}}',
         "timestamp": "2026-08-25T10:00:00"},
        {"role": "assistant", "content": '{"tool_call": {"tool": "b", "args": {}}}',
         "timestamp": "2026-08-25T10:00:01"},
    ]
    tool_log = [
        {"tool": "a", "args": {}, "result": {"exit_code": 0, "stdout_preview": "ok", "duration": 1.0, "status": "success"},
         "timestamp": "2026-08-25T10:00:00"},
        {"tool": "b", "args": {}, "result": {"exit_code": 1, "stdout_preview": "", "duration": 2.0, "status": "error"},
         "timestamp": "2026-08-25T10:00:01"},
    ]
    findings = [
        {"severity": "critical", "title": "RCE", "timestamp": "2026-08-25T10:00:02", "target": "1.2.3.4"},
        {"severity": "info", "title": "Port 22", "timestamp": "2026-08-25T10:00:03", "target": "1.2.3.4"},
    ]
    replay = EngagementReplay.from_dict(build_session(messages, tool_log, findings))
    stats = replay.analyze()
    check("tool usage counts", stats["tool_usage"]["a"]["count"] == 1
          and stats["tool_usage"]["b"]["count"] == 1)
    check("success rate 50%", stats["success_rate"] == 50.0, f"got {stats['success_rate']}")
    check("findings by severity", stats["findings_by_severity"].get("critical") == 1
          and stats["findings_by_severity"].get("info") == 1)
    check("targets rollup", stats["targets"]["1.2.3.4"]["findings"] == 2)
    check("duration computed", stats["duration_seconds"] == 3.0,
          f"got {stats['duration_seconds']}")
    check("tools_used", stats["tools_used"] == 2)


# ═══════════════════════════════════════════════════════════════
# 5. Training export
# ═══════════════════════════════════════════════════════════════
def test_training_export():
    print("\n── training export ──")
    messages = [
        {"role": "system", "content": "You are a pentester.", "timestamp": "t"},
        {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {"target": "1.2.3.4"}}}',
         "timestamp": "t"},
    ]
    tool_log = [
        {"tool": "nmap_scan", "args": {"target": "1.2.3.4"},
         "result": {"exit_code": 0, "stdout_preview": "22/tcp open", "duration": 1.0, "status": "success"},
         "timestamp": "t"},
    ]
    replay = EngagementReplay.from_dict(build_session(messages, tool_log))
    records = replay.export_training(format="jsonl")
    check("jsonl records", len(records) == 1)
    if records:
        msgs = records[0]["messages"]
        check("jsonl structure", any(m["role"] == "system" for m in msgs)
              and any(m["role"] == "assistant" and m.get("tool_calls") for m in msgs)
              and any(m["role"] == "tool" for m in msgs))
        tool_msg = next(m for m in msgs if m["role"] == "tool")
        check("jsonl tool content", tool_msg["content"] == "22/tcp open")
    # Pairs format
    pairs = replay.export_training(format="pairs")
    check("pairs records", len(pairs) == 1 and "output" in pairs[0])
    # File write
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "train.jsonl")
        replay.export_training(path)
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        check("file written", len(lines) == 1)


# ═══════════════════════════════════════════════════════════════
# 6. Transcript
# ═══════════════════════════════════════════════════════════════
def test_transcript():
    print("\n── transcript ──")
    messages = [
        {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {}}}', "timestamp": "t"},
    ]
    tool_log = [
        {"tool": "nmap_scan", "args": {}, "result": {"exit_code": 0, "stdout_preview": "port open", "duration": 1.0, "status": "success"},
         "timestamp": "t"},
    ]
    replay = EngagementReplay.from_dict(build_session(messages, tool_log))
    transcript = replay.render_transcript()
    check("transcript has title", "Engagement Replay" in transcript)
    check("transcript has tool line", "nmap_scan" in transcript)
    check("transcript has decision", "LLM Decision" in transcript)


# ═══════════════════════════════════════════════════════════════
# 7. Campaign bundle ingestion
# ═══════════════════════════════════════════════════════════════
def test_campaign_bundle():
    print("\n── campaign bundle ──")
    bundle = {
        "type": "autonomous_campaign",
        "campaign_id": "autonomous_test",
        "objective": "Compromise the web tier",
        "state": "complete",
        "start_time": "2026-08-25T10:00:00",
        "end_time": "2026-08-25T11:00:00",
        "total_steps": 2,
        "total_findings": 1,
        "targets_count": 2,
        "targets": {
            "10.0.0.1": {
                "target": "10.0.0.1",
                "messages": [
                    {"role": "assistant", "content": '{"tool_call": {"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}}',
                     "timestamp": "2026-08-25T10:00:01", "target": "10.0.0.1"},
                    {"role": "assistant", "content": "All done.", "timestamp": "2026-08-25T10:00:02", "target": "10.0.0.1"},
                ],
                "tool_log": [
                    {"tool": "nmap_scan", "args": {"target": "10.0.0.1"},
                     "result": {"exit_code": 0, "stdout_preview": "80/tcp open", "duration": 0.5, "status": "success"},
                     "timestamp": "2026-08-25T10:00:01", "target": "10.0.0.1"},
                ],
                "findings": [{"severity": "high", "title": "Open web port", "phase": "recon", "target": "10.0.0.1"}],
                "session_id": "engage_x",
                "completed": True,
            },
            "10.0.0.2": {
                "target": "10.0.0.2",
                "messages": [{"role": "assistant", "content": "Nothing found.", "timestamp": "2026-08-25T10:00:05", "target": "10.0.0.2"}],
                "tool_log": [],
                "findings": [],
                "session_id": "engage_y",
                "completed": True,
            },
        },
    }
    replay = EngagementReplay.from_dict(bundle)
    check("bundle session id", replay.session_id == "autonomous_test")
    check("bundle objective in meta", replay.meta.get("objective") == "Compromise the web tier")
    check("bundle findings merged", len(replay._findings) == 1)
    check("bundle executions", sum(1 for e in replay.events if e.type == EV_EXECUTION) == 1)
    # to_dict round-trip
    payload = replay.to_dict()
    check("to_dict has analysis", "analysis" in payload and payload["analysis"]["events"] == replay.event_count)
    check("to_dict transcript", "nmap_scan" in payload["transcript"])


# ═══════════════════════════════════════════════════════════════
# 8. Workflow task state.json fallback
# ═══════════════════════════════════════════════════════════════
def test_workflow_state_fallback():
    print("\n── workflow state.json fallback ──")
    # Workflow-engine steps carry tool_name/args/output/status, NOT the
    # orchestrator's tool_calls/llm_response/results keys.
    state = {
        "workflow": "web_chain",
        "status": "complete",
        "findings": [{"severity": "medium", "title": "Dir listing"}],
        "steps": [
            {"step_name": "nmap", "tool_name": "nmap_scan",
             "args": {"target": "10.0.0.9"},
             "output": "80/tcp open http", "status": "success",
             "duration": 3.1, "timestamp": "2026-08-25T10:00:00"},
            {"step_name": "gobuster", "tool_name": "gobuster_dir",
             "args": {"url": "http://10.0.0.9"},
             "output": "/admin  (Status: 200)", "status": "success",
             "duration": 5.2, "timestamp": "2026-08-25T10:00:05"},
        ],
    }
    replay = EngagementReplay.from_dict(state)
    execs = [e for e in replay.events if e.type == EV_EXECUTION]
    check("workflow executions extracted", len(execs) == 2,
          f"got {len(execs)}")
    tools = sorted(e.data["tool"] for e in execs)
    check("workflow tool names", tools == ["gobuster_dir", "nmap_scan"],
          f"got {tools}")
    check("workflow output preview", any("80/tcp open" in e.data.get("stdout_preview", "")
                                         for e in execs))
    check("workflow findings ingested", len(replay._findings) == 1)
    check("workflow meta preserved", replay.meta.get("workflow") == "web_chain")


# ═══════════════════════════════════════════════════════════════
# 9. File loading + robustness
# ═══════════════════════════════════════════════════════════════
def test_file_load_and_robustness():
    print("\n── file load + robustness ──")
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "session.json")
        with open(path, "w") as f:
            json.dump(build_session(
                [{"role": "assistant", "content": '{"tool_call": {"tool": "x", "args": {}}}', "timestamp": "t"}],
                [{"tool": "x", "args": {}, "result": {"exit_code": 0, "stdout_preview": "ok", "duration": 1.0, "status": "success"},
                  "timestamp": "t"}]),
                f)
        replay = EngagementReplay.from_file(path)
        check("from_file loads", replay.event_count >= 2)
        check("from_file source meta", "source_file" in replay.meta)

    # Empty / garbage resilience
    replay = EngagementReplay.from_dict({"id": "empty", "messages": [], "tool_log": [], "findings": []})
    check("empty session", replay.event_count == 0 and replay.analyze()["events"] == 0)
    try:
        EngagementReplay.from_dict([])
        check("list raises", False)
    except ValueError:
        check("list raises", True)


def main():
    test_parse_tool_calls()
    test_timeline_and_matching()
    test_navigation()
    test_analysis()
    test_training_export()
    test_transcript()
    test_campaign_bundle()
    test_workflow_state_fallback()
    test_file_load_and_robustness()
    print(f"\n=== {PASS} PASSED, {FAIL} FAILED ===")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
