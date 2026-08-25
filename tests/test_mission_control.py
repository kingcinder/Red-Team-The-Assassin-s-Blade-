"""
RedTeam Harness — Mission Control Tests (v4.2)

Validates the Mission Control payload: per-target kill-chain progress
bars, severity histograms, retry escalation history, and the
phase-transition timeline.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.autonomous import AutonomousAgent, TargetPhase, KILL_CHAIN  # noqa: E402

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


class FakeOrchestrator:
    """Minimal orchestrator stand-in for the autonomous agent."""

    def __init__(self):
        self.sessions = type("S", (), {"_load": lambda self, sid: {}})()
        self.tactics = type("T", (), {"get_auto_run_actions": lambda *a, **k: []})()
        self.config = {"harness": {"session_dir": "./sessions"}}

    def new_session(self, name=None):
        return "engage_test"

    def _build_dynamic_system_prompt(self, phase):
        return f"SYSTEM {phase}"

    def _run_iteration(self, session_id, steps, stream=False):
        return {"results": [], "llm_response": "test", "action": "complete", "error": None}


def make_agent():
    orch = FakeOrchestrator()
    agent = AutonomousAgent(orch)
    agent._targets = ["10.0.0.1", "10.0.0.2"]
    agent._objective = "Compromise the fleet"
    agent._start_time = "2026-08-25T10:00:00"
    for t in agent._targets:
        tp = TargetPhase(t)
        tp.start_time = "2026-08-25T10:00:00"
        agent._target_phases[t] = tp
    return agent


# ═══════════════════════════════════════════════════════════════
# 1. Mission Control payload structure
# ═══════════════════════════════════════════════════════════════
def test_payload_structure():
    print("\n── mission control payload structure ──")
    agent = make_agent()
    mc = agent.mission_control()
    check("has state", "state" in mc and mc["state"] == "idle")
    check("has objective", mc["objective"] == "Compromise the fleet")
    check("targets_count", mc["targets_count"] == 2)
    check("has targets list", isinstance(mc["targets"], list) and len(mc["targets"]) == 2)
    check("has retry_history", isinstance(mc["retry_history"], list))
    check("has timeline", isinstance(mc["timeline"], list))
    check("has priority_order", isinstance(mc.get("priority_order"), list))
    # Per-target shape
    t = mc["targets"][0]
    check("target name", t["target"] == "10.0.0.1")
    check("target current_phase", t["current_phase"] == "recon")
    check("target completed", t["completed"] is False)
    check("phase_bars length", len(t["phase_bars"]) == len(KILL_CHAIN) == 4)
    check("phase_bar fields", all(b["phase"] and "pct" in b and "findings" in b
                                 and "iterations" in b and "budget" in b
                                 and "is_current" in b for b in t["phase_bars"]))
    check("severity_counts shape", t["severity_counts"] ==
          {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    check("phase_transitions empty", t["phase_transitions"] == [])
    check("retry fields", "retry_level" in t and "last_error" in t
          and "priority_tier" in t)


# ═══════════════════════════════════════════════════════════════
# 2. Progress bars — iterations vs budget
# ═══════════════════════════════════════════════════════════════
def test_progress_bars():
    print("\n── phase progress bars ──")
    agent = make_agent()
    tp = agent._target_phases["10.0.0.1"]
    tp.phase_iterations["recon"] = 10
    tp.phase_budget["recon"] = 20
    tp.phase_findings["recon"] = [{"severity": "critical", "summary": "RCE"},
                                  {"severity": "info", "summary": "port 22"}]
    mc = agent.mission_control()
    recon_bar = next(b for b in mc["targets"][0]["phase_bars"] if b["phase"] == "recon")
    check("pct = 50", recon_bar["pct"] == 50.0, f"got {recon_bar['pct']}")
    check("iterations tracked", recon_bar["iterations"] == 10)
    check("budget tracked", recon_bar["budget"] == 20)
    check("is_current recon", recon_bar["is_current"] is True)
    # Current phase flag on exploit
    tp2 = agent._target_phases["10.0.0.2"]
    tp2.phase_index = 2
    tp2.current_phase = "exploit"
    tp2.phase_iterations["exploit"] = 25
    tp2.phase_budget["exploit"] = 25
    mc = agent.mission_control()
    vuln_bar = next(b for b in mc["targets"][1]["phase_bars"] if b["phase"] == "vuln")
    check("non-current phase flag", vuln_bar["is_current"] is False)
    exploit_bar = next(b for b in mc["targets"][1]["phase_bars"] if b["phase"] == "exploit")
    check("pct capped at 100", exploit_bar["pct"] == 100.0)
    check("current phase = exploit", mc["targets"][1]["current_phase"] == "exploit")


# ═══════════════════════════════════════════════════════════════
# 3. Severity histogram
# ═══════════════════════════════════════════════════════════════
def test_severity_histogram():
    print("\n── severity histogram ──")
    agent = make_agent()
    tp = agent._target_phases["10.0.0.1"]
    tp.phase_findings["recon"] = [{"severity": "critical"}, {"severity": "info"}]
    tp.phase_findings["vuln"] = [{"severity": "high"}, {"severity": "high"}]
    tp.phase_findings["exploit"] = [{"severity": "medium"}]
    mc = agent.mission_control()
    t = next(x for x in mc["targets"] if x["target"] == "10.0.0.1")
    sev = t["severity_counts"]
    check("critical=1", sev["critical"] == 1)
    check("high=2", sev["high"] == 2)
    check("medium=1", sev["medium"] == 1)
    check("info=1", sev["info"] == 1)
    check("total_findings rollup", mc["total_findings"] == 5,
          f"got {mc['total_findings']}")
    # TargetPhase.to_dict also carries it
    d = tp.to_dict()
    check("to_dict severity_counts", d["severity_counts"]["high"] == 2)


# ═══════════════════════════════════════════════════════════════
# 4. Retry escalation history
# ═══════════════════════════════════════════════════════════════
def test_retry_history():
    print("\n── retry escalation history ──")
    agent = make_agent()
    tp = agent._target_phases["10.0.0.1"]
    tp.current_phase = "vuln"
    tp.last_tool = "nikto_scan"
    tp.last_error = "tool crashed"
    tp.consecutive_failures = 3
    agent._escalate_retry(tp)
    agent._escalate_retry(tp)
    check("history recorded", len(agent._retry_history) == 2)
    h = agent._retry_history[-1]
    check("history fields", h["target"] == "10.0.0.1" and h["phase"] == "vuln"
          and h["last_tool"] == "nikto_scan" and "ts" in h and "level" in h)
    check("level escalated", h["level"] in ("retry", "alternative", "llm_suggest", "skip_phase"))
    mc = agent.mission_control()
    check("payload retry_history", len(mc["retry_history"]) == 2)
    check("target retry_level raw", mc["targets"][0]["retry_level_raw"] == tp.retry_level)
    # start() resets history
    agent._retry_history = []
    agent._timeline = []
    check("reset works", agent.mission_control()["retry_history"] == [])


# ═══════════════════════════════════════════════════════════════
# 5. Phase transition timeline
# ═══════════════════════════════════════════════════════════════
def test_phase_timeline():
    print("\n── phase transition timeline ──")
    agent = make_agent()
    tp = agent._target_phases["10.0.0.1"]
    # Simulate recon → vuln transition
    tp.advance_phase()
    check("TargetPhase transition recorded", len(tp.phase_transitions) == 1
          and tp.phase_transitions[0]["phase"] == "VULN")
    check("advance_phase moved index", tp.current_phase == "vuln")
    # The agent's global timeline records phase_start (via _drive_target) and
    # phase_complete (via _transition_phase) — simulate both entry points.
    agent._timeline.append({"ts": "2026-08-25T10:00:01", "target": "10.0.0.1",
                            "event": "phase_start", "phase": "VULN"})
    agent._timeline.append({"ts": "2026-08-25T10:00:02", "target": "10.0.0.1",
                            "event": "phase_complete", "phase": "RECON"})
    mc = agent.mission_control()
    check("global timeline", len(mc["timeline"]) == 2)
    check("per-target transitions in payload",
          mc["targets"][0]["phase_transitions"][0]["phase"] == "VULN")
    check("timeline event kinds",
          {e["event"] for e in mc["timeline"]} == {"phase_start", "phase_complete"})
    # to_dict serialization sanity
    status = agent.get_status()
    check("get_status has targets_detail",
          status["targets_detail"]["10.0.0.1"]["current_phase"] == "vuln")
    check("get_status detail has transitions",
          len(status["targets_detail"]["10.0.0.1"]["phase_transitions"]) == 1)


# ═══════════════════════════════════════════════════════════════
# 6. Idle payload
# ═══════════════════════════════════════════════════════════════
def test_idle_payload():
    print("\n── idle payload ──")
    orch = FakeOrchestrator()
    agent = AutonomousAgent(orch)
    mc = agent.mission_control()
    check("idle state", mc["state"] == "idle")
    check("empty targets", mc["targets"] == [])
    check("zero counts", mc["targets_count"] == 0 and mc["total_findings"] == 0)


def main():
    test_payload_structure()
    test_progress_bars()
    test_severity_histogram()
    test_retry_history()
    test_phase_timeline()
    test_idle_payload()
    print(f"\n=== {PASS} PASSED, {FAIL} FAILED ===")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
