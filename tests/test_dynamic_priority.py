#!/usr/bin/env python3
"""
RedTeam Harness — Dynamic Priority Engine Tests (v4.1)

Verifies mid-engagement target re-prioritization:
  - Severity-weighted scoring from live findings
  - Phase budget boost for critical/high findings
  - Phase budget chill for info-only findings
  - Queue re-ordering (hot targets first, chilled targets sink)
  - Integration with the autonomous agent's TargetPhase
"""
import os
import sys
import py_compile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Compile checks
for m in ["core/dynamic_priority.py", "core/autonomous.py"]:
    try:
        py_compile.compile(m, doraise=True)
        print(f"OK {m}")
    except py_compile.PyCompileError as e:
        print(f"FAIL {m}: {e}")
        sys.exit(1)

from core.dynamic_priority import (
    DynamicPriorityEngine,
    BOOST_THRESHOLD, CHILL_THRESHOLD,
    BOOST_MULT, BOOST_SLOPE, CHILL_MULT,
    BOOST_FLOOR, MAX_BUDGET_MULT,
    TIER_HOT, TIER_CHILLED, TIER_STANDARD, TIER_NEUTRAL,
)
from core.autonomous import TargetPhase, KILL_CHAIN

engine = DynamicPriorityEngine()


class FakePhase:
    """Minimal duck-type of TargetPhase.phase_findings for pure tests."""

    def __init__(self, findings):
        self.phase_findings = {p: list(findings.get(p, [])) for p in KILL_CHAIN}
        self.current_phase = "recon"


def _finding(severity):
    return {"tool": "nmap_scan", "summary": "x", "severity": severity}


# 2. Score — no findings → neutral
no_findings = FakePhase({})
score = engine.score_target(no_findings)
assert score == 0.5, f"expected neutral 0.5, got {score}"
print("score_target (no findings → neutral): OK")

# 3. Score — critical findings → high score
hot = FakePhase({"recon": [_finding("critical"), _finding("critical")]})
score = engine.score_target(hot)
assert score == 20.0, f"expected 20.0, got {score}"
assert engine.tier(score, True) == TIER_HOT
print("score_target (2× critical = 20.0, hot tier): OK")

# 4. Score — mixed severities
mixed = FakePhase({"vuln": [_finding("high"), _finding("medium"), _finding("info")]})
score = engine.score_target(mixed)
assert score == 12.0, f"expected 12.0 (7+4+1), got {score}"
assert engine.tier(score, True) == TIER_HOT
print("score_target (high+medium+info = 12.0): OK")

# 5. Score — info-only → chilled tier
cold = FakePhase({"recon": [_finding("info"), _finding("info")]})
score = engine.score_target(cold)
assert score == 2.0, f"expected 2.0, got {score}"
assert engine.tier(score, True) == TIER_CHILLED
print("score_target (2× info = 2.0, chilled tier): OK")

# 6. Budget — graduated boost for hot target
# score=20 (2× critical), excess=13, factor=1.5+13*0.05=2.15 → int(20*2.15)=43
budget = engine.phase_budget(hot, "exploit", 20)
excess = 20 - BOOST_THRESHOLD
factor = min(MAX_BUDGET_MULT, BOOST_MULT + excess * BOOST_SLOPE)
expected = max(BOOST_FLOOR, int(20 * factor))
assert budget == expected, f"expected boosted {expected}, got {budget}"
assert budget > 20, f"boost should exceed base, got {budget}"
print(f"phase_budget (hot exploit 20 → {budget}): OK")

# 7. Budget — chill for info-only target
budget = engine.phase_budget(cold, "exploit", 20)
expected = max(1, int(20 * CHILL_MULT))
assert budget == expected, f"expected chilled {expected}, got {budget}"
assert budget < 20, f"chill should drop below base, got {budget}"
print(f"phase_budget (info-only exploit 20 → {budget}): OK")

# 8. Budget — unchanged for no-findings target
budget = engine.phase_budget(no_findings, "exploit", 20)
assert budget == 20, f"expected unchanged 20, got {budget}"
print("phase_budget (no findings → unchanged): OK")

# 8b. Budget — port-rich info-only host is STILL chilled (severity-based)
# 5 info findings = score 5.0 (above CHILL_THRESHOLD), but highest severity
# is info → deprioritized regardless of finding count.
port_rich = FakePhase({"recon": [_finding("info")] * 5})
budget = engine.phase_budget(port_rich, "exploit", 20)
expected = max(1, int(20 * CHILL_MULT))
assert budget == expected, f"expected chilled {expected}, got {budget}"
assert budget < 20, f"port-rich info-only host should be chilled, got {budget}"
print(f"phase_budget (5× info-only → {budget}, severity-based chill): OK")

# 8c. Budget — 7+ info-only findings NEVER trigger boost (severity beats score)
# score 7.0 would pass BOOST_THRESHOLD, but max severity is info → still chilled.
seven_info = FakePhase({"recon": [_finding("info")] * 7})
assert engine.score_target(seven_info) >= BOOST_THRESHOLD, "precondition: score >= boost threshold"
budget = engine.phase_budget(seven_info, "exploit", 20)
expected = max(1, int(20 * CHILL_MULT))
assert budget == expected, f"7× info-only must NOT boost; expected chilled {expected}, got {budget}"
assert engine.tier(engine.score_target(seven_info), True, seven_info) == TIER_CHILLED
print(f"phase_budget (7× info-only → {budget}, severity beats score): OK")

# 9. Budget — never below floor
tiny = FakePhase({"recon": [_finding("info")]})
budget = engine.phase_budget(tiny, "exploit", 1)
assert budget >= 1, f"expected floor 1, got {budget}"
print("phase_budget (floor enforcement): OK")

# 9b. Budget — hard ceiling so one hot phase can't eat the whole engagement
very_hot = FakePhase({"recon": [_finding("critical")] * 20})  # score 200
budget = engine.phase_budget(very_hot, "exploit", 20)
ceiling = int(20 * MAX_BUDGET_MULT)
assert budget <= ceiling, f"budget {budget} exceeds ceiling {ceiling}"
assert budget == ceiling, f"expected ceiling {ceiling}, got {budget}"
print(f"phase_budget (ceiling {budget} <= {ceiling}): OK")

# 10. Reorder — hot target first, empty/neutral host last
phases = {
    "cold.host": cold,          # 2.0 (2× info)
    "hot.host": hot,            # 20.0 (2× critical)
    "empty.host": no_findings,  # 0.5 neutral — no findings at all
}
ordered = engine.reorder_targets(phases)
assert ordered[0] == "hot.host", f"hot target should be first: {ordered}"
assert ordered[-1] == "empty.host", f"empty host (0.5) should be last: {ordered}"
assert ordered[1] == "cold.host", f"info-only host (2.0) ranks above empty (0.5): {ordered}"
assert set(ordered) == set(phases), f"all targets must remain: {ordered}"
print(f"reorder_targets ({ordered}): OK")

# 11. Score summary — dashboard payload
summary = engine.score_summary(phases)
assert summary[0]["target"] == "hot.host"
assert summary[0]["rank"] == 1
assert "severity_counts" in summary[0]
assert summary[1]["target"] == "cold.host"
assert summary[1]["tier"] == TIER_CHILLED, f"expected chilled, got {summary[1]}"
assert summary[2]["target"] == "empty.host"
assert summary[2]["tier"] == TIER_NEUTRAL, f"expected neutral, got {summary[2]}"
print("score_summary (dashboard payload): OK")

# 12. Integration — TargetPhase fields updated by engine
tp = TargetPhase("192.168.1.10")
tp.phase_findings["recon"].append(_finding("critical"))
tp.priority_score = engine.score_target(tp)
tp.priority_tier = engine.tier(tp.priority_score, has_findings=True)
tp.phase_budget["exploit"] = engine.phase_budget(tp, "exploit", 20)
assert tp.priority_score == 10.0, f"expected 10.0, got {tp.priority_score}"
assert tp.priority_tier == TIER_HOT
assert tp.phase_budget["exploit"] > 20
d = tp.to_dict()
assert d["priority_score"] == 10.0
assert d["priority_tier"] == TIER_HOT
assert d["phase_budget"]["exploit"] > 20
print("TargetPhase integration (score/tier/budget in to_dict): OK")

# 13. Integration — info-only target gets chilled in TargetPhase
tp2 = TargetPhase("192.168.1.20")
tp2.phase_findings["recon"].append(_finding("info"))
tp2.priority_score = engine.score_target(tp2)
tp2.priority_tier = engine.tier(tp2.priority_score, has_findings=True)
tp2.phase_budget["exploit"] = engine.phase_budget(tp2, "exploit", 20)
assert tp2.priority_tier == TIER_CHILLED
assert tp2.phase_budget["exploit"] < 20
print("TargetPhase integration (info-only chilled): OK")

# 14. get_stats
stats = engine.get_stats()
assert stats["boost_threshold"] == BOOST_THRESHOLD
assert stats["chill_threshold"] == CHILL_THRESHOLD
assert stats["boost_multiplier"] == BOOST_MULT
print("get_stats: OK")

print("\n=== ALL 14 TESTS PASSED ===")
