"""
RedTeam Harness — Dynamic Target Priority Engine (v4.1)
=======================================================

Mid-engagement target re-prioritization for the autonomous agent.

Whereas the static `TargetPrioritizer` scores hosts *before* a campaign
starts (from port/service guesses), this engine re-scores targets
**live during the engagement** from actual findings:

  - Targets that yield critical/high findings get a BOOSTED phase budget
    (the exploit phase iterates longer — attack the hot host harder)
  - Targets that only ever produce info-level findings get CHILLED
    (fewer iterations, dropped down the queue)
  - The remaining target queue is re-ordered at each engagement step so
    the agent always attacks the most promising host next

Scoring model:
  priority_score = Σ severity_weight(finding) over all findings
  Severity weights: critical=10, high=7, medium=4, low=2, info=1

Phase budget policy (applied per target per phase):
  score >= BOOST_THRESHOLD   → budget × PHASE_BOOST_MULT (default 1.5)
  score <= CHILL_THRESHOLD   → budget × PHASE_CHILL_MULT (default 0.6)
  otherwise                  → base budget unchanged

Pure functions + no I/O → easily unit-testable.
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger("redteam.dynamic_priority")

# ── Severity → weight ──
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
    "unknown": 1.0,
}

# ── Score thresholds ──
BOOST_THRESHOLD = 7.0   # ≥ this → boost phase budgets
CHILL_THRESHOLD = 2.5   # ≤ this → chill phase budgets
NEUTRAL_SCORE = 0.5     # score for a target with no findings yet

# ── Budget multipliers ──
BOOST_MULT = 1.5        # base boost at threshold: 150% iterations
BOOST_SLOPE = 0.05      # +5% iterations per score point above threshold
CHILL_MULT = 0.6        # cold targets: 60% iterations
BOOST_FLOOR = 5         # minimum iterations for a boosted phase
CHILL_FLOOR = 1         # never go below 1 iteration
MAX_BUDGET_MULT = 3.0   # hard ceiling so one hot phase can't eat the whole engagement

# ── Tier labels ──
TIER_HOT = "hot"             # critical/high findings — priority target
TIER_STANDARD = "standard"   # medium findings
TIER_CHILLED = "chilled"     # low/info-only findings — deprioritize
TIER_NEUTRAL = "neutral"     # no findings yet


class DynamicPriorityEngine:
    """
    Scores targets from live findings and computes per-phase iteration
    budgets for the autonomous agent.

    Designed to operate on the agent's `TargetPhase` objects via duck
    typing — it only reads `phase_findings` (dict phase → list of
    {severity, ...}) and `current_phase`.
    """

    def score_target(self, phase_state: Any) -> float:
        """
        Compute the live priority score of a target from its findings.

        phase_state: object with `.phase_findings` (dict: phase → list of
        finding dicts each containing a 'severity' key).
        """
        findings = getattr(phase_state, "phase_findings", None)
        if not findings:
            return NEUTRAL_SCORE

        score = 0.0
        for phase, f_list in findings.items():
            for f in f_list or []:
                sev = str(f.get("severity", "info")).lower()
                score += SEVERITY_WEIGHTS.get(sev, SEVERITY_WEIGHTS["info"])
        return round(score, 2) or NEUTRAL_SCORE

    def tier(self, score: float, has_findings: bool = True,
             phase_state: Any = None) -> str:
        """Map a priority score to a tier label.

        Uses the same severity-based logic as ``phase_budget`` when a
        phase_state is provided, so the displayed tier always matches the
        applied budget: critical/high findings → hot, info/low-only →
        chilled (regardless of finding count), otherwise standard/neutral.
        """
        if phase_state is not None:
            sev = self.max_severity(phase_state)
            if sev in ("critical", "high"):
                return TIER_HOT
            if self._is_info_only(phase_state):
                return TIER_CHILLED
            if not self.has_findings(phase_state) and score <= CHILL_THRESHOLD:
                return TIER_NEUTRAL
            return TIER_STANDARD
        # Fallback for score-only callers (no phase_state available)
        if score >= BOOST_THRESHOLD:
            return TIER_HOT
        if score <= CHILL_THRESHOLD:
            return TIER_CHILLED if has_findings else TIER_NEUTRAL
        return TIER_STANDARD

    def findings_count(self, phase_state: Any) -> int:
        """Total number of findings across all phases of a target."""
        return self._findings_count(phase_state)

    def has_findings(self, phase_state: Any) -> bool:
        """True if the target has produced at least one finding."""
        return self._has_findings(phase_state)

    def phase_budget(self, phase_state: Any, phase: str,
                     base_budget: int) -> int:
        """
        Compute the effective iteration budget for a phase of a target.

        Boosts the budget when the target has high/critical findings
        (the more severe, the more iterations — graduated), chills it
        when the target's *highest* severity is info/low (hosts with
        only low-value findings get deprioritized regardless of how many
        info findings they produced), and leaves it unchanged otherwise.
        """
        score = self.score_target(phase_state)
        base = max(1, int(base_budget))

        # Boost only when the target actually has high/critical findings —
        # a port-rich host with many info-only findings is still
        # deprioritized, never boosted.
        if self.max_severity(phase_state) in ("critical", "high"):
            # Graduated boost: the more severe the findings, the more
            # iterations the phase gets — capped at MAX_BUDGET_MULT so one
            # hot phase can't consume the whole engagement budget, but
            # never below BOOST_FLOOR even for tiny base budgets.
            excess = max(0.0, score - BOOST_THRESHOLD)
            factor = min(MAX_BUDGET_MULT, BOOST_MULT + excess * BOOST_SLOPE)
            boosted = int(base * factor)
            capped = min(int(base * MAX_BUDGET_MULT), boosted)
            return max(BOOST_FLOOR, capped)
        if self._is_info_only(phase_state):
            return max(CHILL_FLOOR, int(base * CHILL_MULT))
        return base

    def reorder_targets(self, phase_states: Dict[str, Any]) -> List[str]:
        """
        Return target names ordered by live priority (highest first).

        Hot targets bubble to the front; chilled/neutral targets sink.
        Stable sort keeps the original order for equal scores.
        """
        return sorted(
            phase_states.keys(),
            key=lambda t: self.score_target(phase_states[t]),
            reverse=True,
        )

    def score_summary(self, phase_states: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build a dashboard-friendly priority summary."""
        ordered = self.reorder_targets(phase_states)
        out = []
        for rank, target in enumerate(ordered, start=1):
            ps = phase_states[target]
            score = self.score_target(ps)
            has = self.has_findings(ps)
            out.append({
                "rank": rank,
                "target": target,
                "score": score,
                "tier": self.tier(score, has, ps),
                "findings_count": self.findings_count(ps),
                "severity_counts": self._severity_counts(ps),
            })
        return out

    def max_severity(self, phase_state: Any) -> str:
        """Highest severity present in the target's findings ("" if none)."""
        counts = self._severity_counts(phase_state)
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev, 0) > 0:
                return sev
        return ""

    def _is_info_only(self, phase_state: Any) -> bool:
        """True when the target has findings but none above low severity."""
        return self.has_findings(phase_state) and \
            self.max_severity(phase_state) in ("low", "info")

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        return {
            "severity_weights": SEVERITY_WEIGHTS,
            "boost_threshold": BOOST_THRESHOLD,
            "chill_threshold": CHILL_THRESHOLD,
            "boost_multiplier": BOOST_MULT,
            "boost_slope": BOOST_SLOPE,
            "chill_multiplier": CHILL_MULT,
            "max_budget_multiplier": MAX_BUDGET_MULT,
        }

    # ── helpers ──
    @staticmethod
    def _has_findings(phase_state: Any) -> bool:
        findings = getattr(phase_state, "phase_findings", None)
        return bool(findings) and any(f_list for f_list in findings.values())

    @staticmethod
    def _findings_count(phase_state: Any) -> int:
        findings = getattr(phase_state, "phase_findings", None) or {}
        return sum(len(f_list or []) for f_list in findings.values())

    @staticmethod
    def _severity_counts(phase_state: Any) -> Dict[str, int]:
        findings = getattr(phase_state, "phase_findings", None) or {}
        counts = {}
        for f_list in findings.values():
            for f in f_list or []:
                sev = str(f.get("severity", "info")).lower()
                counts[sev] = counts.get(sev, 0) + 1
        return counts
