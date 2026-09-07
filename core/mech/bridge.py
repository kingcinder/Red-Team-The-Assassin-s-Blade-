"""
RedTeam Harness — Legacy/Mech Bridge (v7.0 P5.4)

Lets the autonomous campaign drive Mech-Unit plans instead of LLM
iterations when the harness runs in mech mode — while keeping the legacy
v6 path byte-for-byte unchanged when mode is legacy (or the key is absent,
the default for every pre-v7 config).

Mapping (manifest P5.4):
  MIN_FINDINGS_PER_PHASE-style budgets → plan step budgets. The bridge
  drives ONE intent plan per target per capitalization round:
    1. pick the highest-scoring VULN-GRAPH move for the target's findings
       (or the recon-seeded ap.discovered vertex on a cold target),
    2. compile + execute that intent plan with per-plan budgets = the
       autonomous phase budgets,
    3. feed plan findings back into the campaign (dynamic priority sees
       them) and loop until the engagement budget is exhausted or the
       graph offers nothing further.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("redteam.mech.bridge")


def harness_mode(config: Optional[dict]) -> str:
    """Effective harness mode. DEFAULT IS LEGACY — no key, no change."""
    if not isinstance(config, dict):
        return "legacy"
    return str(config.get("harness", {}).get("mode", "legacy")).lower()


class MechCampaignDriver:
    """Drives one target through VULN-GRAPH-selected intent plans.

    Used by AutonomousAgent._drive_target when mode == 'mech'. Reuses the
    target's phase budgets (MAX_ITERATIONS_PER_PHASE semantics) as plan
    budgets so Mission Control numbers stay meaningful.
    """

    def __init__(self, orchestrator, mech_unit):
        self.orch = orchestrator
        self.unit = mech_unit
        self._log: List[Dict[str, Any]] = []

    def drive_target(self, target: str,
                     findings: Optional[List[Dict[str, Any]]] = None,
                     max_rounds: int = 3) -> List[Dict[str, Any]]:
        """Run up to max_rounds capitalization rounds against one target.

        Returns the plan-run summaries (one per executed round) — the
        campaign folds them into phase_findings via the caller.
        """
        findings = list(findings or [])
        rounds: List[Dict[str, Any]] = []

        for round_no in range(1, max_rounds + 1):
            # 1. Next move (VULN-GRAPH, deterministic).
            moves = self.unit.suggest_moves(findings)
            move = next((m for m in moves if m["score"] > 0 and m["probe_ok"]),
                        None)
            if move is None:
                logger.info("mech bridge: no viable move for %s — stopping",
                            target)
                break

            # 2. Compile with the target's accumulated facts.
            try:
                plan = self.unit.compile(
                    move["intent"],
                    target=self._target_vars(target, findings),
                    facts=self._facts(findings))
            except (PermissionError, KeyError, ValueError) as exc:
                logger.info("mech bridge: compile blocked for %s (%s): %s",
                            target, move["intent"], exc)
                blocked = {"target": target, "intent": move["intent"],
                           "state": "blocked", "reason": str(exc)}
                rounds.append(blocked)
                self._log.append(blocked)
                break

            # 3. Execute (synchronous — the bridge runs inside the
            #    campaign thread; budgets enforced by step max_wait).
            run_state = self.unit.run(plan)
            summary = run_state.summary()
            summary["intent"] = move["intent"]
            summary["round"] = round_no
            rounds.append(summary)
            self._log.append(summary)

            # 4. Feed findings back for the next round's graph query.
            findings.extend(run_state.findings)
            if summary["state"] != "done":
                break

        return rounds

    # ── target/fact shaping for resolvers ────────────────────────────

    @staticmethod
    def _target_vars(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Derive resolver target-vars from the campaign target + findings.

        Wireless findings carry bssid/essid directly; host targets map to
        host. Anything the graph knows about the target beats guessing.
        """
        vars: Dict[str, Any] = {"target": target, "host": target}
        for f in findings:
            detail = str(f.get("detail", ""))
            bssid = _extract_bssid(detail) or _extract_bssid(str(f.get("title", "")))
            if bssid:
                vars["bssid"] = bssid
            essid = _extract_essid(str(f.get("title", "")))
            if essid:
                vars["essid"] = essid
        return vars

    @staticmethod
    def _facts(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        facts: Dict[str, Any] = {}
        for f in findings:
            if f.get("detail"):
                facts[f["title"] if f.get("title") else f"finding{len(facts)}"] = \
                    f["detail"]
        return facts


_BSSID_RE = __import__("re").compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _extract_bssid(text: str) -> Optional[str]:
    m = _BSSID_RE.search(text or "")
    return m.group(1) if m else None


def _extract_essid(text: str) -> Optional[str]:
    # Cheap heuristic: 'ESSID <value>' markers from findings.
    m = __import__("re").search(r"ESSID[:\s]+([^\s,;]+)", text or "")
    return m.group(1) if m else None
