"""
RedTeam Harness — Auto Target Prioritizer (v5.2)
================================================

LLM-driven target ranking that runs BEFORE the multi-target scheduler
so high-value targets are processed first and most aggressively.

Flow:
  1. Recon provides per-target profiles (ports, services, versions,
     findings) — all attacker-controlled, so every field is run through
     sanitize_tool_output() before it ever reaches the LLM.
  2. A compact sanitized profile is built for each target.
  3. The local LLM ranks the targets by exploitability via a strict JSON
     schema (chat_structured / GBNF on llama-server).
  4. The rankings are validated against the known target set (unknown
     targets dropped, missing targets filled from the heuristic scorer),
     then mapped to an execution plan with per-target aggressiveness.
  5. If the LLM is unavailable, returns garbage, or violates the schema,
     the engine falls back to the heuristic `TargetPrioritizer` — a
     campaign never blocks on the LLM.

Aggressiveness (tier → retry multiplier):
    critical → 2.0x   high → 1.5x   medium → 1.0x
    low → 0.7x        info → 0.5x

The multiplier is applied to each workflow step's retry budget inside
the WorkflowStateMachine, so hot targets genuinely get more attempts —
not just a different queue order.
"""
import re
import json
import logging
from typing import Dict, List, Any, Optional

from core.injection_defense import sanitize_tool_output
from core.prioritizer import TargetPrioritizer

logger = logging.getLogger("redteam.auto_prioritizer")

# ── Tier → retry/aggression multiplier ──
AGGRESSIVENESS_BY_TIER = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.7,
    "info": 0.5,
}

VALID_TIERS = set(AGGRESSIVENESS_BY_TIER)

# ── LLM ranking schema (GBNF-enforced on llama-server) ──
RANKING_SCHEMA = {
    "type": "object",
    "properties": {
        "rankings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "score": {"type": "number"},
                    "tier": {"type": "string"},
                    "rationale": {"type": "string"},
                    "suggested_workflow": {"type": "string"},
                },
                "required": ["target", "score", "tier", "rationale"],
            }
        }
    },
    "required": ["rankings"],
}

MAX_PROFILE_CHARS = 4000
MAX_RANKING_SCORE = 100.0


class AutoTargetPrioritizer:
    """
    Ranks discovered targets by exploitability using the local LLM,
    producing a priority-ordered execution plan with per-target
    aggressiveness multipliers. Heuristic fallback is automatic.
    """

    def __init__(self, llm=None, config: Optional[Dict[str, Any]] = None,
                 heuristic: Optional[TargetPrioritizer] = None):
        self.llm = llm
        self.config = config or {}
        self.heuristic = heuristic or TargetPrioritizer()
        harness_cfg = self.config.get("harness", {})
        self.enabled = harness_cfg.get("prioritizer_llm_enabled", True)
        self.max_targets = int(harness_cfg.get("prioritizer_max_targets", 100))

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def prioritize(self, targets_data: List[Dict[str, Any]],
                   findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Rank targets by exploitability.

        targets_data: list of {target, ports: [{port, service, version, state}], ...}
        findings: optional list of {target, severity, title, ...} from recon.

        Returns a plan dict:
          ordered_targets: [{target, rank, score, tier, rationale,
                             suggested_workflow, aggressiveness}]
          used_llm: bool
          fallback_reason: str | None
          llm_rankings: raw parsed LLM output (for dashboard display)
        """
        targets_data = [t for t in (targets_data or []) if (t.get("target") or t.get("host"))]
        if not targets_data:
            return {"error": "No targets to prioritize"}

        # Normalize target keys
        for td in targets_data:
            td["target"] = td.get("target") or td.get("host")

        # Trim to configured cap (scheduler caps at 50 anyway)
        if len(targets_data) > self.max_targets:
            targets_data = targets_data[:self.max_targets]

        plan = {"used_llm": False, "fallback_reason": None,
                "llm_rankings": [], "ordered_targets": []}

        # ── Attempt LLM ranking (only if enabled + connected) ──
        llm_plan = None
        if self.enabled and self.llm is not None:
            try:
                if self.llm.is_connected():
                    llm_plan = self._llm_rank(targets_data, findings or [])
            except Exception as e:
                logger.warning(f"LLM prioritization failed ({e}) — heuristic fallback")
                plan["fallback_reason"] = f"llm_error: {e}"
        elif not self.enabled:
            plan["fallback_reason"] = "disabled_by_config"

        if llm_plan and llm_plan.get("rankings"):
            plan["used_llm"] = True
            plan["llm_rankings"] = llm_plan["rankings"]
            plan["ordered_targets"] = self._build_plan(llm_plan["rankings"],
                                                       targets_data,
                                                       findings or [])
            if not plan["ordered_targets"]:
                plan["used_llm"] = False
                plan["fallback_reason"] = "llm_rankings_invalid"
                plan["ordered_targets"] = self._heuristic_plan(targets_data)
        else:
            if not plan["fallback_reason"]:
                plan["fallback_reason"] = "llm_unavailable_or_empty"
            plan["ordered_targets"] = self._heuristic_plan(targets_data)

        return plan

    # ═══════════════════════════════════════════════════════════════
    # LLM ranking
    # ═══════════════════════════════════════════════════════════════

    def _build_profile(self, targets_data: List[Dict],
                       findings: List[Dict]) -> str:
        """Build a compact, sanitized per-target profile for the LLM.

        Every field that came from recon/tool output is attacker-
        controlled and passes through sanitize_tool_output() — a
        malicious service banner cannot plant prompt-injection payloads
        in the ranking prompt.
        """
        lines = []
        for i, td in enumerate(targets_data, 1):
            target = td["target"]
            ports = td.get("ports") or []
            port_strs = []
            for p in ports[:12]:
                svc = f"{p.get('service','')} {p.get('version','')}".strip()
                port_strs.append(
                    f"{p.get('port','?')}/{p.get('protocol','tcp')} "
                    f"{p.get('state','?')}"
                    + (f" {svc}" if svc else ""))
            target_findings = [f for f in findings
                               if f.get("target") == target]
            finding_strs = []
            for f in target_findings[:6]:
                finding_strs.append(
                    f"{f.get('severity','info')}: {f.get('title','')} "
                    f"({f.get('source_tool','')})")
            # Sanitize each attacker-controlled field
            safe_target = sanitize_tool_output(str(target), max_len=80)
            safe_ports = sanitize_tool_output("\n    ".join(port_strs),
                                              max_len=600)
            safe_findings = sanitize_tool_output("\n    ".join(finding_strs),
                                                 max_len=600)
            os_hint = sanitize_tool_output(str(td.get("os", "")), max_len=40)
            lines.append(
                f"[{i}] target={safe_target}\n"
                f"    os={os_hint or 'unknown'}\n"
                f"    open_ports:\n    {safe_ports or '  none'}\n"
                f"    findings:\n    {safe_findings or '  none'}")
        return "\n".join(lines)[:MAX_PROFILE_CHARS]

    def _build_prompt(self, profile: str) -> str:
        return (
            "You are an expert red-team target triager. Rank the following "
            "discovered targets by EXPLOITABILITY — how likely each is to be "
            "compromised given its exposed services, versions, and known "
            "findings. Consider: reachable high-risk services (SMB, RDP, SSH, "
            "web apps, databases), known vulnerable versions, exposure breadth, "
            "and existing findings. Score each target 0-100 (higher = more "
            "exploitable). Tier must be one of: critical, high, medium, low, "
            "info. Suggest the best workflow template name for each target if "
            "you can. Respond ONLY with JSON matching this schema:\n"
            '{"rankings": [{"target": "<exact target string>", '
            '"score": <0-100 number>, "tier": "<critical|high|medium|low|info>", '
            '"rationale": "<one sentence>", "suggested_workflow": "<name>"}]}\n\n'
            "Rank ALL targets — never omit one. Rank the most exploitable first.\n\n"
            "TARGETS:\n" + profile
        )

    def _llm_rank(self, targets_data: List[Dict],
                  findings: List[Dict]) -> Optional[Dict]:
        """Ask the LLM to rank targets; parse + validate the response."""
        profile = self._build_profile(targets_data, findings)
        prompt = self._build_prompt(profile)
        try:
            response = self.llm.chat_structured(
                [{"role": "user", "content": prompt}],
                RANKING_SCHEMA, max_tokens=2048, temperature=0.2)
        except Exception as e:
            logger.warning(f"LLM ranking request failed: {e}")
            return None

        data = self._parse_json(response)
        if not data or not isinstance(data.get("rankings"), list):
            logger.warning("LLM ranking response unparseable or missing 'rankings'")
            return None
        return {"rankings": data["rankings"]}

    def _parse_json(self, text: str) -> Optional[dict]:
        """Robust JSON extraction from LLM output (same pattern as orchestrator)."""
        if not text or text.startswith("[ERROR]"):
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return None

    # ═══════════════════════════════════════════════════════════════
    # Plan building
    # ═══════════════════════════════════════════════════════════════

    def _build_plan(self, raw_rankings: List[Dict],
                    targets_data: List[Dict],
                    findings: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
        """
        Validate LLM rankings against the known target set and map them
        to an execution plan.

        - Unknown targets in the LLM output are dropped.
        - Known targets the LLM omitted are appended, scored by the
          heuristic (they still run — never silently skipped).
        - Scores are clamped to 0-100; tiers validated; aggressiveness
          derived from tier.
        """
        findings = findings or []
        known = {td["target"] for td in targets_data}

        ordered = []
        seen = set()
        for r in raw_rankings:
            t = str(r.get("target", "")).strip()
            if not t or t not in known or t in seen:
                continue
            seen.add(t)
            tier = str(r.get("tier", "medium")).lower()
            if tier not in VALID_TIERS:
                tier = "medium"
            try:
                score = float(r.get("score", 0))
            except (TypeError, ValueError):
                score = 0.0
            score = max(0.0, min(MAX_RANKING_SCORE, score))
            rationale = sanitize_tool_output(str(r.get("rationale", "")),
                                             max_len=200)
            ordered.append({
                "target": t,
                "score": round(score, 1),
                "tier": tier,
                "rationale": rationale,
                "suggested_workflow": sanitize_tool_output(
                    str(r.get("suggested_workflow", "")), max_len=80),
                "aggressiveness": AGGRESSIVENESS_BY_TIER[tier],
            })

        # Fill known targets the LLM omitted (never drop a target).
        # Feed the real findings so filled targets rank on recon data,
        # not ports alone.
        omitted = [td for td in targets_data if td["target"] not in seen]
        if omitted:
            omitted_targets = {td["target"] for td in omitted}
            fill_findings = [f for f in findings
                             if f.get("target") in omitted_targets]
            heuristic_plan = self.heuristic.prioritize(omitted, fill_findings)
            for hp in heuristic_plan:
                # Heuristic tier labels include emoji ("🔴 Critical") —
                # _plain_tier matches on substring, so no stripping needed.
                tier = self._plain_tier(hp.get("tier", "medium"))
                ordered.append({
                    "target": hp["target"],
                    "score": float(hp.get("score", 0)),
                    "tier": tier,
                    "rationale": "Filled by heuristic scorer (LLM omitted)",
                    "suggested_workflow": hp.get("suggested_workflow", ""),
                    "aggressiveness": AGGRESSIVENESS_BY_TIER.get(tier, 1.0),
                })

        # Rank: LLM score desc (stable — keeps fill order for ties)
        ordered.sort(key=lambda x: x["score"], reverse=True)
        for rank, entry in enumerate(ordered, 1):
            entry["rank"] = rank
        return ordered

    def _heuristic_plan(self, targets_data: List[Dict]) -> List[Dict[str, Any]]:
        """Full heuristic fallback plan (no LLM involvement)."""
        plan = self.heuristic.prioritize(targets_data, [])
        out = []
        for rank, hp in enumerate(plan, 1):
            tier = self._plain_tier(hp.get("tier", "medium"))
            out.append({
                "target": hp["target"],
                "rank": rank,
                "score": float(hp.get("score", 0)),
                "tier": tier,
                "rationale": "Heuristic scoring (ports + exposure)",
                "suggested_workflow": hp.get("suggested_workflow", ""),
                "aggressiveness": AGGRESSIVENESS_BY_TIER.get(tier, 1.0),
            })
        return out

    @staticmethod
    def _plain_tier(label: str) -> str:
        """Map a (possibly emoji-prefixed) heuristic tier label to a plain
        tier key by substring match — "🔴 Critical" → "critical"; unknown
        labels fall through to "medium" (safe default)."""
        for k in VALID_TIERS:
            if k in label.lower():
                return k
        return "medium"

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        return {
            "llm_enabled": self.enabled,
            "max_targets": self.max_targets,
            "aggressiveness_map": AGGRESSIVENESS_BY_TIER,
        }
