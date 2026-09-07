"""
RedTeam Harness — Mech-Unit Optional LLM Advisor (v7.0 P5.1)

The ONLY place the LLM touches the Mech-Unit, and only as an advisor:

  1. suggest_param(param, context) — compile-time, called only when the
     deterministic resolvers came up empty.
  2. critique_plan(plan)          — preview-time; suggestions render as
     optional, operator-accepted diffs.

Contract (manifest §3.7):
  - Both calls are BOUNDED (max_tokens ≤ ADVISOR_MAX_TOKENS) and skippable.
  - Anything derived from tool output is sanitized through
    core.injection_defense.sanitize_for_llm before it reaches a prompt —
    tool output stays untrusted even in advisory mode.
  - No backend → both calls return None and the caller degrades gracefully
    (the compiler surfaces a highlighted blank; the preview renders without
    critique). The advisor is never on any execution path: manifests carry
    llm_required: false and the schema validator enforces it.
  - Feature-flagged off by default: enabled only when config
    mech.advisor.enabled is true AND the backend answers a status probe.
"""
import logging
from typing import Any, Dict, Optional

from core.injection_defense import sanitize_for_llm

logger = logging.getLogger("redteam.mech.advisors")

ADVISOR_MAX_TOKENS = 512          # hard bound on every advisory call
ADVISOR_TEMPERATURE = 0.2         # low-creativity; advisory values must be sane


class Advisor:
    """Bounded, optional LLM advisor for compile/preview-time help."""

    def __init__(self, llm_backend=None, enabled: bool = False):
        self.llm = llm_backend
        self.enabled = enabled
        self.calls_made = 0
        self.calls_skipped = 0

    # ── backend liveness ─────────────────────────────────────────────

    def _backend_available(self) -> bool:
        if not self.enabled or self.llm is None:
            return False
        try:
            status = self.llm.get_status() if hasattr(self.llm, "get_status") else {}
            return bool(status.get("connected", False))
        except Exception:
            return False

    def _chat(self, system: str, user: str) -> Optional[str]:
        """One bounded, sanitized LLM call. None on any failure."""
        if not self._backend_available():
            self.calls_skipped += 1
            return None
        try:
            response = self.llm.chat(
                [{"role": "system", "content": sanitize_for_llm(system)},
                 {"role": "user", "content": sanitize_for_llm(user)}],
                max_tokens=ADVISOR_MAX_TOKENS,
                temperature=ADVISOR_TEMPERATURE,
            )
        except Exception as exc:
            logger.warning("advisor chat failed: %s", exc)
            self.calls_skipped += 1
            return None
        if not response or response.startswith("[ERROR]"):
            self.calls_skipped += 1
            return None
        self.calls_made += 1
        return response.strip()

    # ── advisory call 1: parameter suggestion (compile-time) ─────────

    def suggest_param(self, param: str, context: Dict[str, Any]) -> Optional[str]:
        """Suggest a value for one unresolvable plan parameter.

        context may carry target/facts/artifacts data (all sanitized).
        Returns a plain-string suggestion or None (caller surfaces a blank).
        """
        user = (
            f"A deterministic attack-plan resolver could not fill the "
            f"parameter '{param}'. Suggest ONE concrete value for it.\n"
            f"Known context: {context}\n"
            f"Answer with the value only — no explanation, no code block."
        )
        suggestion = self._chat(
            "You are a parameter advisor for an offline attack-plan compiler. "
            "You suggest concrete, safe-to-attempt parameter values. "
            "Respond with the value only.",
            user)
        if suggestion is None:
            return None
        # One line, hard-capped — the preview treats it as untrusted text.
        return sanitize_for_llm(suggestion.splitlines()[0][:200])

    # ── advisory call 2: plan critique (preview-time) ────────────────

    def critique_plan(self, plan: Dict[str, Any]) -> Optional[str]:
        """Optional plan critique rendered as operator-optional diffs.

        plan is the CompiledPlan.to_dict() summary — step names, tools,
        gates. No stdout and no raw tool output ever enters this prompt.
        """
        steps = [
            {"step": s.get("step"), "tool": s.get("tool"),
             "gate": s.get("gate"), "when": s.get("when")}
            for s in plan.get("steps", [])
        ]
        user = (
            "Review this compiled attack plan for ordering mistakes, missing "
            "precondition steps, or risky gates. Reply with up to 3 short "
            "bullet suggestions. If the plan looks sound, reply exactly "
            "'PLAN OK'.\n"
            f"Steps: {steps}"
        )
        critique = self._chat(
            "You are a plan reviewer for an offline attack-plan compiler. "
            "Be terse and concrete.",
            user)
        if critique is None:
            return None
        return sanitize_for_llm(critique[:2000])


def build_advisor(config: Optional[dict], llm_backend=None) -> Advisor:
    """Feature-flagged factory: enabled only via mech.advisor.enabled."""
    mech_cfg = (config or {}).get("mech", {}) if isinstance(config, dict) else {}
    advisor_cfg = mech_cfg.get("advisor", {})
    enabled = bool(advisor_cfg.get("enabled", False))
    return Advisor(llm_backend=llm_backend, enabled=enabled)
