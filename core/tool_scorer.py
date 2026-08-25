"""
RedTeam Harness — Tool Scorer (v4.1)
Tracks success/failure/timeout/blocked per tool across engagements.

Persists scores to disk so the LLM learns over time which tools work on
this host and avoids calling missing or broken ones.

Scoring model:
  - Each tool invocation is recorded as success / error / timeout / blocked
  - Reliability = weighted combination of recent success rate + trend
  - "Toxic" tools (consistently failing) are flagged with suggested alternatives
  - Scores are injected into the LLM system prompt as "Tool Reliability" hints
"""
import json
import os
import logging
import threading
import contextlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("redteam.scorer")

# ── Scoring constants ──
SUCCESS_WEIGHT = 1.0
ERROR_WEIGHT = -0.7           # harsh — a tool that always errors is useless
TIMEOUT_WEIGHT = -0.5
BLOCKED_WEIGHT = 0.0        # blocked by safety — not the tool's fault
NOT_INSTALLED_WEIGHT = -0.8  # tool binary missing

# Exponential decay: recent runs matter more
RECENT_WINDOW = 50           # last N invocations to consider
DECAY_HALF_LIFE = 20         # older runs get halved every N invocations

# Toxicity threshold: if reliability drops below this, flag the tool
TOXICITY_THRESHOLD = 0.25

# Suggest alternatives after N consecutive failures
CONSECUTIVE_FAILURE_THRESHOLD = 3

# Known alternative mappings (tool_name → list of fallback tools)
ALTERNATIVES = {
    "nikto_scan": ["nuclei_scan", "whatweb_scan", "waf_detect"],
    "gobuster_dir": ["feroxbuster_scan", "ffuf_fuzz", "dirb_scan", "wfuzz_fuzz"],
    "dirb_scan": ["gobuster_dir", "feroxbuster_scan", "ffuf_fuzz"],
    "wfuzz_fuzz": ["ffuf_fuzz", "gobuster_dir"],
    "feroxbuster_scan": ["gobuster_dir", "ffuf_fuzz"],
    "ffuf_fuzz": ["gobuster_dir", "feroxbuster_scan"],
    "nmap_scan": ["masscan_scan", "naabu_scan"],
    "masscan_scan": ["nmap_scan", "zmap_scan"],
    "sqlmap_scan": ["nikto_scan"],
    "hydra_brute": ["medusa"],
    "john_crack": ["hashcat_crack"],
    "hashcat_crack": ["john_crack"],
    "subfinder_enum": ["amass_enum", "dnsx_probe"],
    "amass_enum": ["subfinder_enum"],
    "whatweb_scan": ["waf_detect", "nikto_scan"],
    "httpx_probe": ["curl_request"],
    "nuclei_scan": ["nikto_scan"],
    "enum4linux_enum": ["smbmap_enum", "nbtscan_scan"],
    "snmpwalk_enum": ["onesixtyone_scan"],
    "wpscan_enum": ["nuclei_scan", "nikto_scan"],
    "sherlock_search": ["holehe_check"],
    "binwalk_analyze": ["strings_extract"],
}


class ToolScorer:
    """
    Tracks per-tool execution outcomes and computes reliability scores.

    Usage:
        scorer = ToolScorer("./sessions")
        scorer.record("nmap_scan", success=True, duration=12.3)
        scorer.record("nikto_scan", success=False, error="not installed")

        # Get LLM-facing summary
        hint = scorer.get_reliability_hint()  # injected into system prompt
        report = scorer.get_report()          # full stats for dashboard
    """

    def __init__(self, data_dir: str = "./sessions"):
        self._data_dir = data_dir
        self._score_file = os.path.join(data_dir, "tool_scores.json")
        self._lock = threading.Lock()
        self._scores: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ═══════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════

    def record(self, tool_name: str, success: bool,
               duration: float = 0.0, error: str = "",
               blocked: bool = False, timed_out: bool = False,
               not_installed: bool = False) -> None:
        """Record a single tool invocation outcome."""
        with self._lock:
            if tool_name not in self._scores:
                self._scores[tool_name] = {
                    "invocations": [],
                    "total_success": 0,
                    "total_error": 0,
                    "total_timeout": 0,
                    "total_blocked": 0,
                    "total_not_installed": 0,
                    "total_runs": 0,
                }

            entry = self._scores[tool_name]

            # Determine outcome
            if not_installed:
                outcome = "not_installed"
                weight = NOT_INSTALLED_WEIGHT
            elif blocked:
                outcome = "blocked"
                weight = BLOCKED_WEIGHT
            elif timed_out:
                outcome = "timeout"
                weight = TIMEOUT_WEIGHT
            elif success:
                outcome = "success"
                weight = SUCCESS_WEIGHT
            else:
                outcome = "error"
                weight = ERROR_WEIGHT

            # Record invocation
            inv = {
                "outcome": outcome,
                "weight": weight,
                "duration": round(duration, 2),
                "error": error[:200] if error else "",
                "timestamp": datetime.now().isoformat(),
            }
            entry["invocations"].append(inv)

            # Keep only recent window
            if len(entry["invocations"]) > RECENT_WINDOW * 2:
                entry["invocations"] = entry["invocations"][-RECENT_WINDOW:]

            # Update counters
            entry["total_runs"] += 1
            if outcome == "success":
                entry["total_success"] += 1
            elif outcome == "error":
                entry["total_error"] += 1
            elif outcome == "timeout":
                entry["total_timeout"] += 1
            elif outcome == "blocked":
                entry["total_blocked"] += 1
            elif outcome == "not_installed":
                entry["total_not_installed"] += 1

            # Track consecutive failures
            self._update_consecutive_failures(tool_name)

            # Persist periodically (every 10 writes)
            if entry["total_runs"] % 10 == 0:
                self._save()

    def get_reliability(self, tool_name: str) -> float:
        """
        Get reliability score for a tool (0.0 to 1.0).
        Uses exponential decay — recent runs matter more.
        """
        with self._lock:
            return self._compute_reliability_unlocked(tool_name)

    def get_reliability_hint(self, max_tools: int = 20, min_runs: int = 3) -> str:
        """
        Build a concise string for injection into the LLM system prompt.
        Shows tool reliability tiers: reliable, unreliable, toxic, not_installed.
        Capped to max_tools to avoid bloating the system prompt.
        """
        with self._lock:
            if not self._scores:
                return ""

            reliable = []
            unreliable = []
            toxic = []
            not_installed = []

            for tool_name in sorted(self._scores.keys()):
                entry = self._scores[tool_name]
                reliability = self._compute_reliability_unlocked(tool_name)
                total = entry["total_runs"]
                if total < min_runs:
                    continue  # not enough data

                cons_fail = entry.get("consecutive_failures", 0)
                last_error = ""
                for inv in reversed(entry["invocations"]):
                    if inv.get("error"):
                        last_error = inv["error"][:60]
                        break

                line = f"  {tool_name}: {reliability:.0%} ({total} runs)"
                if last_error:
                    line += f" [last error: {last_error}]"

                if entry["total_not_installed"] > 0 and entry["total_success"] == 0:
                    not_installed.append(line)
                elif reliability < TOXICITY_THRESHOLD:
                    alternatives = ALTERNATIVES.get(tool_name, [])
                    alt_str = ", ".join(alternatives[:3]) if alternatives else "none known"
                    line += f" \u2192 try: {alt_str}"
                    toxic.append(line)
                elif reliability < 0.6 or cons_fail >= CONSECUTIVE_FAILURE_THRESHOLD:
                    unreliable.append(line)
                elif reliability >= 0.8:
                    reliable.append(line)

            if not reliable and not unreliable and not toxic and not not_installed:
                return ""

            # Priority order: toxic > unreliable > not_installed > reliable
            # Cap total lines to max_tools to avoid prompt bloat
            ordered_sections = []
            if toxic:
                ordered_sections.append(("### Toxic tools (consistently fail \u2014 use alternatives)", toxic))
            if unreliable:
                ordered_sections.append(("### Unreliable tools (use with caution)", unreliable))
            if not_installed:
                ordered_sections.append(("### Not installed (install first or use alternatives)", not_installed))
            if reliable:
                ordered_sections.append(("### Reliable tools (prefer these)", reliable))

            parts = ["\n## Tool Reliability (learned from previous runs)"]
            remaining = max_tools
            for header, items in ordered_sections:
                if remaining <= 0:
                    break
                show = items[:remaining]
                remaining -= len(show)
                parts.append(header)
                parts.extend(show)

            if remaining <= 0 and sum(len(items) for _, items in ordered_sections) > max_tools:
                parts.append(f"  ... {sum(len(items) for _, items in ordered_sections) - max_tools} more tools tracked")

            return "\n".join(parts)

    def get_report(self) -> Dict[str, Any]:
        """Get full scoring report for the dashboard."""
        with self._lock:
            tools = []
            for name, entry in sorted(self._scores.items()):
                reliability = self._compute_reliability_unlocked(name)
                tools.append({
                    "tool": name,
                    "reliability": round(reliability, 3),
                    "total_runs": entry["total_runs"],
                    "success": entry["total_success"],
                    "errors": entry["total_error"],
                    "timeouts": entry["total_timeout"],
                    "blocked": entry["total_blocked"],
                    "not_installed": entry["total_not_installed"],
                    "consecutive_failures": entry.get("consecutive_failures", 0),
                    "toxic": reliability < TOXICITY_THRESHOLD and entry["total_runs"] >= 3,
                    "alternatives": ALTERNATIVES.get(name, []),
                })

            return {
                "total_tools_tracked": len(tools),
                "reliable": sum(1 for t in tools if t["reliability"] >= 0.8),
                "unreliable": sum(1 for t in tools if 0.25 <= t["reliability"] < 0.8),
                "toxic": sum(1 for t in tools if t["toxic"]),
                "tools": tools,
            }

    def get_alternatives(self, tool_name: str) -> List[str]:
        """Get suggested alternatives for a failing tool."""
        return ALTERNATIVES.get(tool_name, [])

    def reset_tool(self, tool_name: str) -> None:
        """Reset scores for a specific tool (e.g. after reinstalling)."""
        with self._lock:
            self._scores.pop(tool_name, None)
            self._save()

    def reset_all(self) -> None:
        """Reset all scores."""
        with self._lock:
            self._scores.clear()
            self._save()

    def get_stats(self) -> Dict[str, Any]:
        """Quick stats for the status endpoint."""
        with self._lock:
            return {
                "tools_tracked": len(self._scores),
                "total_invocations": sum(e["total_runs"] for e in self._scores.values()),
                "reliability_hint_length": len(self.get_reliability_hint()),
            }

    def save(self) -> None:
        """Public save — call on shutdown to avoid losing unsaved writes."""
        with self._lock:
            self._save()

    # ═══════════════════════════════════════════════════════════════
    # INTERNALS
    # ═══════════════════════════════════════════════════════════════

    def _compute_reliability_unlocked(self, tool_name: str) -> float:
        """Internal — caller must hold self._lock."""
        entry = self._scores.get(tool_name)
        if not entry or not entry["invocations"]:
            return 0.5

        invocations = entry["invocations"]
        total_weight = 0.0
        weighted_sum = 0.0
        for i, inv in enumerate(reversed(invocations)):
            decay = 0.5 ** (i / DECAY_HALF_LIFE)
            weighted_sum += inv["weight"] * decay
            total_weight += decay

        if total_weight == 0:
            return 0.5

        raw = weighted_sum / total_weight
        normalized = (raw - (-NOT_INSTALLED_WEIGHT)) / (SUCCESS_WEIGHT - NOT_INSTALLED_WEIGHT)
        return max(0.0, min(1.0, normalized))

    def _update_consecutive_failures(self, tool_name: str) -> None:
        """Count consecutive failures at the end of the invocation list."""
        entry = self._scores[tool_name]
        count = 0
        for inv in reversed(entry["invocations"]):
            if inv["outcome"] in ("error", "timeout", "not_installed"):
                count += 1
            else:
                break
        entry["consecutive_failures"] = count

    def __del__(self):
        """Safety net — persist scores if process exits unexpectedly."""
        try:
            self._save(use_lock=False)
        except Exception:
            pass

    def _load(self) -> None:
        """Load scores from disk."""
        if not os.path.exists(self._score_file):
            return
        try:
            with open(self._score_file) as f:
                data = json.load(f)
            if data.get("version") != "4.1":
                logger.warning(f"Score file version mismatch ({data.get('version')}), resetting")
                self._scores = {}
                return
            self._scores = data.get("scores", {})
            logger.info(f"Loaded tool scores: {len(self._scores)} tools from {self._score_file}")
        except Exception as e:
            logger.warning(f"Failed to load tool scores: {e}")

    def _save(self, use_lock: bool = True) -> None:
        """Persist scores to disk. Pass use_lock=False for __del__ safety."""
        try:
            os.makedirs(os.path.dirname(self._score_file), exist_ok=True)
            ctx = self._lock if use_lock else contextlib.nullcontext()
            with ctx:
                with open(self._score_file, "w") as f:
                    json.dump({
                        "scores": self._scores,
                        "saved_at": datetime.now().isoformat(),
                        "version": "4.1",
                    }, f, indent=2)
            logger.debug(f"Saved tool scores: {len(self._scores)} tools")
        except Exception as e:
            logger.error(f"Failed to save tool scores: {e}")
