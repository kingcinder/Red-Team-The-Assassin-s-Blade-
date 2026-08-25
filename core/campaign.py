"""
RedTeam Harness — Campaign Manager (v4.0)
C2-style campaign tracking for concurrent multi-target runs.

Tracks per-target live status with progress, findings heatmap grid,
drift confidence gauges, and cumulative risk scoring across the
entire campaign lifecycle.

Each campaign is identified by a unique ID and stores:
  - Per-target status, progress, findings, drift metrics
  - Aggregate findings heatmap (tool × severity grid)
  - Cumulative risk score (weighted combination of vuln + drift + exposure)
  - Campaign-level timeline and status
"""
import os
import logging
import threading
import secrets
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger("redteam.campaign")

# ── Risk scoring weights ──
RISK_WEIGHTS = {
    "findings_severity": 0.40,
    "drift_penalty": 0.15,
    "coverage_bonus": 0.20,
    "criticality_bonus": 0.25,
}

SEVERITY_RISK = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
}


class CampaignManager:
    """
    Manages C2-style campaign tracking for the RedTeam Harness.
    
    A campaign groups multiple concurrent multi-target workflow runs
    under a single identifier with aggregated metrics.
    """

    def __init__(self, tasks_dir: str = "tasks"):
        self.tasks_dir = tasks_dir
        self._campaigns: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ═══════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════

    def create_campaign(self, name: str, targets: List[str],
                        workflow: str = "", description: str = "") -> Dict[str, Any]:
        """Create a new campaign and return its ID + initial state."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        hex_id = secrets.token_hex(3)
        campaign_id = f"campaign_{ts}_{hex_id}"

        with self._lock:
            campaign = {
                "id": campaign_id,
                "name": name,
                "description": description,
                "workflow": workflow,
                "targets": list(targets),
                "created": datetime.now().isoformat(),
                "status": "created",
                "per_target": {},
                "findings_heatmap": {},
                "findings_total": 0,
                "risk_score": 0.0,
                "drift_avg": 0.0,
                "drift_confidence": "N/A",
                "completed_targets": 0,
                "failed_targets": 0,
                "active_targets": 0,
            }
            for t in targets:
                campaign["per_target"][t] = {
                    "target": t,
                    "status": "pending",
                    "progress": 0,
                    "total_steps": 0,
                    "completed_steps": 0,
                    "findings_count": 0,
                    "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "drift_score": 0.0,
                    "drift_confidence": "N/A",
                    "started": None,
                    "finished": None,
                    "error": None,
                    "workflow": workflow,
                }
            self._campaigns[campaign_id] = campaign

        logger.info(f"Campaign created: {campaign_id} ({name}) — {len(targets)} targets")
        return campaign

    def update_target(self, campaign_id: str, target: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update per-target status from workflow/scheduler events."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            if target not in campaign["per_target"]:
                return {"error": f"Target not in campaign: {target}"}

            t = campaign["per_target"][target]

            # Update fields
            if "status" in data:
                t["status"] = data["status"]
            if "completed_steps" in data:
                t["completed_steps"] = data["completed_steps"]
            if "total_steps" in data:
                t["total_steps"] = data["total_steps"]
            if t["total_steps"] > 0:
                t["progress"] = round(t["completed_steps"] / t["total_steps"] * 100)
            if "findings" in data:
                for f in data["findings"]:
                    sev = f.get("severity", "info").lower()
                    t["findings_by_severity"][sev] = t["findings_by_severity"].get(sev, 0) + 1
                    t["findings_count"] += 1
                    campaign["findings_total"] += 1
                    # Update heatmap: tool × severity
                    tool = f.get("source_tool", "unknown")
                    key = f"{tool}:{sev}"
                    campaign["findings_heatmap"][key] = campaign["findings_heatmap"].get(key, 0) + 1
            if "drift_score" in data:
                t["drift_score"] = data["drift_score"]
                t["drift_confidence"] = self._confidence_tag(data["drift_score"])
            if "error" in data:
                t["error"] = data["error"]
            if data.get("status") == "running" and not t["started"]:
                t["started"] = datetime.now().isoformat()
            if data.get("status") in ("complete", "failed", "error", "partial"):
                t["finished"] = datetime.now().isoformat()

            # Recompute aggregate metrics
            self._recompute_aggregates(campaign)

            return campaign

    def get_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Get full campaign state."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            return dict(campaign)

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns with summary info."""
        with self._lock:
            summaries = []
            for cid, c in self._campaigns.items():
                summaries.append({
                    "id": cid,
                    "name": c["name"],
                    "workflow": c["workflow"],
                    "status": c["status"],
                    "target_count": len(c["targets"]),
                    "completed_targets": c["completed_targets"],
                    "findings_total": c["findings_total"],
                    "risk_score": c["risk_score"],
                    "created": c["created"],
                })
            return sorted(summaries, key=lambda x: x["created"], reverse=True)

    def get_target_heatmap(self, campaign_id: str) -> Dict[str, Any]:
        """Get the findings heatmap grid for a campaign."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}

            # Build tool × severity grid
            tools = set()
            severities = ["critical", "high", "medium", "low", "info"]
            grid = {}
            for key, count in campaign["findings_heatmap"].items():
                parts = key.split(":")
                if len(parts) == 2:
                    tool, sev = parts
                    tools.add(tool)
                    if tool not in grid:
                        grid[tool] = {s: 0 for s in severities}
                    grid[tool][sev] = count

            return {
                "campaign_id": campaign_id,
                "tools": sorted(tools),
                "severities": severities,
                "grid": grid,
                "total": campaign["findings_total"],
            }

    def get_risk_summary(self, campaign_id: str) -> Dict[str, Any]:
        """Get cumulative risk scoring breakdown for a campaign."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}

            risk = self._compute_risk_score(campaign)
            return {
                "campaign_id": campaign_id,
                "total_risk": risk["total"],
                "breakdown": risk["breakdown"],
                "rating": risk["rating"],
                "drift_avg": campaign["drift_avg"],
                "drift_confidence": campaign["drift_confidence"],
                "coverage_pct": risk["coverage_pct"],
                "findings_total": campaign["findings_total"],
                "targets_total": len(campaign["targets"]),
                "targets_completed": campaign["completed_targets"],
            }

    def mark_target_started(self, campaign_id: str, target: str) -> Dict[str, Any]:
        """Mark a target as actively running."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign or target not in campaign["per_target"]:
                return {"error": "Campaign or target not found"}
            t = campaign["per_target"][target]
            t["status"] = "running"
            t["started"] = t["started"] or datetime.now().isoformat()
            campaign["status"] = "running"
            self._recompute_aggregates(campaign)
            return campaign

    def mark_campaign_complete(self, campaign_id: str) -> Dict[str, Any]:
        """Mark the entire campaign as complete."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": "Campaign not found"}
            campaign["status"] = "complete"
            self._recompute_aggregates(campaign)
            return campaign

    def delete_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Remove a campaign from memory."""
        with self._lock:
            if campaign_id in self._campaigns:
                del self._campaigns[campaign_id]
                return {"deleted": True}
            return {"error": "Campaign not found"}

    # ═══════════════════════════════════════════════════════════════
    # INTERNALS
    # ═══════════════════════════════════════════════════════════════

    def _recompute_aggregates(self, campaign: Dict):
        """Recompute campaign-level aggregates from per-target data."""
        completed = 0
        failed = 0
        active = 0
        drift_scores = []

        for t in campaign["per_target"].values():
            if t["status"] in ("complete", "partial"):
                completed += 1
            elif t["status"] in ("failed", "error"):
                failed += 1
            elif t["status"] == "running":
                active += 1
            if t["drift_score"] > 0:
                drift_scores.append(t["drift_score"])

        campaign["completed_targets"] = completed
        campaign["failed_targets"] = failed
        campaign["active_targets"] = active

        # Average drift
        if drift_scores:
            campaign["drift_avg"] = round(sum(drift_scores) / len(drift_scores), 3)
            campaign["drift_confidence"] = self._confidence_tag(campaign["drift_avg"])
        else:
            campaign["drift_avg"] = 0.0
            campaign["drift_confidence"] = "N/A"

        # Update campaign status
        total = len(campaign["per_target"])
        if completed == total:
            campaign["status"] = "complete"
        elif failed > 0 and completed + failed == total:
            campaign["status"] = "failed"
        elif active > 0:
            campaign["status"] = "running"

        # Risk score
        risk = self._compute_risk_score(campaign)
        campaign["risk_score"] = risk["total"]

    def _compute_risk_score(self, campaign: Dict) -> Dict[str, Any]:
        """
        Compute cumulative risk score across the campaign.
        
        Components:
        1. Findings severity risk (weighted sum of all findings by severity)
        2. Drift penalty (higher drift = less reliable results)
        3. Coverage bonus (more targets scanned = better coverage)
        4. Criticality bonus (critical findings increase risk significantly)
        """
        total_targets = len(campaign["targets"]) or 1
        completed = campaign["completed_targets"]
        total_findings = campaign["findings_total"]

        # 1. Findings severity risk (0–100)
        severity_risk = 0.0
        for t in campaign["per_target"].values():
            for sev, count in t["findings_by_severity"].items():
                severity_risk += SEVERITY_RISK.get(sev, 1.0) * count
        severity_risk = min(100.0, severity_risk)

        # 2. Drift penalty (0–30, higher = worse)
        drift_penalty = campaign["drift_avg"] * 30.0

        # 3. Coverage bonus (0–40)
        coverage_pct = (completed / total_targets) * 100 if total_targets > 0 else 0
        coverage_bonus = (completed / total_targets) * 40.0

        # 4. Criticality bonus (0–30)
        crit_count = 0
        high_count = 0
        for t in campaign["per_target"].values():
            crit_count += t["findings_by_severity"].get("critical", 0)
            high_count += t["findings_by_severity"].get("high", 0)
        criticality = min(30.0, (crit_count * 10.0) + (high_count * 4.0))

        total = round(severity_risk * RISK_WEIGHTS["findings_severity"] +
                      drift_penalty * RISK_WEIGHTS["drift_penalty"] +
                      coverage_bonus * RISK_WEIGHTS["coverage_bonus"] +
                      criticality * RISK_WEIGHTS["criticality_bonus"], 1)

        total = min(100.0, max(0.0, total))

        # Rating
        if total >= 75:
            rating = "🔴 Critical"
        elif total >= 50:
            rating = "🟠 High"
        elif total >= 25:
            rating = "🟡 Medium"
        elif total > 5:
            rating = "🟢 Low"
        else:
            rating = "⚪ Minimal"

        return {
            "total": total,
            "rating": rating,
            "coverage_pct": round(coverage_pct),
            "breakdown": {
                "findings_severity_risk": round(severity_risk * RISK_WEIGHTS["findings_severity"], 1),
                "drift_penalty": round(drift_penalty * RISK_WEIGHTS["drift_penalty"], 1),
                "coverage_bonus": round(coverage_bonus * RISK_WEIGHTS["coverage_bonus"], 1),
                "criticality_bonus": round(criticality * RISK_WEIGHTS["criticality_bonus"], 1),
            },
        }

    def _confidence_tag(self, drift_score: float) -> str:
        """Tag drift score with a confidence level."""
        if drift_score <= 0.15:
            return "high"
        elif drift_score <= 0.40:
            return "medium"
        elif drift_score <= 0.70:
            return "low"
        return "uncertain"
