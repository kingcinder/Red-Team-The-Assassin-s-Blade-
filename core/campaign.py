"""
RedTeam Harness — Campaign Manager (v4.0 / v5.5)
C2-style campaign tracking for concurrent multi-target runs.

Tracks per-target live status with progress, findings heatmap grid,
drift confidence gauges, and cumulative risk scoring across the
entire campaign lifecycle.

v5.5 additions:
  - Campaign persistence: save/load campaigns to disk (state.json + report)
    so the dashboard can list history, reload finished campaigns for
    post-engagement review, and compare risk scores across past runs.
  - Mid-run snapshots: capture a campaign's state at any point and diff it
    against the final state to see exactly which findings appeared after a
    specific workflow step.
  - Cross-campaign trends: rank which vulnerabilities recur most often
    across all engagements (leaderboard of persistent exposures with
    severity heat per engagement and trend arrows).

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
import copy
from datetime import datetime
from typing import Dict, List, Any

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

# ── Retained raw findings per target (for the comparison view) ──
MAX_RETAINED_FINDINGS_PER_TARGET = 200


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
                    "findings": [],          # raw retained findings (comparison view)
                    "_finding_keys": set(),  # dedupe keys already retained
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
                    # Retain raw finding (deduped) for the side-by-side
                    # comparison view — identifies overlapping vulnerabilities
                    # by target across campaigns.
                    fkey = f.get("dedupe_key") or f.get("title")
                    if fkey:
                        t.setdefault("_finding_keys", set())
                        if fkey not in t["_finding_keys"]:
                            t["_finding_keys"].add(fkey)
                            if len(t.setdefault("findings", [])) < MAX_RETAINED_FINDINGS_PER_TARGET:
                                t["findings"].append({
                                    "title": f.get("title", ""),
                                    "severity": sev,
                                    "dedupe_key": fkey,
                                    "source_tool": f.get("source_tool", ""),
                                    "evidence": str(f.get("evidence", ""))[:200],
                                })
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
        """Get full campaign state.

        Returns a JSON-serializable copy: per-target internals like the
        ``_finding_keys`` dedupe set are stripped (a ``set`` would break
        ``jsonify`` on the dashboard detail API).
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            result = dict(campaign)
            result["per_target"] = {
                t: {k: v for k, v in pt.items() if k != "_finding_keys"}
                for t, pt in campaign["per_target"].items()
            }
            return result

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
    # CAMPAIGN COMPARISON (side-by-side view)
    # ═══════════════════════════════════════════════════════════════

    def compare_campaigns(self, campaign_id_a: str,
                          campaign_id_b: str) -> Dict[str, Any]:
        """
        Compare two campaigns side-by-side.

        Returns overlapping vulnerabilities (found in both), findings unique
        to each side, per-target overlap (targets present in BOTH campaigns
        with the same vuln → persistent exposure across engagements),
        a risk-score side-by-side, and attack-path segments derived from
        the severity-ordered findings of each campaign.
        """
        with self._lock:
            ca = self._campaigns.get(campaign_id_a)
            cb = self._campaigns.get(campaign_id_b)
            if not ca or not cb:
                missing = campaign_id_a if not ca else campaign_id_b
                return {"error": f"Campaign not found: {missing}"}

            def _index(campaign):
                """Map dedupe_key → list of {target, severity, source_tool}."""
                idx: Dict[str, List[Dict[str, Any]]] = {}
                for target, t in campaign["per_target"].items():
                    for f in t.get("findings", []):
                        key = f.get("dedupe_key") or f.get("title")
                        if not key:
                            continue
                        idx.setdefault(key, []).append({
                            "target": target,
                            "severity": (f.get("severity") or "info").lower(),
                            "source_tool": f.get("source_tool", ""),
                            "evidence": f.get("evidence", ""),
                        })
                return idx

            idx_a, idx_b = _index(ca), _index(cb)
            keys_a, keys_b = set(idx_a), set(idx_b)
            overlap_keys = keys_a & keys_b
            only_a_keys = keys_a - keys_b
            only_b_keys = keys_b - keys_a

            SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

            def _max_sev(instances):
                return min((i["severity"] for i in instances),
                           key=lambda s: SEV_ORDER.get(s, 9))

            # ── Overlapping vulnerabilities (found in both campaigns) ──
            overlap = []
            for key in overlap_keys:
                a_inst, b_inst = idx_a[key], idx_b[key]
                targets_a = sorted({i["target"] for i in a_inst})
                targets_b = sorted({i["target"] for i in b_inst})
                shared_targets = sorted(set(targets_a) & set(targets_b))
                overlap.append({
                    "dedupe_key": key,
                    "severity_a": _max_sev(a_inst),
                    "severity_b": _max_sev(b_inst),
                    "source_tool": a_inst[0]["source_tool"],
                    "count_a": len(a_inst),
                    "count_b": len(b_inst),
                    "targets_a": targets_a,
                    "targets_b": targets_b,
                    "shared_targets": shared_targets,
                    # Persistent: same host hit in both engagements
                    "persistent": len(shared_targets) > 0,
                })
            overlap.sort(key=lambda o: SEV_ORDER.get(o["severity_a"], 9))

            # ── Findings unique to each side ──
            def _unique(keys, idx):
                out = []
                for key in keys:
                    inst = idx[key]
                    out.append({
                        "dedupe_key": key,
                        "severity": _max_sev(inst),
                        "source_tool": inst[0]["source_tool"],
                        "count": len(inst),
                        "targets": sorted({i["target"] for i in inst}),
                    })
                out.sort(key=lambda o: SEV_ORDER.get(o["severity"], 9))
                return out

            unique_a = _unique(only_a_keys, idx_a)
            unique_b = _unique(only_b_keys, idx_b)

            # ── Per-target overlap (same host present in both campaigns) ──
            targets_a_set = set(ca["per_target"])
            targets_b_set = set(cb["per_target"])
            common_targets = sorted(targets_a_set & targets_b_set)
            shared_vuln_keys = set(idx_a) & set(idx_b)
            per_target_overlap = []
            for target in common_targets:
                vulns = []
                for key in shared_vuln_keys:
                    a_targets = {i["target"] for i in idx_a[key]}
                    b_targets = {i["target"] for i in idx_b[key]}
                    if target in a_targets and target in b_targets:
                        vulns.append({
                            "dedupe_key": key,
                            "severity": _max_sev(idx_a[key]),
                            "source_tool": idx_a[key][0]["source_tool"],
                        })
                if vulns:
                    vulns.sort(key=lambda v: SEV_ORDER.get(v["severity"], 9))
                    per_target_overlap.append({"target": target, "vulns": vulns})

            # ── Attack-path segments (severity-ordered finding chains) ──
            def _attack_path(campaign, idx):
                segs = []
                for key, inst in idx.items():
                    segs.append({
                        "dedupe_key": key,
                        "severity": _max_sev(inst),
                        "source_tool": inst[0]["source_tool"],
                        "targets": sorted({i["target"] for i in inst}),
                    })
                segs.sort(key=lambda s: (SEV_ORDER.get(s["severity"], 9), s["dedupe_key"]))
                return segs

            shared_path = sorted(
                (_attack_path(ca, idx_a)),
                key=lambda s: (SEV_ORDER.get(s["severity"], 9), s["dedupe_key"]))
            shared_path = [s for s in shared_path if s["dedupe_key"] in overlap_keys]
            path_a = [s for s in _attack_path(ca, idx_a) if s["dedupe_key"] not in overlap_keys]
            path_b = [s for s in _attack_path(cb, idx_b) if s["dedupe_key"] not in overlap_keys]

            # ── Risk side-by-side ──
            risk_a = self._compute_risk_score(ca)
            risk_b = self._compute_risk_score(cb)

            def _severity_counts(campaign):
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for t in campaign["per_target"].values():
                    for sev, n in t["findings_by_severity"].items():
                        counts[sev] = counts.get(sev, 0) + n
                return counts

            return {
                "campaign_a": {
                    "id": campaign_id_a,
                    "name": ca["name"],
                    "workflow": ca["workflow"],
                    "status": ca["status"],
                    "findings_total": ca["findings_total"],
                    "targets": list(ca["targets"]),
                    "severity_counts": _severity_counts(ca),
                    "risk": {"score": risk_a["total"], "rating": risk_a["rating"],
                              "coverage_pct": risk_a["coverage_pct"]},
                    "drift_avg": ca["drift_avg"],
                },
                "campaign_b": {
                    "id": campaign_id_b,
                    "name": cb["name"],
                    "workflow": cb["workflow"],
                    "status": cb["status"],
                    "findings_total": cb["findings_total"],
                    "targets": list(cb["targets"]),
                    "severity_counts": _severity_counts(cb),
                    "risk": {"score": risk_b["total"], "rating": risk_b["rating"],
                              "coverage_pct": risk_b["coverage_pct"]},
                    "drift_avg": cb["drift_avg"],
                },
                "overlap": overlap,
                "overlap_count": len(overlap),
                "unique_a": unique_a,
                "unique_a_count": len(unique_a),
                "unique_b": unique_b,
                "unique_b_count": len(unique_b),
                "per_target_overlap": per_target_overlap,
                "common_targets": common_targets,
                "attack_paths": {
                    "shared": shared_path,
                    "a_only": path_a,
                    "b_only": path_b,
                },
            }

    # ═══════════════════════════════════════════════════════════════
    # CAMPAIGN PERSISTENCE (v5.5) — save/load/list to disk
    # ═══════════════════════════════════════════════════════════════

    def save_campaign(self, campaign_id: str,
                      campaigns_dir: str = "campaigns") -> Dict[str, Any]:
        """
        Persist a campaign to disk as state.json + a markdown report so the
        dashboard can list history, reload a finished campaign for
        post-engagement review, and compare risk scores across past runs.

        Returns {saved, path, report_path} or {error}.
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            os.makedirs(campaigns_dir, exist_ok=True)
            data = self._serializable(campaign)
            data["saved_at"] = datetime.now().isoformat()
            state_path = os.path.join(campaigns_dir, f"{campaign_id}.json")
            try:
                from core.state_store import atomic_write_json
                atomic_write_json(state_path, data)
            except Exception as e:
                return {"error": f"Failed to save campaign: {e}"}
            report_path = self._write_campaign_report(data, campaigns_dir)
            logger.info(f"Campaign {campaign_id} persisted to {state_path}")
            return {"saved": True, "path": state_path,
                    "report_path": report_path}

    def load_campaign(self, campaign_id: str,
                      campaigns_dir: str = "campaigns") -> Dict[str, Any]:
        """Load a persisted campaign back into memory (for reload + compare)."""
        state_path = os.path.join(campaigns_dir, f"{campaign_id}.json")
        if not os.path.exists(state_path):
            return {"error": f"Campaign not found on disk: {campaign_id}"}
        from core.state_store import read_json
        data = read_json(state_path)
        if data is None:
            return {"error": f"Failed to load campaign: {campaign_id} (missing or corrupt)"}
        with self._lock:
            self._campaigns[campaign_id] = data
        logger.info(f"Campaign {campaign_id} loaded from disk")
        return self.get_campaign(campaign_id)

    def list_history(self, campaigns_dir: str = "campaigns") -> List[Dict[str, Any]]:
        """List ALL campaigns — in-memory plus persisted history on disk.

        In-memory campaigns are always authoritative (live data); persisted
        campaigns that aren't loaded are listed from their state files.
        """
        summaries = self.list_campaigns()
        in_mem = {s["id"] for s in summaries}
        if os.path.isdir(campaigns_dir):
            for fn in sorted(os.listdir(campaigns_dir), reverse=True):
                if not fn.endswith(".json"):
                    continue
                cid = fn[:-5]
                if cid in in_mem:
                    continue
                try:
                    from core.state_store import read_json
                    data = read_json(os.path.join(campaigns_dir, fn))
                    if data is None:
                        continue
                    summaries.append({
                        "id": cid,
                        "name": data.get("name", cid),
                        "workflow": data.get("workflow", ""),
                        "status": data.get("status", "unknown"),
                        "target_count": len(data.get("targets", []) or []),
                        "completed_targets": data.get("completed_targets", 0),
                        "findings_total": data.get("findings_total", 0),
                        "risk_score": data.get("risk_score", 0),
                        "created": data.get("created", ""),
                        "archived": True,
                    })
                except Exception:
                    continue
        return sorted(summaries, key=lambda x: x.get("created", ""),
                      reverse=True)

    def _write_campaign_report(self, data: Dict, campaigns_dir: str) -> str:
        """Write a markdown post-engagement report for a persisted campaign.
        Formatting delegated to core.report (single report writer)."""
        from core.report import campaign_report

        report = campaign_report(data, self._risk_rating)
        path = os.path.join(campaigns_dir, f"{data.get('id', 'campaign')}_report.md")
        try:
            with open(path, "w") as f:
                f.write(report)
        except Exception:
            return ""
        return path

    # ═══════════════════════════════════════════════════════════════
    # MID-RUN SNAPSHOTS + DIFF (v5.5)
    # ═══════════════════════════════════════════════════════════════

    def snapshot_campaign(self, campaign_id: str,
                          label: str = "") -> Dict[str, Any]:
        """Capture a snapshot of the campaign's current state (findings per
        target, severity counts, risk) so it can be diffed against the final
        state to see exactly what changed after a specific workflow step.
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            snapshot = {
                "snapshot_id": f"snap_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
                "label": label or "mid-run",
                "captured": datetime.now().isoformat(),
                "status": campaign["status"],
                "risk_score": campaign["risk_score"],
                "findings_total": campaign["findings_total"],
                "completed_targets": campaign["completed_targets"],
                "per_target": {},
            }
            for t, pt in campaign["per_target"].items():
                snapshot["per_target"][t] = {
                    "status": pt["status"],
                    "progress": pt["progress"],
                    "findings_count": pt["findings_count"],
                    "findings_by_severity": dict(pt["findings_by_severity"]),
                    "findings": [dict(f) for f in pt.get("findings", [])],
                }
            campaign.setdefault("snapshots", []).append(snapshot)
            return snapshot

    def diff_snapshot(self, campaign_id: str,
                      snapshot_id: str = "") -> Dict[str, Any]:
        """Diff a mid-run snapshot against the campaign's CURRENT (final)
        state. Returns the findings that appeared AFTER the snapshot,
        severity deltas, and risk delta — so you can see exactly which
        findings a specific workflow step produced.
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return {"error": f"Campaign not found: {campaign_id}"}
            snaps = campaign.get("snapshots", [])
            snap = None
            if snapshot_id:
                snap = next((s for s in snaps if s["snapshot_id"] == snapshot_id),
                            None)
                if not snap:
                    return {"error": f"Snapshot not found: {snapshot_id}"}
            elif snaps:
                snap = snaps[-1]
            else:
                return {"error": "No snapshots captured for this campaign"}

            # Findings present at snapshot time (dedupe key per target)
            snap_keys = set()
            for t, pt in snap["per_target"].items():
                for f in pt.get("findings", []):
                    k = f.get("dedupe_key") or f.get("title")
                    if k:
                        snap_keys.add((t, k))

            # Findings that appeared AFTER the snapshot
            new_findings = []
            for t, pt in campaign["per_target"].items():
                for f in pt.get("findings", []):
                    k = f.get("dedupe_key") or f.get("title")
                    if k and (t, k) not in snap_keys:
                        new_findings.append({"target": t, **f})

            # Severity deltas
            def _sev_totals(per_target):
                totals = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                          "info": 0}
                for pt in per_target.values():
                    for sev, n in (pt.get("findings_by_severity") or {}).items():
                        totals[sev] = totals.get(sev, 0) + n
                return totals

            before = _sev_totals(snap["per_target"])
            after = _sev_totals(campaign["per_target"])
            sev_delta = {sev: after[sev] - before.get(sev, 0)
                         for sev in after}

            return {
                "campaign_id": campaign_id,
                "snapshot_id": snap["snapshot_id"],
                "label": snap["label"],
                "captured": snap["captured"],
                "snapshot_status": snap["status"],
                "final_status": campaign["status"],
                "new_findings": new_findings,
                "new_findings_count": len(new_findings),
                "severity_delta": sev_delta,
                "findings_total_before": snap["findings_total"],
                "findings_total_after": campaign["findings_total"],
                "risk_before": snap["risk_score"],
                "risk_after": campaign["risk_score"],
                "risk_delta": round(campaign["risk_score"] - snap["risk_score"], 1),
            }

    # ═══════════════════════════════════════════════════════════════
    # CROSS-CAMPAIGN TRENDS (v5.5) — persistent exposure leaderboard
    # ═══════════════════════════════════════════════════════════════

    def campaign_trends(self, campaigns_dir: str = "campaigns") -> Dict[str, Any]:
        """
        Rank which vulnerabilities recur most often across ALL campaigns
        (in-memory + persisted history). Returns a leaderboard of persistent
        exposures: each unique dedupe_key with occurrence count, per-campaign
        severity heat, affected targets, and a trend arrow.
        """
        # Collect every campaign (in-memory first, then persisted)
        campaigns = []
        with self._lock:
            for cid, c in self._campaigns.items():
                campaigns.append((cid, c.get("name", cid), c.get("created", ""),
                                  c.get("per_target", {})))
        if os.path.isdir(campaigns_dir):
            for fn in sorted(os.listdir(campaigns_dir), reverse=True):
                if not fn.endswith(".json"):
                    continue
                cid = fn[:-5]
                try:
                    from core.state_store import read_json
                    data = read_json(os.path.join(campaigns_dir, fn))
                    if data is None:
                        continue
                    campaigns.append((cid, data.get("name", cid),
                                      data.get("created", ""),
                                      data.get("per_target", {})))
                except Exception:
                    continue

        SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        exposure_map: Dict[str, Dict[str, Any]] = {}
        for cid, name, created, per_target in campaigns:
            seen_in_campaign = set()
            for t, pt in (per_target or {}).items():
                for f in pt.get("findings", []) or []:
                    key = f.get("dedupe_key") or f.get("title")
                    if not key or key in seen_in_campaign:
                        continue
                    seen_in_campaign.add(key)
                    entry = exposure_map.setdefault(key, {
                        "dedupe_key": key,
                        "occurrences": 0,
                        "campaigns": [],
                        "targets": set(),
                        "worst_severity": "info",
                    })
                    entry["occurrences"] += 1
                    entry["campaigns"].append({
                        "campaign_id": cid,
                        "name": name,
                        "created": created,
                        "severity": (f.get("severity") or "info").lower(),
                    })
                    entry["targets"].add(t)
                    sev = (f.get("severity") or "info").lower()
                    if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(
                            entry["worst_severity"], 9):
                        entry["worst_severity"] = sev

        leaderboard = []
        for key, entry in exposure_map.items():
            cams = sorted(entry["campaigns"],
                          key=lambda c: c.get("created", ""))
            # Trend arrow: more recent campaigns with this exposure vs older
            mid = max(1, len(cams) // 2)
            recent = len([c for c in cams[mid:] if c.get("created")])
            older = len([c for c in cams[:mid] if c.get("created")])
            if recent > older:
                trend = "▲ rising"
            elif recent < older:
                trend = "▼ declining"
            else:
                trend = "→ stable"
            # Severity heat per campaign (for the dashboard heat grid)
            sev_heat = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                        "info": 0}
            for c in cams:
                sev_heat[c["severity"]] = sev_heat.get(c["severity"], 0) + 1
            leaderboard.append({
                "dedupe_key": key,
                "occurrences": entry["occurrences"],
                "campaigns": cams,
                "targets": sorted(entry["targets"]),
                "worst_severity": entry["worst_severity"],
                "severity_heat": sev_heat,
                "trend": trend,
                "persistent": entry["occurrences"] > 1,
            })
        leaderboard.sort(key=lambda x: (x["occurrences"],
                                        -SEV_ORDER.get(x["worst_severity"], 9)),
                         reverse=True)
        return {"leaderboard": leaderboard, "campaigns_scanned": len(campaigns),
                "total_exposures": len(leaderboard),
                "persistent_exposures": sum(1 for x in leaderboard if x["persistent"])}

    # ═══════════════════════════════════════════════════════════════
    # INTERNALS
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _risk_rating(score: float) -> str:
        """Map a raw risk score to a rating label (used by the persisted report)."""
        if score >= 75:
            return "🔴 Critical"
        if score >= 50:
            return "🟠 High"
        if score >= 25:
            return "🟡 Medium"
        if score > 5:
            return "🟢 Low"
        return "⚪ Minimal"

    @staticmethod
    def _serializable(campaign: Dict) -> Dict:
        """Deep-copy a campaign into a JSON-serializable dict (strip sets)."""
        data = copy.deepcopy(campaign)
        for pt in data.get("per_target", {}).values():
            pt.pop("_finding_keys", None)
        return data

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
