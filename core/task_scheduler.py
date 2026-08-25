"""
RedTeam Harness — Concurrent Multi-Target Scheduler (v5.0)
Runs the same workflow template across N targets concurrently. Each target
gets its OWN TaskSandbox + WorkflowStateMachine (never shared — no state
races). Results, findings, and chain values are pooled into a combined
summary + report with cross-target dedup.

v5.0 enhancements:
  - FindingCorrelator integration: correlated attack paths with kill chain,
    ATT&CK technique mapping, confidence scoring, and remediation
  - CampaignManager integration: auto-create/update campaigns with per-target
    live status, heatmap, and cumulative risk scoring
  - Real-time progress events via SocketIO (step completion, findings, drift)
  - Enhanced combined report with correlation summary, risk breakdown, and
    cross-target attack path graph

Thread-safety notes:
  - HardenedToolRunner's global semaphore (MAX_CONCURRENT_EXECUTIONS) is
    shared across worker threads, which is the intended global cap.
  - Each worker builds fresh TaskSandbox/WorkflowStateMachine instances, so
    self.state / _chain_values never race.
  - Audit log append on the shared runner uses list.append (atomic under the
    GIL) — acceptable for a log.
"""
import os
import json
import logging
import threading

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from core.task_isolation import TaskSandbox
from core.workflow_engine import WorkflowStateMachine
from core.findings import SEVERITY_ORDER
from core.correlation import FindingCorrelator

logger = logging.getLogger("redteam.scheduler")

DEFAULT_MAX_CONCURRENT = 3


class MultiTargetScheduler:
    """
    Runs a workflow across multiple targets concurrently and aggregates
    results into a single combined engagement summary + report with:
    - Cross-workflow finding correlation into scored attack paths
    - MITRE ATT&CK technique coverage mapping
    - Kill chain progression tracking
    - Concrete remediation steps per path/finding
    - CampaignManager integration for C2-style tracking
    - Real-time progress events for dashboard streaming
    """

    def __init__(self, runner, llm, templates_dir: str = "workflows/templates",
                 tasks_dir: str = "tasks",
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                 emit: Optional[Callable] = None,
                 campaign_mgr=None):
        self.runner = runner
        self.llm = llm
        self.templates_dir = templates_dir
        self.tasks_dir = tasks_dir
        self.max_concurrent = max_concurrent
        self._emit = emit  # callback(event_name, data) for dashboard events
        self._results_lock = threading.Lock()
        self._correlator = FindingCorrelator()
        self._campaign_mgr = campaign_mgr  # optional CampaignManager instance

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def run(self, workflow_name: str, targets: List[str],
            base_variables: Optional[Dict[str, Any]] = None,
            max_concurrent: Optional[int] = None,
            per_target_vars: Optional[Dict[str, Dict[str, Any]]] = None,
            campaign_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run `workflow_name` against each target in `targets` concurrently.

        base_variables: shared across all targets (e.g. username, wordlist).
        per_target_vars: optional {target: extra_vars} merged over base.
        campaign_id: optional existing campaign to update (auto-created if None).

        Returns a combined summary dict with per-target results, pooled
        findings, correlated attack paths, and a combined report path.
        """
        targets = [t for t in targets if t and str(t).strip()]
        if not targets:
            return {"error": "No targets provided"}
        if len(targets) > 50:
            return {"error": f"Too many targets ({len(targets)} > 50)"}

        # Resolve template path once
        template_path = self._resolve_template(workflow_name)
        if not template_path:
            return {"error": f"Workflow template not found: {workflow_name}"}

        max_workers = max(1, min(
            max_concurrent or self.max_concurrent, len(targets)))
        base_variables = base_variables or {}

        # Combined task container: tasks/<workflow>/multi_<timestamp>_<hex>/
        import secrets as _secrets
        ts = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + _secrets.token_hex(2)
        combined_root = os.path.join(
            self.tasks_dir, workflow_name.replace(".yaml", ""), f"multi_{ts}")
        os.makedirs(combined_root, exist_ok=True)
        combined_id = f"multi_{workflow_name.replace('.yaml', '')}_{ts}"

        # ── CampaignManager integration ──
        if campaign_id and self._campaign_mgr:
            self._campaign_mgr.mark_target_started(campaign_id, targets[0])
            # Mark all targets as started
            for t in targets:
                self._campaign_mgr.mark_target_started(campaign_id, t)
        elif self._campaign_mgr and not campaign_id:
            camp = self._campaign_mgr.create_campaign(
                name=f"Multi-target: {workflow_name}",
                targets=targets,
                workflow=workflow_name,
                description=f"Auto-created for {len(targets)} target run")
            campaign_id = camp.get("id")

        self._log(combined_root, f"Multi-target run: {len(targets)} targets, "
                                 f"{max_workers} workers"
                                 f"{f', campaign={campaign_id}' if campaign_id else ''}")

        self._emit("scheduler_start", {
            "combined_id": combined_id,
            "workflow": workflow_name,
            "targets": targets,
            "max_workers": max_workers,
            "campaign_id": campaign_id,
        })

        results: Dict[str, Dict[str, Any]] = {}
        all_findings: List[Dict[str, Any]] = []
        all_chain_values: Dict[str, str] = {}
        completed_count = [0]  # mutable counter for progress events
        total_count = len(targets)

        def run_one(target: str) -> Dict[str, Any]:
            # Fresh sandbox + state machine per target — no shared state
            sandbox = TaskSandbox(workflow_name.replace(".yaml", ""),
                                  base_dir=self.tasks_dir)
            sandbox.setup()
            variables = dict(base_variables)
            variables["target"] = str(target)
            if per_target_vars and target in per_target_vars:
                variables.update(per_target_vars[target])

            wf = WorkflowStateMachine(template_path, sandbox, self.runner,
                                      variables, llm=self.llm)
            try:
                wf.load()
            except Exception as e:
                return {"target": target, "status": "error",
                        "error": f"template load failed: {e}",
                        "task_id": sandbox.task_id, "root": sandbox.root}

            self._emit("workflow_start", {
                "workflow": wf.get_summary(), "task_id": sandbox.task_id,
                "root": sandbox.root, "target": target,
                "combined_id": combined_id})

            # Real-time progress: target starting
            self._emit("multi_target_progress", {
                "combined_id": combined_id,
                "target": target,
                "phase": "started",
                "completed": completed_count[0],
                "total": total_count,
            })

            result = wf.start()

            self._emit("workflow_complete", {"task_id": sandbox.task_id,
                                              "target": target, **result})

            # Real-time progress: target complete
            with self._results_lock:
                completed_count[0] += 1

            target_findings = result.get("findings", [])
            self._emit("multi_target_progress", {
                "combined_id": combined_id,
                "target": target,
                "phase": "complete",
                "status": result.get("status", "unknown"),
                "completed": completed_count[0],
                "total": total_count,
                "findings_count": len(target_findings),
                "steps_count": result.get("completed_steps", 0),
                "total_steps": result.get("total_steps", 0),
                "error": result.get("error"),
            })

            # Compute drift for this target (always, for reporting)
            drift_scores = [
                s.get("drift_score", 0)
                for s in result.get("steps", [])
                if s.get("drift_score")
            ]
            avg_drift = (sum(drift_scores) / len(drift_scores)
                         if drift_scores else 0.0)

            # ── CampaignManager: update target status ──
            if campaign_id and self._campaign_mgr:
                self._campaign_mgr.update_target(campaign_id, target, {
                    "status": result.get("status", "unknown"),
                    "completed_steps": result.get("completed_steps", 0),
                    "total_steps": result.get("total_steps", 0),
                    "findings": target_findings,
                    "drift_score": avg_drift,
                    "error": result.get("error"),
                })

            # Pool findings + chain values (thread-safe)
            with self._results_lock:
                for f in target_findings:
                    f = dict(f)
                    f["target"] = str(target)
                    all_findings.append(f)
                for k, v in result.get("chain_values", {}).items():
                    all_chain_values.setdefault(k, str(v))

            return {"target": target, "task_id": sandbox.task_id,
                    "root": sandbox.root,
                    **{k: v for k, v in result.items()
                       if k not in ("findings", "steps")},
                    "steps_count": result.get("completed_steps", 0),
                    "total_steps": result.get("total_steps", 0),
                    "status": result.get("status", "unknown"),
                    "error": result.get("error"),
                    "report_path": result.get("report_path"),
                    "findings_count": len(target_findings),
                    "drift_score": avg_drift if drift_scores else 0.0,
                    "steps": result.get("steps", [])}

        # ── Concurrent execution ──
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(run_one, t): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results[target] = fut.result()
                except Exception as e:
                    logger.error(f"Worker failed for {target}: {e}", exc_info=True)
                    results[target] = {"target": target, "status": "error",
                                       "error": str(e)}

        # ── Aggregate ──
        errors = [r for r in results.values() if r.get("status") == "error"]
        blocked = [r for r in results.values() if r.get("status") == "failed"]
        fully_complete = [r for r in results.values()
                          if r.get("status") == "complete"]

        # Dedup findings across targets by (target, dedupe_key)
        seen = set()
        deduped_findings = []
        for f in all_findings:
            key = (f.get("target"), f.get("dedupe_key"))
            if key in seen:
                continue
            seen.add(key)
            deduped_findings.append(f)

        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in deduped_findings:
            counts[f.get("severity", "info")] = \
                counts.get(f.get("severity", "info"), 0) + 1

        # ── Cross-workflow finding correlation ──
        self._emit("scheduler_progress", {
            "combined_id": combined_id,
            "phase": "correlating",
            "findings_count": len(deduped_findings),
        })

        correlated_paths = self._correlator.correlate(deduped_findings)
        augmented_findings = self._correlator.augment_findings(deduped_findings)

        # Attack graph data (shared across all paths)
        attack_graph = correlated_paths[0].get("graph", {}) if correlated_paths else {
            "nodes": [], "edges": [], "metadata": {}}

        # ATT&CK coverage
        all_techniques = set()
        for p in correlated_paths:
            for t in p.get("attack_techniques", []):
                all_techniques.add(t["id"])

        # Kill chain coverage
        all_phases = set()
        for p in correlated_paths:
            all_phases.update(p.get("kill_chain_phases", []))

        # Risk score
        risk = self._compute_combined_risk(counts, len(targets),
                                            len(fully_complete),
                                            correlated_paths)

        combined_summary = {
            "combined_id": combined_id,
            "workflow": workflow_name,
            "targets": targets,
            "started": datetime.now().isoformat(),
            "finished": datetime.now().isoformat(),
            "per_target": results,
            "pooled_findings": deduped_findings,
            "augmented_findings": augmented_findings,
            "findings_summary": counts,
            "chain_values": all_chain_values,
            "correlated_paths": correlated_paths,
            "attack_graph": attack_graph,
            "attack_techniques": sorted(all_techniques),
            "kill_chain_phases": sorted(all_phases),
            "risk_score": risk,
            "campaign_id": campaign_id,
            "status": ("complete" if (len(results) and len(fully_complete) == len(results))
                       else ("failed" if errors or blocked else "partial")),
            "root": combined_root,
        }

        # Generate enhanced combined report
        report_path = self._write_combined_report(combined_summary)
        combined_summary["report_path"] = report_path

        # Persist combined state
        try:
            state_path = os.path.join(combined_root, "state.json")
            with open(state_path, "w") as f:
                json.dump(combined_summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save combined state: {e}")

        # ── CampaignManager: mark campaign complete ──
        if campaign_id and self._campaign_mgr:
            self._campaign_mgr.mark_campaign_complete(campaign_id)

        self._emit("scheduler_complete", {
            "combined_id": combined_id,
            "campaign_id": campaign_id,
            "status": combined_summary["status"],
            "targets_total": len(targets),
            "targets_complete": len(fully_complete),
            "targets_failed": len(errors) + len(blocked),
            "findings_total": len(deduped_findings),
            "paths_correlated": len(correlated_paths),
            "risk_score": risk["total"],
            "report_path": report_path,
        })

        self._log(combined_root, f"Multi-target complete: "
                                 f"{len(fully_complete)} complete, "
                                 f"{len(errors)} errors, "
                                 f"{len(blocked)} failed; "
                                 f"{len(deduped_findings)} pooled findings; "
                                 f"{len(correlated_paths)} attack paths; "
                                 f"risk={risk['total']}/100")

        return combined_summary

    # ═══════════════════════════════════════════════════════════════
    # Risk Scoring
    # ═══════════════════════════════════════════════════════════════

    def _compute_combined_risk(self, counts: Dict[str, int],
                               total_targets: int, completed_targets: int,
                               paths: List[Dict]) -> Dict[str, Any]:
        """Compute cumulative risk score for the combined engagement."""
        SEV_RISK = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0.5}

        # Findings severity risk (0-100)
        severity_risk = sum(SEV_RISK.get(sev, 1) * cnt
                           for sev, cnt in counts.items())
        severity_risk = min(100.0, severity_risk)

        # Critical path bonus (0-30)
        crit_paths = [p for p in paths if p["severity"] == "critical"]
        high_paths = [p for p in paths if p["severity"] == "high"]
        criticality = min(30.0, len(crit_paths) * 10 + len(high_paths) * 4)

        # Coverage (0-20)
        coverage = (completed_targets / max(total_targets, 1)) * 20

        # Kill chain depth bonus (0-20)
        max_depth = max((len(p.get("kill_chain_phases", [])) for p in paths),
                        default=0)
        chain_bonus = min(20.0, max_depth * 5)

        total = round(min(100.0,
            severity_risk * 0.45 +
            criticality * 0.25 +
            coverage * 0.15 +
            chain_bonus * 0.15), 1)

        if total >= 75:
            rating = "CRITICAL"
        elif total >= 50:
            rating = "HIGH"
        elif total >= 25:
            rating = "MEDIUM"
        elif total > 5:
            rating = "LOW"
        else:
            rating = "MINIMAL"

        return {
            "total": total,
            "rating": rating,
            "breakdown": {
                "severity_risk": round(severity_risk * 0.45, 1),
                "criticality": round(criticality * 0.25, 1),
                "coverage": round(coverage * 0.15, 1),
                "chain_depth": round(chain_bonus * 0.15, 1),
            },
        }

    # ═══════════════════════════════════════════════════════════════
    # Enhanced Combined Report
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _write_combined_report(summary: Dict[str, Any]) -> str:
        """Write a comprehensive combined markdown report with correlation."""
        lines = []
        workflow = summary["workflow"]
        risk = summary.get("risk_score", {})
        paths = summary.get("correlated_paths", [])
        counts = summary.get("findings_summary", {})

        lines.append(f"# Combined Engagement Report — {workflow}")
        lines.append("")
        lines.append(f"- **Targets**: {', '.join(summary['targets'])}")
        lines.append(f"- **Started**: {summary.get('started', '')}")
        lines.append(f"- **Status**: {summary.get('status', 'unknown')}")
        lines.append(f"- **Risk Score**: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})")
        if summary.get("campaign_id"):
            lines.append(f"- **Campaign**: {summary['campaign_id']}")
        lines.append("")

        # ── Executive Summary ──
        lines.append("## 1. Executive Summary")
        lines.append("")
        targets = summary["targets"]
        findings = summary.get("pooled_findings", [])
        lines.append(f"Assessed **{len(targets)} target(s)** using workflow "
                     f"`{workflow}`. Identified **{len(findings)} unique finding(s)** "
                     f"across all targets, correlated into **{len(paths)} attack path(s)**.")
        lines.append("")
        lines.append(f"**Risk Assessment: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})**")
        lines.append("")

        # Severity breakdown table
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = counts.get(sev, 0)
            if c > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                         "low": "🔵", "info": "⚪"}.get(sev, "⚪")
                lines.append(f"| {emoji} {sev.upper()} | {c} |")
        lines.append("")

        # ── Per-Target Results ──
        lines.append("## 2. Per-Target Results")
        lines.append("")
        lines.append("| Target | Status | Steps | Findings | Drift |")
        lines.append("|--------|--------|-------|----------|-------|")
        for t, r in summary["per_target"].items():
            status = r.get("status", "unknown")
            emoji = {"complete": "✅", "partial": "⚠️", "failed": "❌",
                     "error": "💀"}.get(status, "❓")
            lines.append(
                f"| {t} | {emoji} {status} | "
                f"{r.get('steps_count', 0)}/{r.get('total_steps', 0)} | "
                f"{r.get('findings_count', 0)} | "
                f"{r.get('drift_score', 0):.2f} |")
        lines.append("")

        # ── Correlated Attack Paths ──
        if paths:
            lines.append("## 3. Correlated Attack Paths")
            lines.append("")
            lines.append(
                f"{len(paths)} attack path(s) identified across all targets:")
            lines.append("")

            # Summary table
            lines.append("| # | Severity | Path | Score | Confidence "
                         "| Kill Chain | ATT&CK |")
            lines.append("|---|----------|------|-------|------------"
                         "|------------|--------|")
            for i, p in enumerate(paths[:15], 1):
                sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                             "low": "🔵", "info": "⚪"}.get(p["severity"], "⚪")
                kill_pct = f"{p.get('kill_chain_progress', 0)*100:.0f}%"
                techs = ", ".join(t["id"] for t in p.get("attack_techniques", [])[:3])
                lines.append(
                    f"| {i} | {sev_emoji} {p['severity'].upper()} | "
                    f"{p['title']} | {p['score']} | "
                    f"{p.get('confidence', 0)*100:.0f}% | {kill_pct} | {techs} |")
            lines.append("")

            # Detailed paths
            for i, p in enumerate(paths[:10], 1):
                sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                             "low": "🔵", "info": "⚪"}.get(p["severity"], "⚪")
                lines.append(f"### {i}. {sev_emoji} {p['title']}")
                lines.append(f"- **Score**: {p['score']} | **Confidence**: "
                             f"{p.get('confidence', 0)*100:.0f}%")
                lines.append(f"- **Kill Chain**: "
                             f"{p.get('kill_chain_progress', 0)*100:.0f}% "
                             f"(phases: {', '.join(p.get('kill_chain_phases', []))})")

                if p.get("attack_techniques"):
                    tech_str = ", ".join(
                        f"`{t['id']}` {t.get('name', '')}"
                        for t in p["attack_techniques"][:5])
                    lines.append(f"- **ATT&CK**: {tech_str}")

                if p.get("finding_details"):
                    lines.append("- **Linked Findings**:")
                    for fd in p["finding_details"][:5]:
                        lines.append(
                            f"  - [{fd['severity'].upper()}] {fd['title']} "
                            f"(`{fd.get('source_tool', '')}`)")

                lines.append("- **Remediation**:")
                for r in p["remediation"]:
                    lines.append(f"  - {r}")
                lines.append("")

            # ATT&CK coverage
            all_techs = summary.get("attack_techniques", [])
            if all_techs:
                lines.append("### MITRE ATT&CK Coverage")
                lines.append("")
                lines.append(f"**{len(all_techs)} technique(s)** mapped:")
                lines.append("")
                lines.append(", ".join(f"`{t}`" for t in all_techs))
                lines.append("")

            # Kill chain coverage
            all_phases = summary.get("kill_chain_phases", [])
            if all_phases:
                lines.append("### Kill Chain Coverage")
                lines.append("")
                lines.append(", ".join(f"`{p}`" for p in all_phases))
                lines.append("")
        else:
            lines.append("## 3. Correlated Attack Paths")
            lines.append("")
            lines.append("No correlated attack paths identified.")
            lines.append("")

        # ── Pooled Findings Detail ──
        lines.append("## 4. Pooled Findings")
        lines.append("")
        if findings:
            lines.append(f"**{len(findings)} unique finding(s)**:")
            lines.append("")
            for f in findings:
                target = f.get("target", "")
                sev = f.get("severity", "info").upper()
                lines.append(
                    f"- [{sev}] **{f.get('title', '')}** "
                    f"(`{target}`) — "
                    f"{f.get('evidence', '')[:120]}")
        else:
            lines.append("No findings extracted.")
        lines.append("")

        # ── Chain Values ──
        if summary.get("chain_values"):
            lines.append("## 5. Extracted Chain Values")
            lines.append("")
            lines.append("```")
            for k, v in summary["chain_values"].items():
                lines.append(f"{k} = {v}")
            lines.append("```")
            lines.append("")

        # ── Risk Breakdown ──
        if risk:
            lines.append("## 6. Risk Score Breakdown")
            lines.append("")
            lines.append(f"- **Total**: {risk['total']}/100 ({risk['rating']})")
            for k, v in risk.get("breakdown", {}).items():
                lines.append(f"  - {k}: {v}")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by RedTeam Harness v5.0 multi-target scheduler "
                     "with finding correlation.*")

        report = "\n".join(lines)
        try:
            path = os.path.join(summary["root"], "report.md")
            with open(path, "w") as f:
                f.write(report)
            return path
        except Exception as e:
            logger.error(f"Failed to write combined report: {e}")
            return ""

    # ═══════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════

    def _resolve_template(self, workflow_name: str) -> Optional[str]:
        name = workflow_name if workflow_name.endswith((".yaml", ".yml")) \
            else workflow_name + ".yaml"
        path = os.path.join(self.templates_dir, name)
        if os.path.exists(path):
            return path
        alt = os.path.join(self.templates_dir,
                           workflow_name.replace(".yaml", "") + ".yml")
        if os.path.exists(alt):
            return alt
        return None

    def _log(self, root: str, msg: str):
        try:
            logs = os.path.join(root, "logs")
            os.makedirs(logs, exist_ok=True)
            with open(os.path.join(logs, "scheduler.log"), "a") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")
        except Exception:
            pass
