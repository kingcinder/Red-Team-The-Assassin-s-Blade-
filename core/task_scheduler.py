"""
RedTeam Harness — Concurrent Multi-Target Scheduler (v4.0)
Runs the same workflow template across N targets concurrently. Each target
gets its OWN TaskSandbox + WorkflowStateMachine (never shared — no state
races). Results, findings, and chain values are pooled into a combined
summary + report with cross-target dedup.

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

logger = logging.getLogger("redteam.scheduler")

DEFAULT_MAX_CONCURRENT = 3


class MultiTargetScheduler:
    """
    Runs a workflow across multiple targets concurrently and aggregates
    results into a single combined engagement summary + report.
    """

    def __init__(self, runner, llm, templates_dir: str = "workflows/templates",
                 tasks_dir: str = "tasks",
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                 emit: Optional[Callable] = None):
        self.runner = runner
        self.llm = llm
        self.templates_dir = templates_dir
        self.tasks_dir = tasks_dir
        self.max_concurrent = max_concurrent
        self._emit = emit  # callback(event_name, data) for dashboard events
        self._results_lock = threading.Lock()

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def run(self, workflow_name: str, targets: List[str],
            base_variables: Optional[Dict[str, Any]] = None,
            max_concurrent: Optional[int] = None,
            per_target_vars: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Run `workflow_name` against each target in `targets` concurrently.

        base_variables: shared across all targets (e.g. username, wordlist).
        per_target_vars: optional {target: extra_vars} merged over base.
        Returns a combined summary dict with per-target results, pooled
        findings, and a combined report path.
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
        # The hex suffix prevents collisions between concurrent/back-to-back
        # multi-runs in the same second (same fix as per-target sandboxes).
        import secrets as _secrets
        ts = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + _secrets.token_hex(2)
        combined_root = os.path.join(
            self.tasks_dir, workflow_name.replace(".yaml", ""), f"multi_{ts}")
        os.makedirs(combined_root, exist_ok=True)
        combined_id = f"multi_{workflow_name.replace('.yaml', '')}_{ts}"

        self._log(combined_root, f"Multi-target run: {len(targets)} targets, "
                                 f"{max_workers} workers")

        results: Dict[str, Dict[str, Any]] = {}
        all_findings: List[Dict[str, Any]] = []
        all_chain_values: Dict[str, str] = {}

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

            if self._emit:
                self._emit("workflow_start", {
                    "workflow": wf.get_summary(), "task_id": sandbox.task_id,
                    "root": sandbox.root, "target": target})

            result = wf.start()

            if self._emit:
                self._emit("workflow_complete", {"task_id": sandbox.task_id,
                                                 "target": target, **result})

            # Pool findings + chain values
            with self._results_lock:
                for f in result.get("findings", []):
                    f = dict(f)
                    f["target"] = str(target)
                    all_findings.append(f)
                for k, v in result.get("chain_values", {}).items():
                    all_chain_values.setdefault(k, str(v))

            return {"target": target, "task_id": sandbox.task_id,
                    "root": sandbox.root, **{k: v for k, v in result.items()
                                             if k not in ("findings", "steps")},
                    "steps_count": result.get("completed_steps", 0),
                    "total_steps": result.get("total_steps", 0),
                    "status": result.get("status", "unknown"),
                    "error": result.get("error"),
                    "report_path": result.get("report_path")}

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
        # A target that finished partial (some steps failed but workflow ran)
        # must NOT count as fully complete at the combined level.
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

        # Combined report
        combined_summary = {
            "combined_id": combined_id,
            "workflow": workflow_name,
            "targets": targets,
            "started": datetime.now().isoformat(),
            "per_target": results,
            "pooled_findings": deduped_findings,
            "findings_summary": counts,
            "chain_values": all_chain_values,
            "status": ("complete" if (len(results) and len(fully_complete) == len(results))
                       else ("failed" if errors or blocked else "partial")),
            "root": combined_root,
        }
        report_path = self._write_combined_report(combined_summary)
        combined_summary["report_path"] = report_path

        # Persist combined state
        try:
            state_path = os.path.join(combined_root, "state.json")
            with open(state_path, "w") as f:
                json.dump(combined_summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save combined state: {e}")

        self._log(combined_root, f"Multi-target complete: "
                                 f"{len(fully_complete)} complete, {len(errors)} errors, "
                                 f"{len(blocked)} failed; "
                                 f"{len(deduped_findings)} pooled findings")

        return combined_summary

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

    @staticmethod
    def _write_combined_report(summary: Dict[str, Any]) -> str:
        """Write a combined markdown report for the multi-target run."""
        lines = []
        lines.append(f"# Combined Engagement Report — {summary['workflow']}")
        lines.append("")
        lines.append(f"- **Targets**: {', '.join(summary['targets'])}")
        lines.append(f"- **Started**: {summary.get('started', '')}")
        lines.append(f"- **Status**: {summary.get('status', 'unknown')}")
        lines.append("")

        # Per-target summary
        lines.append("## 1. Per-Target Results")
        lines.append("")
        for t, r in summary["per_target"].items():
            lines.append(f"- **{t}**: {r.get('status', 'unknown')} "
                         f"({r.get('steps_count', 0)}/{r.get('total_steps', 0)} steps) "
                         f"{'— ' + str(r.get('error', '')) if r.get('error') else ''}")
        lines.append("")

        # Pooled findings
        findings = summary.get("pooled_findings", [])
        counts = summary.get("findings_summary", {})
        lines.append("## 2. Pooled Findings")
        lines.append("")
        if findings:
            lines.append(f"**{len(findings)} unique findings** across all targets "
                         f"(critical={counts.get('critical', 0)}, "
                         f"high={counts.get('high', 0)}, "
                         f"medium={counts.get('medium', 0)}):")
            lines.append("")
            for f in findings:
                lines.append(f"- [{f.get('severity', 'info').upper()}] "
                             f"**{f.get('title', '')}** "
                             f"`{f.get('target', '')}` — {f.get('evidence', '')[:120]}")
        else:
            lines.append("No findings extracted.")
        lines.append("")

        # Chain values
        if summary.get("chain_values"):
            lines.append("## 3. Shared Chain Values")
            lines.append("")
            lines.append("```")
            for k, v in summary["chain_values"].items():
                lines.append(f"{k} = {v}")
            lines.append("```")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by RedTeam Harness multi-target scheduler.*")

        report = "\n".join(lines)
        try:
            path = os.path.join(summary["root"], "report.md")
            with open(path, "w") as f:
                f.write(report)
            return path
        except Exception as e:
            logger.error(f"Failed to write combined report: {e}")
            return ""
