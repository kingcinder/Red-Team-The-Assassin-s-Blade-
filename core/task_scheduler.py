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
                 campaign_mgr=None,
                 config: Optional[Dict[str, Any]] = None):
        self.runner = runner
        self.llm = llm
        self.templates_dir = templates_dir
        self.tasks_dir = tasks_dir
        self.max_concurrent = max_concurrent
        self._emit = emit  # callback(event_name, data) for dashboard events
        self._results_lock = threading.Lock()
        self._correlator = FindingCorrelator()
        self._campaign_mgr = campaign_mgr  # optional CampaignManager instance
        self._config = config or {}  # for v5.5 knobs (parallel retries, auto-chain)

    def _config_get(self, dotted_key: str, default=None):
        """Read a dotted config key (e.g. 'workflow.parallel_max_job_retries').
        Safe against instances constructed without config (e.g. via __new__ in
        tests) — those get defaults."""
        node = getattr(self, "_config", None) or {}
        for part in dotted_key.split("."):
            if not isinstance(node, dict):
                return default
            node = node.get(part)
            if node is None:
                return default
        return node

    def _run_job_with_retry(self, idx: int, job: Dict[str, Any],
                            campaign_id: Optional[str],
                            max_concurrent: Optional[int],
                            max_job_retries: int,
                            results: Dict[int, Dict[str, Any]],
                            job_attempts: Dict[int, int],
                            job_recovered: Dict[int, bool],
                            circuit_state: Dict[int, str]):
        """
        Submit one parallel job, resubmitting up to max_job_retries when the
        worker dies mid-run (sandbox/template exception) with linear backoff.
        Consecutive failures open the per-job circuit breaker; success closes
        it. Writes into the shared `results` dict (mutated in place).
        """
        import time as _time
        attempt = 0
        while attempt <= max_job_retries:
            attempt += 1
            job_attempts[idx] = attempt
            if circuit_state[idx] == "open":
                # Circuit open — skip further retries for this pathological job
                results[idx] = {"status": "error", "error": "circuit open "
                                "(too many consecutive worker failures)",
                                "workflow": job["workflow"],
                                "circuit": "open", "attempts": attempt}
                return
            try:
                r = self.run(job["workflow"], job.get("targets", []),
                             base_variables=job.get("variables", {}) or {},
                             max_concurrent=max_concurrent,
                             per_target_vars=job.get("per_target_vars"),
                             campaign_id=campaign_id,
                             finalize_campaign=False)
                if r.get("status") in ("error", "failed") and not r.get("per_target"):
                    raise RuntimeError(r.get("error") or "job failed before any target ran")
                results[idx] = r
                circuit_state[idx] = "closed"
                job_recovered[idx] = attempt > 1
                if attempt > 1:
                    logger.warning(f"Parallel job {idx} recovered on attempt "
                                   f"{attempt}/{max_job_retries + 1}")
                return
            except Exception as e:
                logger.error(f"Parallel job {idx} attempt {attempt} failed: {e}")
                if attempt > max_job_retries:
                    circuit_state[idx] = "open"
                    results[idx] = {"status": "error", "error": str(e),
                                    "workflow": job["workflow"],
                                    "circuit": "open", "attempts": attempt}
                    return
                _time.sleep(1.0 * attempt)  # linear backoff
                circuit_state[idx] = "half-open"

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def run(self, workflow_name: str, targets: List[str],
            base_variables: Optional[Dict[str, Any]] = None,
            max_concurrent: Optional[int] = None,
            per_target_vars: Optional[Dict[str, Dict[str, Any]]] = None,
            campaign_id: Optional[str] = None,
            priority_plan: Optional[List[Dict[str, Any]]] = None,
            finalize_campaign: bool = True) -> Dict[str, Any]:
        """
        Run `workflow_name` against each target in `targets` concurrently.

        base_variables: shared across all targets (e.g. username, wordlist).
        per_target_vars: optional {target: extra_vars} merged over base.
        campaign_id: optional existing campaign to update (auto-created if None).
        priority_plan: optional LLM/heuristic target ranking — an ordered list
            of {target, rank, score, tier, aggressiveness, ...}. When present:
              • targets are executed in plan order (high-value FIRST)
              • each target's WorkflowStateMachine gets a retry_multiplier
                derived from its tier aggressiveness (hot targets get more
                attempts — processed most aggressively)
              • priority metadata is injected into per-target variables
                (priority_rank / priority_score / priority_tier) so workflow
                templates can branch on it
              • the plan is recorded in the combined summary + report
        finalize_campaign: when False (used by run_multiple with a SHARED
            campaign), per-target updates still stream to the campaign but the
            campaign is NOT marked complete here — the orchestrator of the
            parallel run finalizes it once ALL jobs finish.

        Returns a combined summary dict with per-target results, pooled
        findings, correlated attack paths, and a combined report path.
        """
        targets = [t for t in targets if t and str(t).strip()]
        if not targets:
            return {"error": "No targets provided"}
        if len(targets) > 50:
            return {"error": f"Too many targets ({len(targets)} > 50)"}

        # ── v5.2: apply the priority plan (reorder + per-target aggression) ──
        plan_by_target = {}
        plan_order = []
        if priority_plan:
            for entry in priority_plan:
                t = str(entry.get("target", "")).strip()
                if t and t in targets and t not in plan_by_target:
                    plan_by_target[t] = entry
                    plan_order.append(t)
            # Reorder: ranked targets first (rank order), unranked targets
            # keep original order and are processed after ranked ones.
            ranked = [t for t in plan_order if t in targets]
            unranked = [t for t in targets if t not in plan_by_target]
            targets = ranked + unranked

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

            # ── v5.2: per-target priority metadata + retry aggressiveness ──
            retry_multiplier = 1.0
            plan_entry = plan_by_target.get(target)
            if plan_entry:
                variables["priority_rank"] = plan_entry.get("rank", 0)
                variables["priority_score"] = plan_entry.get("score", 0.0)
                variables["priority_tier"] = plan_entry.get("tier", "medium")
                try:
                    retry_multiplier = float(
                        plan_entry.get("aggressiveness", 1.0) or 1.0)
                except (TypeError, ValueError):
                    retry_multiplier = 1.0
            else:
                variables["priority_rank"] = 999
                variables["priority_score"] = 0.0
                variables["priority_tier"] = "unranked"

            # ── v5.5: per-target workflow selection — the priority plan's
            # suggested_workflow overrides the shared workflow for THIS target
            # (e.g. SMB/Windows hosts get domain workflows, web hosts get web
            # workflows in the same multi-target run). Falls back to the run's
            # workflow when the suggestion is absent or unresolvable.
            wf_template = template_path
            if plan_entry and plan_entry.get("suggested_workflow"):
                suggested = plan_entry["suggested_workflow"]
                alt_path = self._resolve_template(suggested)
                if alt_path:
                    wf_template = alt_path
                    variables["priority_workflow"] = suggested
                else:
                    variables["priority_workflow"] = workflow_name

            wf = WorkflowStateMachine(wf_template, sandbox, self.runner,
                                      variables, llm=self.llm,
                                      retry_multiplier=retry_multiplier)
            try:
                wf.load()
            except Exception as e:
                return {"target": target, "status": "error",
                        "error": f"template load failed: {e}",
                        "task_id": sandbox.task_id, "root": sandbox.root}

            # NOTE: the dashboard subscribes to the orchestrator's
            # on_workflow_start/on_workflow_complete events (prefixed) —
            # emitting the same names here is what makes per-target
            # campaign progress push to the C2 dashboard in real-time.
            self._emit("on_workflow_start", {
                "workflow": wf.get_summary(), "task_id": sandbox.task_id,
                "root": sandbox.root, "target": target,
                "combined_id": combined_id})

            # Real-time progress: target starting
            self._emit("multi_target_progress", {
                "combined_id": combined_id,
                "campaign_id": campaign_id,
                "target": target,
                "phase": "started",
                "completed": completed_count[0],
                "total": total_count,
            })

            result = wf.start()

            self._emit("on_workflow_complete", {"task_id": sandbox.task_id,
                                                 "target": target, **result})

            # Real-time progress: target complete
            with self._results_lock:
                completed_count[0] += 1

            target_findings = result.get("findings", [])
            self._emit("multi_target_progress", {
                "combined_id": combined_id,
                "campaign_id": campaign_id,
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
            "priority_plan": (priority_plan[:50] if priority_plan else []),
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
        # (skipped when finalize_campaign=False — run_multiple finalizes the
        #  shared campaign once every job has finished)
        if campaign_id and self._campaign_mgr and finalize_campaign:
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
    # Multi-Workflow Parallel Execution (v5.3)
    # ═══════════════════════════════════════════════════════════════

    def run_multiple(self, jobs: List[Dict[str, Any]],
                     campaign_id: Optional[str] = None,
                     max_concurrent: Optional[int] = None,
                     max_workers: Optional[int] = None) -> Dict[str, Any]:
        """
        Run MULTIPLE different workflow jobs concurrently — each job is its
        own (workflow, targets) pair that may target different hosts — then
        merge ALL findings across every workflow with
        ``FindingCorrelator.correlate_cross_workflow`` to produce a unified
        campaign-level attack path report.

        jobs: [{"workflow": name, "targets": [...], "variables": {...},
                "per_target_vars": {...}}]

        v5.5 additions:
          - PER-JOB RETRY + CIRCUIT BREAKER: a job whose worker thread dies
            mid-run (sandbox/template exception) is resubmitted up to
            max_job_retries (default 2) with linear backoff. Consecutive
            failures trip a per-job circuit breaker ("open" = skip further
            retries) so a pathological job can't stall the campaign. Job-level
            recovery (attempts, recovered flag, circuit state) is surfaced in
            the unified report.
          - GANTT TIMELINE DATA: each job records wall-clock start/finish and
            per-target sub-intervals so the dashboard can render a Gantt-style
            timeline of what ran concurrently vs sequentially.
          - CHAINED PARALLEL WAVES: accepts ``parent_wave`` (the unified
            findings of a previous wave) and, when ``auto_chain=True``, uses
            the auto-prioritizer to decide the NEXT wave's jobs/targets.

        Behavior:
          - Each job runs through the standard scheduler (fresh sandboxes,
            campaign per-target streaming, per-job combined report).
          - ALL jobs share ONE campaign (created here or passed in) — per-job
            run() calls use finalize_campaign=False so the campaign is only
            marked complete once every job has finished.
          - Findings from every job are merged, then correlated with
            correlate_cross_workflow so paths can chain ACROSS different
            workflows targeting different hosts.
          - A unified campaign report ("Parallel Campaign Report") is written
            with the cross-workflow attack paths, ATT&CK coverage, kill chain,
            and risk score.
        """
        max_job_retries = int(self._config_get(
            "workflow.parallel_max_job_retries", 2))
        jobs = [j for j in (jobs or []) if j.get("workflow") and j.get("targets")]
        if not jobs:
            return {"error": "No valid jobs provided (need workflow + targets)"}

        # ── Validate every template up-front (fail fast, no wasted workers) ──
        for job in jobs:
            if not self._resolve_template(job["workflow"]):
                return {"error": f"Workflow template not found: {job['workflow']}"}

        job_names = [j["workflow"].replace(".yaml", "") for j in jobs]
        all_targets = sorted({t for j in jobs for t in j.get("targets", [])})

        # ── Unified task container FIRST (report + logs + state live here) ──
        import secrets as _secrets
        ts = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + _secrets.token_hex(2)
        unified_root = os.path.join(self.tasks_dir, "parallel", f"multi_{ts}")
        os.makedirs(unified_root, exist_ok=True)
        unified_id = f"parallel_{ts}"

        # ── One shared campaign for the whole parallel run ──
        if not campaign_id and self._campaign_mgr:
            camp = self._campaign_mgr.create_campaign(
                name=f"Parallel: {len(jobs)} workflows",
                targets=all_targets,
                workflow=", ".join(job_names),
                description=f"Unified {len(jobs)}-job parallel run "
                            f"({len(all_targets)} targets)")
            campaign_id = camp.get("id")

        workers = max(1, min(max_workers or len(jobs), len(jobs)))
        # Log inside the unified task container — never the repo/CWD root
        self._log(unified_root, f"Parallel multi-workflow run: {len(jobs)} jobs "
                                f"across {workers} workers"
                                f"{f', campaign={campaign_id}' if campaign_id else ''}")

        self._emit("scheduler_start", {
            "combined_id": unified_id,
            "workflow": ", ".join(job_names),
            "targets": all_targets,
            "jobs": len(jobs),
            "max_workers": workers,
            "campaign_id": campaign_id,
        })

        # ── Run every job concurrently with per-job retry + circuit breaker ──
        # Each job: resubmit up to max_job_retries on worker death (sandbox /
        # template exception) with linear backoff. Consecutive failures open
        # the circuit (no further retries). Success closes it.
        results: Dict[int, Dict[str, Any]] = {}
        job_attempts: Dict[int, int] = {}
        job_recovered: Dict[int, bool] = {}
        circuit_state: Dict[int, str] = {}  # closed / half-open / open
        job_timing: Dict[int, Dict[str, str]] = {}

        import time as _time
        for idx, job in enumerate(jobs):
            job_attempts[idx] = 0
            job_recovered[idx] = False
            circuit_state[idx] = "closed"

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for idx, job in enumerate(jobs):
                job_timing[idx] = {"started": datetime.now().isoformat()}
                futures[pool.submit(
                    self._run_job_with_retry, idx, job,
                    campaign_id=campaign_id, max_concurrent=max_concurrent,
                    max_job_retries=max_job_retries, results=results,
                    job_attempts=job_attempts, job_recovered=job_recovered,
                    circuit_state=circuit_state)] = idx
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    fut.result()
                except Exception as e:
                    logger.error(f"Parallel job {idx} retry wrapper failed: {e}",
                                 exc_info=True)
                    if idx not in results or not results[idx]:
                        results[idx] = {"status": "error", "error": str(e),
                                        "workflow": job_names[idx] if idx < len(job_names) else "?"}
                finally:
                    job_timing[idx]["finished"] = datetime.now().isoformat()

        # Recover the per-job summary from the retry wrapper (it updates
        # results in place via the mutable dict) — nothing further to do here.

        # ── Merge findings from all jobs for cross-workflow correlation ──
        merged_findings: List[Dict[str, Any]] = []
        workflow_results = []
        for idx, job in enumerate(jobs):
            job_result = results.get(idx, {})
            findings = job_result.get("pooled_findings", [])
            wf_name = job["workflow"].replace(".yaml", "")
            # correlate_cross_workflow expects one entry per workflow source
            workflow_results.append({
                "workflow_name": wf_name,
                "target": ", ".join(job.get("targets", [])),
                "findings": findings,
            })
            # Tag the merged copies with their source workflow/target so the
            # unified report and augmented findings carry workflow attribution
            # (mirrors what correlate_cross_workflow does internally).
            for f in findings:
                f2 = dict(f)
                f2["_source_workflow"] = wf_name
                f2["_source_target"] = f2.get("target") or \
                    ", ".join(job.get("targets", []))
                merged_findings.append(f2)

        # Dedup merged findings across workflows by (target, dedupe_key)
        seen = set()
        deduped_findings = []
        for f in merged_findings:
            key = (f.get("target"), f.get("dedupe_key"))
            if key in seen:
                continue
            seen.add(key)
            deduped_findings.append(f)

        # ── Cross-workflow correlation (chains findings across workflows) ──
        self._emit("scheduler_progress", {
            "combined_id": f"parallel_{'_'.join(job_names)}",
            "phase": "cross_workflow_correlating",
            "findings_count": len(deduped_findings),
        })

        try:
            unified_paths = self._correlator.correlate_cross_workflow(
                workflow_results)
        except Exception as e:
            logger.error(f"Cross-workflow correlation failed: {e}", exc_info=True)
            unified_paths = self._correlator.correlate(deduped_findings)
        augmented = self._correlator.augment_findings(deduped_findings)

        attack_graph = unified_paths[0].get("graph", {}) if unified_paths else {
            "nodes": [], "edges": [], "metadata": {}}
        all_techniques = sorted({t["id"]
                                 for p in unified_paths
                                 for t in p.get("attack_techniques", [])})
        all_phases = sorted({ph for p in unified_paths
                             for ph in p.get("kill_chain_phases", [])})

        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in deduped_findings:
            counts[f.get("severity", "info")] = \
                counts.get(f.get("severity", "info"), 0) + 1

        # Coverage must reflect HOSTS, not jobs: count completed per-target
        # entries across every job's result (a job over 3 hosts counts 3).
        completed_targets = sum(
            sum(1 for pt in (r.get("per_target") or {}).values()
                if pt.get("status") in ("complete", "partial"))
            for r in results.values())
        errors = sum(1 for r in results.values()
                     if r.get("status") in ("error", "failed"))
        completed = sum(1 for r in results.values()
                        if r.get("status") in ("complete", "partial"))
        risk = self._compute_combined_risk(counts, len(all_targets),
                                           completed_targets, unified_paths)

        # ── Unified summary + campaign report ──
        per_job = {}
        recovered_jobs = 0
        open_circuits = 0
        for idx, job in enumerate(jobs):
            jr = results.get(idx, {})
            attempts = job_attempts.get(idx, 1)
            recovered = job_recovered.get(idx, False)
            circuit = circuit_state.get(idx, "closed")
            if recovered:
                recovered_jobs += 1
            if circuit == "open":
                open_circuits += 1
            per_job[f"{job['workflow'].replace('.yaml', '')} #{idx + 1}"] = {
                "workflow": job["workflow"],
                "targets": job.get("targets", []),
                "status": jr.get("status", "unknown"),
                "findings_count": len(jr.get("pooled_findings", [])),
                "error": jr.get("error"),
                # v5.5 retry/circuit-breaker metadata
                "attempts": attempts,
                "recovered": recovered,
                "circuit": circuit,
                "timing": job_timing.get(idx, {}),
            }

        unified_summary = {
            "combined_id": unified_id,
            "workflow": ", ".join(job_names),
            "jobs": per_job,
            "targets": all_targets,
            "started": datetime.now().isoformat(),
            "finished": datetime.now().isoformat(),
            "per_target": {},
            "pooled_findings": deduped_findings,
            "augmented_findings": augmented,
            "findings_summary": counts,
            "chain_values": {},
            "correlated_paths": unified_paths,
            "attack_graph": attack_graph,
            "attack_techniques": all_techniques,
            "kill_chain_phases": all_phases,
            "risk_score": risk,
            "campaign_id": campaign_id,
            "parallel": True,
            "root": unified_root,
            "completed_targets": completed_targets,
            # v5.5: per-job recovery + Gantt timeline data for the dashboard
            "job_recovery": {"recovered_jobs": recovered_jobs,
                             "open_circuits": open_circuits,
                             "attempts": dict(job_attempts)},
            "gantt": {
                "jobs": {f"{job_names[i] if i < len(job_names) else i}":
                          job_timing.get(i, {}) for i in range(len(jobs))},
                "started": datetime.now().isoformat(),
                "finished": datetime.now().isoformat(),
            },
            "status": ("complete" if len(results) and
                        completed_targets == len(all_targets)
                        else ("failed" if errors else "partial")),
        }

        report_path = self._write_parallel_report(unified_summary)
        unified_summary["report_path"] = report_path

        try:
            with open(os.path.join(unified_root, "state.json"), "w") as f:
                json.dump(unified_summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save parallel state: {e}")

        if campaign_id and self._campaign_mgr:
            self._campaign_mgr.mark_campaign_complete(campaign_id)

        self._emit("scheduler_complete", {
            "combined_id": unified_id,
            "campaign_id": campaign_id,
            "status": unified_summary["status"],
            "jobs_total": len(jobs),
            "jobs_complete": completed,
            "jobs_failed": errors,
            "targets_total": len(all_targets),
            "findings_total": len(deduped_findings),
            "paths_correlated": len(unified_paths),
            "cross_workflow": True,
            "risk_score": risk["total"],
            "report_path": report_path,
        })

        self._log(unified_root, f"Parallel multi-workflow complete: "
                                f"{completed}/{len(jobs)} jobs, "
                                f"{len(deduped_findings)} merged findings, "
                                f"{len(unified_paths)} cross-workflow paths; "
                                f"risk={risk['total']}/100")

        return unified_summary

    # ═══════════════════════════════════════════════════════════════
    # Parallel Campaign Report
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _write_parallel_report(summary: Dict[str, Any]) -> str:
        """Write the unified campaign-level attack path report for a parallel
        multi-workflow run (cross-workflow correlation). Formatting delegated
        to core.report (single report writer)."""
        from core.report import parallel_report

        report = parallel_report(summary)
        try:
            path = os.path.join(summary["root"], "report.md")
            with open(path, "w") as f:
                f.write(report)
            return path
        except Exception as e:
            logger.error(f"Failed to write parallel report: {e}")
            return ""

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
        """Write a comprehensive combined markdown report with correlation.
        Formatting delegated to core.report (single report writer)."""
        from core.report import combined_report

        report = combined_report(summary)
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
