"""RedTeam Harness - Dashboard blueprint: campaign (C2) domain.
Campaign CRUD, persistence/drill-down routes, correlation graph and
ATT&CK matrix endpoints (which read combined multi_* task state).
"""
import os
import json
from flask import request, jsonify
from core.correlation import build_attack_matrix
def _collect_campaign_findings(campaign, config):

    """

    Collect every finding attached to a campaign: pooled findings from the

    scheduler's combined multi_* state.json (per-target runs) plus the raw

    retained per-target findings the CampaignManager keeps for the

    comparison view. Used by both the campaign-correlation route and the

    attack-graph endpoint so they see identical data.

    """

    all_findings = []

    tasks_dir = config.get("workflow", {}).get("tasks_dir", "tasks")

    # 1. Pooled findings from combined multi-target state files

    if os.path.isdir(tasks_dir):

        for t_dir in os.listdir(tasks_dir):

            t_path = os.path.join(tasks_dir, t_dir)

            if not os.path.isdir(t_path):

                continue

            for sub in os.listdir(t_path):

                if sub.startswith("multi_"):

                    state_path = os.path.join(t_path, sub, "state.json")

                    if os.path.exists(state_path):

                        try:

                            with open(state_path) as f:

                                state = json.load(f)

                            for fnd in state.get("pooled_findings", []):

                                all_findings.append(fnd)

                        except Exception:

                            pass

    # 2. Raw retained per-target findings (campaign comparison view)

    for target, pt in (campaign.get("per_target") or {}).items():

        for fnd in pt.get("findings", []):

            f2 = dict(fnd)

            f2.setdefault("target", target)

            all_findings.append(f2)

    return all_findings


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

    # ═══════════════════════════════════════════════════
    # C2 Campaign Dashboard Routes
    # ═══════════════════════════════════════════════════
    @app.route("/api/campaigns")
    def api_campaigns():
        """List all campaigns."""
        return jsonify(campaign_mgr.list_campaigns())

    @app.route("/api/campaigns", methods=["POST"])
    def api_create_campaign():
        """Create a new campaign."""
        data = request.get_json()
        name = data.get("name", "Unnamed Campaign")
        targets = data.get("targets", [])
        workflow = data.get("workflow", "")
        description = data.get("description", "")
        if not targets:
            return jsonify({"error": "No targets provided"}), 400
        result = campaign_mgr.create_campaign(name, targets, workflow, description)
        return jsonify(result)

    # NOTE: this route MUST be registered before /api/campaigns/<campaign_id>
    # or Flask would capture "compare" as a campaign ID.
    # NOTE: static campaign routes (history/trends) MUST be registered before
    # the dynamic /api/campaigns/<campaign_id> route so Flask doesn't capture
    # "history" / "trends" as campaign IDs.
    @app.route("/api/campaigns/history")
    def api_campaign_history():
        """List all campaigns (in-memory + persisted history on disk)."""
        campaigns_dir = config.get("campaigns", {}).get("dir", "campaigns")
        return jsonify(campaign_mgr.list_history(campaigns_dir))

    @app.route("/api/campaigns/trends")
    def api_campaign_trends():
        """Cross-campaign trends — leaderboard of persistent exposures."""
        campaigns_dir = config.get("campaigns", {}).get("dir", "campaigns")
        return jsonify(campaign_mgr.campaign_trends(campaigns_dir))

    @app.route("/api/campaigns/compare")
    def api_campaign_compare():
        """Compare two campaigns side-by-side (?a=ID&b=ID)."""
        a = request.args.get("a", "")
        b = request.args.get("b", "")
        if not a or not b:
            return jsonify({"error": "Both ?a= and ?b= campaign IDs are required"}), 400
        if a == b:
            return jsonify({"error": "Cannot compare a campaign with itself"}), 400
        result = campaign_mgr.compare_campaigns(a, b)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>")
    def api_campaign_detail(campaign_id):
        """Get full campaign state."""
        return jsonify(campaign_mgr.get_campaign(campaign_id))

    @app.route("/api/campaigns/<campaign_id>/heatmap")
    def api_campaign_heatmap(campaign_id):
        """Get findings heatmap grid for a campaign."""
        return jsonify(campaign_mgr.get_target_heatmap(campaign_id))

    @app.route("/api/campaigns/<campaign_id>/risk")
    def api_campaign_risk(campaign_id):
        """Get risk scoring breakdown for a campaign."""
        return jsonify(campaign_mgr.get_risk_summary(campaign_id))

    @app.route("/api/campaigns/<campaign_id>/correlation")
    def api_campaign_correlation(campaign_id):
        """Get correlated attack paths for a completed campaign."""
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        all_findings = _collect_campaign_findings(campaign, config)
        if not all_findings and campaign.get("findings_total", 0) == 0:
            return jsonify({"paths": [], "findings": [], "paths_count": 0})
        return jsonify(orchestrator.correlate_findings(all_findings))

    @app.route("/api/tasks/all")
    def api_all_tasks():
        """List every saved task run across workflows (attack-graph source picker).

        NOTE: multi_* directories are combined-run containers (their findings
        live in the campaign/combined state) and their directory name does not
        match the get_task_correlation task-id regex — they are excluded so the
        source picker never lists a task that would 404 when clicked.
        """
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "tasks")
        entries = []
        if os.path.isdir(tasks_dir):
            for wf in sorted(os.listdir(tasks_dir)):
                wf_path = os.path.join(tasks_dir, wf)
                if not os.path.isdir(wf_path):
                    continue
                for ts in sorted(os.listdir(wf_path), reverse=True):
                    if ts.startswith("multi_"):
                        continue
                    state_path = os.path.join(wf_path, ts, "state.json")
                    if not os.path.exists(state_path):
                        continue
                    state = {}
                    try:
                        with open(state_path) as f:
                            state = json.load(f)
                    except Exception:
                        pass
                    task_id = f"{wf}_{ts}"
                    entries.append({
                        "task_id": task_id,
                        "workflow": wf,
                        "status": state.get("status", "unknown"),
                        "findings_count": len(state.get("findings", []) or []),
                        "targets": state.get("targets", []),
                    })
        return jsonify(entries)

    @app.route("/api/correlation/graph")
    def api_correlation_graph():
        """
        v5.3: attack-graph visualization data. Accepts ?task_id=<id> or
        ?campaign_id=<id>. Returns {graph, paths, findings, paths_count} where
        graph = {nodes, edges, metadata} built by FindingCorrelator.
        """
        task_id = request.args.get("task_id", "")
        campaign_id = request.args.get("campaign_id", "")
        if not task_id and not campaign_id:
            return jsonify({"error": "Provide ?task_id= or ?campaign_id="}), 400

        if task_id:
            result = orchestrator.get_task_correlation(task_id)
        else:
            campaign = campaign_mgr.get_campaign(campaign_id)
            if "error" in campaign:
                return jsonify(campaign), 404
            all_findings = _collect_campaign_findings(campaign, config)
            if not all_findings and campaign.get("findings_total", 0) == 0:
                return jsonify({"paths": [], "findings": [], "paths_count": 0,
                                "graph": {"nodes": [], "edges": [],
                                           "metadata": {}}})
            result = orchestrator.correlate_findings(all_findings)

        if "error" in result:
            return jsonify(result), 404
        paths = result.get("paths", [])
        # The correlator attaches the SAME graph object to every path
        graph = paths[0].get("graph", {}) if paths else \
            {"nodes": [], "edges": [], "metadata": {}}
        return jsonify({
            "graph": graph,
            "paths": paths,
            "findings": result.get("findings", []),
            "paths_count": result.get("paths_count", len(paths)),
            "source": task_id or campaign_id,
        })

    @app.route("/api/attack/matrix")
    def api_attack_matrix():
        """
        v5.4: MITRE ATT&CK tactic × technique heatmap data. Accepts
        ?task_id=<id> or ?campaign_id=<id>. Returns {tactics, rows, summary,
        total_findings, total_paths, total_techniques} where each row is a
        discovered technique with worst-severity, findings, evidence, and the
        attack path titles that chain it.
        """
        task_id = request.args.get("task_id", "")
        campaign_id = request.args.get("campaign_id", "")
        if not task_id and not campaign_id:
            return jsonify({"error": "Provide ?task_id= or ?campaign_id="}), 400

        if task_id:
            result = orchestrator.get_task_correlation(task_id)
        else:
            campaign = campaign_mgr.get_campaign(campaign_id)
            if "error" in campaign:
                return jsonify(campaign), 404
            all_findings = _collect_campaign_findings(campaign, config)
            if not all_findings and campaign.get("findings_total", 0) == 0:
                return jsonify({"tactics": [], "rows": [], "summary": {},
                                "total_findings": 0, "total_paths": 0,
                                "total_techniques": 0})
            result = orchestrator.correlate_findings(all_findings)

        if "error" in result:
            return jsonify(result), 404
        paths = result.get("paths", [])
        findings = result.get("findings", []) or []
        matrix = build_attack_matrix(findings, paths)
        matrix["source"] = task_id or campaign_id
        return jsonify(matrix)

    @app.route("/api/campaigns/<campaign_id>/prioritize", methods=["POST"])
    def api_prioritize_campaign(campaign_id):
        """
        v5.2: LLM-rank the campaign's targets by exploitability BEFORE the
        scheduler runs, so high-value targets get processed first and with a
        higher retry budget. Falls back to heuristic scoring when the LLM is
        unavailable. Accepts optional body {findings: [...], targets_data: [...]}
        to feed recon context into the ranking.
        """
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        data = request.get_json() or {}
        targets = campaign.get("targets", [])
        targets_data = data.get("targets_data") or [
            {"target": t} for t in targets]
        findings = data.get("findings", [])
        # Include per-target recon findings already retained by the campaign
        for t in targets:
            pt = campaign.get("per_target", {}).get(t, {})
            for f in pt.get("findings", []):
                findings.append({
                    "target": t,
                    "severity": f.get("severity", "info"),
                    "title": f.get("title", ""),
                    "source_tool": f.get("source_tool", ""),
                })
        plan = orchestrator.auto_prioritize_targets(targets_data, findings)
        if "error" in plan:
            return jsonify(plan), 400
        # Persist the plan on the campaign so /start can consume it
        with campaign_mgr._lock:
            campaign_mgr._campaigns[campaign_id]["priority_plan"] = \
                plan.get("ordered_targets", [])
        return jsonify(plan)

    @app.route("/api/campaigns/<campaign_id>/start", methods=["POST"])
    def api_start_campaign(campaign_id):
        """Start a campaign — run the workflow against all targets."""
        data = request.get_json() or {}
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        campaign_mgr._campaigns[campaign_id]["status"] = "running"
        workflow = data.get("workflow") or campaign.get("workflow")
        if not workflow:
            return jsonify({"error": "No workflow specified"}), 400
        targets = campaign.get("targets", [])
        variables = data.get("variables", {})
        # v5.2: consume a stored priority plan (set via /prioritize) so the
        # scheduler processes high-value targets first + most aggressively.
        priority_plan = data.get("priority_plan") or \
            campaign_mgr._campaigns[campaign_id].get("priority_plan")
        # Run in background via orchestrator
        try:
            import threading as _threading
            def _run():
                try:
                    # Pass the operator's campaign_id through so the scheduler
                    # updates THIS campaign instead of auto-creating a duplicate
                    # one for the same targets.
                    result = orchestrator.run_multi_workflow(
                        workflow, targets, variables,
                        campaign_id=campaign_id,
                        priority_plan=priority_plan)
                    campaign_mgr.mark_campaign_complete(campaign_id)
                    socketio.emit("campaign_complete", {
                        "campaign_id": campaign_id,
                        "status": result.get("status", "unknown"),
                    })
                except Exception as e:
                    logger.error(f"Campaign {campaign_id} failed: {e}")
                    campaign_mgr._campaigns[campaign_id]["status"] = "failed"
                    socketio.emit("campaign_complete", {
                        "campaign_id": campaign_id,
                        "status": "failed",
                        "error": str(e),
                    })
            _threading.Thread(target=_run, daemon=True).start()
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"campaign_id": campaign_id, "status": "started", "workflow": workflow, "targets": targets, "prioritized": bool(priority_plan)})

    @app.route("/api/campaigns/<campaign_id>", methods=["DELETE"])
    def api_delete_campaign(campaign_id):
        """Remove a campaign from memory."""
        result = campaign_mgr.delete_campaign(campaign_id)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)


    # ═══════════════════════════════════════════════════════════════
    # Campaign Persistence + Drill-down Routes (v5.5)
    # ═══════════════════════════════════════════════════════════════
    @app.route("/api/campaigns/<campaign_id>/save", methods=["POST"])
    def api_campaign_save(campaign_id):
        """Persist a campaign to disk (state.json + report)."""
        campaigns_dir = config.get("campaigns", {}).get("dir", "campaigns")
        result = campaign_mgr.save_campaign(campaign_id, campaigns_dir)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>/load", methods=["POST"])
    def api_campaign_load(campaign_id):
        """Reload a persisted campaign back into memory."""
        campaigns_dir = config.get("campaigns", {}).get("dir", "campaigns")
        result = campaign_mgr.load_campaign(campaign_id, campaigns_dir)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>/snapshot", methods=["POST"])
    def api_campaign_snapshot(campaign_id):
        """Capture a mid-run snapshot of a campaign."""
        data = request.get_json() or {}
        result = campaign_mgr.snapshot_campaign(campaign_id, data.get("label", ""))
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>/diff")
    def api_campaign_diff(campaign_id):
        """Diff a snapshot against the campaign's final state."""
        snapshot_id = request.args.get("snapshot_id", "")
        result = campaign_mgr.diff_snapshot(campaign_id, snapshot_id)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>/drilldown")
    def api_campaign_drilldown(campaign_id):
        """
        Per-campaign drill-down: pull the saved multi_* task state for each
        target of a campaign and return per-target step lists with drift
        scores, findings with evidence, and start/finish timestamps.
        """
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "tasks")
        targets = campaign.get("targets", [])
        drill = {"campaign_id": campaign_id, "targets": {}}
        # Find multi_* combined runs whose campaign_id matches
        multi_roots = []
        if os.path.isdir(tasks_dir):
            for wf in os.listdir(tasks_dir):
                wf_path = os.path.join(tasks_dir, wf)
                if not os.path.isdir(wf_path):
                    continue
                for ts in os.listdir(wf_path):
                    if not ts.startswith("multi_"):
                        continue
                    state_path = os.path.join(wf_path, ts, "state.json")
                    if not os.path.exists(state_path):
                        continue
                    try:
                        with open(state_path) as f:
                            st = json.load(f)
                        if st.get("campaign_id") == campaign_id:
                            multi_roots.append({"state": st, "root":
                                                os.path.join(wf_path, ts)})
                    except Exception:
                        pass
        for t in targets:
            pt = campaign.get("per_target", {}).get(t, {})
            target_drill = {
                "target": t,
                "status": pt.get("status", "unknown"),
                "progress": pt.get("progress", 0),
                "started": pt.get("started"),
                "finished": pt.get("finished"),
                "drift_score": pt.get("drift_score", 0),
                "findings": pt.get("findings", []),
                "steps": [],
                "task_id": None,
            }
            # Match the per-target task state from the combined runs
            for mr in multi_roots:
                per_target = mr["state"].get("per_target", {})
                if t in per_target:
                    tr = per_target[t]
                    target_drill["steps"] = tr.get("steps", []) or []
                    target_drill["task_id"] = tr.get("task_id")
                    if not target_drill["started"]:
                        target_drill["started"] = tr.get("started")
                    if not target_drill["finished"]:
                        target_drill["finished"] = tr.get("finished")
                    if not target_drill["drift_score"]:
                        target_drill["drift_score"] = tr.get("drift_score", 0)
                    break
            drill["targets"][t] = target_drill
        return jsonify(drill)

    @app.route("/api/campaigns/<campaign_id>/brief", methods=["POST"])
    def api_campaign_brief(campaign_id):
        """
        LLM analyst brief for a campaign comparison: send the comparison data
        to the local model and get a 2-paragraph brief on the risk delta and
        which persistent exposures deserve immediate remediation.
        """
        data = request.get_json() or {}
        compare = data.get("compare", {})
        if not compare or "error" in compare:
            return jsonify({"error": "Provide a valid comparison payload"}), 400
        brief = orchestrator.llm_campaign_brief(compare)
        return jsonify({"brief": brief})

    @app.route("/api/campaigns/<campaign_id>/chain", methods=["POST"])
    def api_campaign_chain(campaign_id):
        """
        v5.5: live campaign auto-start flow. Runs the workflow against the
        campaign's targets, then the LLM decides the next workflow objective
        per campaign — each link tracked live in the same campaign.
        """
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        data = request.get_json() or {}
        workflow = data.get("workflow") or campaign.get("workflow")
        if not workflow:
            return jsonify({"error": "No workflow specified"}), 400
        targets = campaign.get("targets", [])
        variables = data.get("variables", {})
        max_links = data.get("max_links")
        campaign_mgr._campaigns[campaign_id]["status"] = "running"
        result = orchestrator.start_campaign_chain(
            campaign_id, workflow, targets, variables, max_links)
        return jsonify(result)

    @app.route("/api/workflows/parallel-chain", methods=["POST"])
    def api_parallel_chain():
        """
        v5.5: chained parallel waves (campaign of campaigns). After each
        multi-workflow wave completes, the unified findings feed the
        auto-prioritizer to pick the next wave's workflows/targets.
        """
        data = request.get_json() or {}
        jobs = data.get("jobs", [])
        if not jobs:
            return jsonify({"error": "No seed jobs provided"}), 400
        for j in jobs:
            if not j.get("workflow") or not j.get("targets"):
                return jsonify({"error": "Each job needs 'workflow' + 'targets'"}), 400
        max_waves = data.get("max_waves", 3)
        campaign_id = data.get("campaign_id")
        result = orchestrator.chain_parallel_waves(jobs, max_waves=max_waves,
                                                   campaign_id=campaign_id)
        return jsonify(result)

    @app.route("/api/campaigns/<campaign_id>/gantt")
    def api_campaign_gantt(campaign_id):
        """
        v5.5: Gantt-style timeline data for a campaign — per-job wall-clock
        intervals pulled from the parallel multi_* state.json files.
        """
        campaign = campaign_mgr.get_campaign(campaign_id)
        if "error" in campaign:
            return jsonify(campaign), 404
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "tasks")
        rows = []
        if os.path.isdir(tasks_dir):
            for wf in os.listdir(tasks_dir):
                wf_path = os.path.join(tasks_dir, wf)
                if not os.path.isdir(wf_path):
                    continue
                for ts in os.listdir(wf_path):
                    if not ts.startswith("multi_"):
                        continue
                    state_path = os.path.join(wf_path, ts, "state.json")
                    if not os.path.exists(state_path):
                        continue
                    try:
                        with open(state_path) as f:
                            st = json.load(f)
                        if st.get("campaign_id") != campaign_id:
                            continue
                        gantt = st.get("gantt") or {}
                        jobs = gantt.get("jobs") or {}
                        per_target = st.get("per_target") or {}
                        rows.append({
                            "run_id": st.get("combined_id"),
                            "workflow": st.get("workflow", ""),
                            "parallel": st.get("parallel", False),
                            "started": gantt.get("started") or st.get("started"),
                            "finished": gantt.get("finished") or st.get("finished"),
                            "jobs": jobs,
                            "targets": [{"target": t, "status": pt.get("status"),
                                          "started": pt.get("started"),
                                          "finished": pt.get("finished")}
                                         for t, pt in per_target.items()],
                            "report_path": st.get("report_path"),
                        })
                    except Exception:
                        continue
        rows.sort(key=lambda r: r.get("started") or "")
        return jsonify({"campaign_id": campaign_id, "runs": rows})
