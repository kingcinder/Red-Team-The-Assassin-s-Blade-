"""RedTeam Harness - Dashboard blueprint: workflow engine domain.
Workflow REST routes, chain-graph/state/sandbox/drift routes, and the
workflow WebSocket handlers (run/multi/parallel/generate/auto/chain).
"""
import os
import re
import json
from flask import request, jsonify
from flask_socketio import emit


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

    # ═══════════════════════════════════════════════════
    # Workflow Engine Routes (v3.0)
    # ═══════════════════════════════════════════════════
    @app.route("/api/workflows")
    def api_workflows():
        """List all available workflow templates."""
        return jsonify(orchestrator.list_workflows())

    @app.route("/api/workflows/run", methods=["POST"])
    def api_workflow_run():
        """Run a workflow template with variables."""
        data = request.get_json()
        workflow_name = data.get("workflow")
        variables = data.get("variables", {})
        resume = data.get("resume", False)

        if not workflow_name:
            return jsonify({"error": "No workflow specified"}), 400

        result = orchestrator.run_workflow(workflow_name, variables, resume=resume)
        return jsonify(result)

    @app.route("/api/workflows/<workflow_name>/status")
    def api_workflow_status(workflow_name):
        """Get task status for a workflow."""
        return jsonify(orchestrator.get_workflow_status(workflow_name))

    @app.route("/api/workflows/generate", methods=["POST"])
    def api_workflow_generate():
        """LLM-generate a workflow from a natural-language objective."""
        data = request.get_json()
        objective = data.get("objective", "")
        if not objective:
            return jsonify({"error": "No objective provided"}), 400
        result = orchestrator.generate_workflow(objective)
        return jsonify(result)

    @app.route("/api/workflows/auto", methods=["POST"])
    def api_workflow_auto():
        """Auto-workflow: generate + validate + save + optionally execute."""
        data = request.get_json()
        objective = data.get("objective", "")
        if not objective:
            return jsonify({"error": "No objective provided"}), 400
        variables = data.get("variables", {})
        auto_execute = data.get("auto_execute", True)
        result = orchestrator.auto_workflow(objective, variables, auto_execute)
        return jsonify(result)

    @app.route("/api/workflows/parallel", methods=["POST"])
    def api_workflows_parallel():
        """
        v5.3: run MULTIPLE workflow jobs concurrently and merge all findings
        across workflows via correlate_cross_workflow into a unified campaign
        attack-path report. Body: {jobs: [{workflow, targets, variables}],
        campaign_id?, max_workers?}. Runs in a background thread (long task).
        """
        data = request.get_json() or {}
        jobs = data.get("jobs", [])
        if not jobs:
            return jsonify({"error": "No jobs provided"}), 400
        for j in jobs:
            if not j.get("workflow") or not j.get("targets"):
                return jsonify({"error": "Each job needs 'workflow' + 'targets'"}), 400
        campaign_id = data.get("campaign_id")

        import threading as _threading

        def _run():
            try:
                result = orchestrator.run_parallel_workflows(
                    jobs, campaign_id=campaign_id,
                    max_workers=data.get("max_workers"))
                socketio.emit("parallel_complete", {
                    "status": result.get("status", "unknown"),
                    "jobs_total": len(jobs),
                    "paths_correlated": len(result.get("correlated_paths", [])),
                    "findings_total": len(result.get("pooled_findings", [])),
                    "risk_score": result.get("risk_score", {}).get("total", 0),
                    "report_path": result.get("report_path"),
                    "campaign_id": result.get("campaign_id"),
                })
            except Exception as e:
                logger.error(f"Parallel workflows failed: {e}", exc_info=True)
                socketio.emit("parallel_complete", {
                    "status": "failed", "error": str(e), "jobs_total": len(jobs)})

        _threading.Thread(target=_run, daemon=True).start()
        return jsonify({"status": "started", "jobs": len(jobs),
                        "campaign_id": campaign_id})

    @app.route("/api/workflows/chain", methods=["POST"])
    def api_workflow_chain():
        """Chain multiple auto-generated workflows: after each completes, the
        LLM decides the next logical workflow objective from the findings."""
        data = request.get_json()
        objective = data.get("objective", "")
        if not objective:
            return jsonify({"error": "No objective provided"}), 400
        variables = data.get("variables", {})
        max_links = data.get("max_links")
        result = orchestrator.chain_workflows(objective, variables, max_links)
        return jsonify(result)

    @app.route("/api/workflows/run-multi", methods=["POST"])
    def api_workflow_run_multi():
        """Run a workflow concurrently against multiple targets."""
        data = request.get_json()
        workflow_name = data.get("workflow")
        targets = data.get("targets", [])
        variables = data.get("variables", {})
        max_concurrent = data.get("max_concurrent")

        if not workflow_name:
            return jsonify({"error": "No workflow specified"}), 400
        if not targets:
            return jsonify({"error": "No targets specified"}), 400

        result = orchestrator.run_multi_workflow(
            workflow_name, targets, variables, max_concurrent=max_concurrent)
        return jsonify(result)

    @app.route("/api/correlate", methods=["POST"])
    def api_correlate():
        """Correlate findings into attack paths with remediation."""
        data = request.get_json()
        findings = data.get("findings", [])
        return jsonify(orchestrator.correlate_findings(findings))

    @app.route("/api/workflows/<path:task_id>/correlation")
    def api_task_correlation(task_id):
        """Correlate the findings of a saved task run."""
        return jsonify(orchestrator.get_task_correlation(task_id))

    @app.route("/api/workflows/graph/<path:workflow_name>")
    def api_workflow_graph(workflow_name):
        """
        Build the chain graph for a workflow template.
        Optionally merge a task's state for live coloring: ?task_id=<id>
        """
        from core.workflow_engine import WorkflowStateMachine

        templates_dir = config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        # Resolve name → file (allow with/without extension)
        path = os.path.join(templates_dir, workflow_name)
        if not os.path.exists(path):
            path = os.path.join(templates_dir, workflow_name + ".yaml")
        if not os.path.exists(path):
            return jsonify({"error": f"Workflow not found: {workflow_name}"}), 404

        # Block path traversal
        real = os.path.realpath(path)
        if not real.startswith(os.path.realpath(templates_dir) + os.sep):
            return jsonify({"error": "Path traversal blocked"}), 403

        try:
            wf = WorkflowStateMachine(path, None, None, {})
            wf.load()
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        # Merge task state if requested
        # task_id format: <workflow_name>_<YYYYmmdd>_<HHMMSS>[_<hex4>] — workflow
        # names themselves contain underscores, so split on the trailing
        # timestamp (the optional hex suffix handles concurrent runs).
        state = {}
        task_id = request.args.get("task_id")
        if task_id:
            tasks_dir = config.get("workflow", {}).get("tasks_dir", "./tasks")
            m = re.match(r"^(.*)_(\d{8}_\d{6}(?:_[0-9a-f]{4})?)$", task_id)
            if m:
                wf_dir, ts = m.group(1), m.group(2)
                state_path = os.path.join(tasks_dir, wf_dir, ts, "state.json")
                if os.path.exists(state_path):
                    with open(state_path) as f:
                        state = json.load(f)

        graph = wf.build_graph(state)
        return jsonify(graph)

    @app.route("/api/workflows/<path:task_id>/state")
    def api_workflow_state(task_id):
        """Get the state.json for a specific task run."""
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "./tasks")
        # task_id = <workflow_name>_<YYYYmmdd>_<HHMMSS>[_<hex4>]; workflow names
        # may contain underscores, so extract the trailing timestamp portion.
        m = re.match(r"^(.*)_(\d{8}_\d{6}(?:_[0-9a-f]{4})?)$", task_id)
        if m:
            wf_dir, ts = m.group(1), m.group(2)
            state_path = os.path.join(tasks_dir, wf_dir, ts, "state.json")
            if os.path.exists(state_path):
                with open(state_path) as f:
                    return jsonify(json.load(f))
        return jsonify({"error": "Task not found"}), 404

    @app.route("/api/workflows/validate/<path:workflow_name>")
    def api_workflow_validate(workflow_name):
        """Phase 6: Mock-run validate a workflow template (regexes, structure)."""
        from core.workflow_engine import WorkflowStateMachine
        templates_dir = config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        path = os.path.join(templates_dir, workflow_name)
        if not os.path.exists(path):
            path = os.path.join(templates_dir, workflow_name + ".yaml")
        if not os.path.exists(path):
            return jsonify({"error": f"Workflow not found: {workflow_name}"}), 404
        # Block path traversal
        real = os.path.realpath(path)
        if not real.startswith(os.path.realpath(templates_dir) + os.sep):
            return jsonify({"error": "Path traversal blocked"}), 403
        result = WorkflowStateMachine.validate_template(path)
        return jsonify(result)

    @app.route("/api/workflows/validate-all")
    def api_workflow_validate_all():
        """Phase 6: Validate ALL workflow templates (drift hardening check)."""
        from core.workflow_engine import WorkflowStateMachine
        templates_dir = config.get("workflow", {}).get(
            "templates_dir", "workflows/templates")
        paths = WorkflowStateMachine.discover_templates(templates_dir)
        results = {}
        all_valid = True
        for p in paths:
            r = WorkflowStateMachine.validate_template(p)
            results[os.path.basename(p)] = r
            if not r["valid"]:
                all_valid = False
        return jsonify({"all_valid": all_valid, "count": len(results), "results": results})

    @app.route("/api/workflows/<path:task_id>/sandbox/<step_name>")
    def api_workflow_sandbox_output(task_id, step_name):
        """Get the sandbox stdout/stderr for a specific step in a task run."""
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "./tasks")
        m = re.match(r"^(.*)_(\d{8}_\d{6}(?:_[0-9a-f]{4})?)$", task_id)
        if not m:
            return jsonify({"error": "Invalid task_id"}), 400
        wf_dir, ts = m.group(1), m.group(2)
        task_root = os.path.join(tasks_dir, wf_dir, ts)
        if not os.path.isdir(task_root):
            return jsonify({"error": "Task not found"}), 404
        # Sanitize step_name to prevent path traversal
        safe_step = re.sub(r'[^a-zA-Z0-9_\-]', '', step_name)
        stdout_path = os.path.join(task_root, f"{safe_step}_stdout.txt")
        stderr_path = os.path.join(task_root, f"{safe_step}_stderr.txt")
        stdout = ""
        stderr = ""
        if os.path.exists(stdout_path):
            with open(stdout_path) as f:
                stdout = f.read()[:50000]
        if os.path.exists(stderr_path):
            with open(stderr_path) as f:
                stderr = f.read()[:10000]
        # Also check for log files
        log_path = os.path.join(task_root, "workflow.log")
        log_excerpt = ""
        if os.path.exists(log_path):
            with open(log_path) as f:
                log_content = f.read()
                # Find lines related to this step
                step_lines = [l for l in log_content.split("\n") if safe_step in l]
                log_excerpt = "\n".join(step_lines[-50:])[:5000]
        return jsonify({
            "step": safe_step,
            "stdout": stdout,
            "stderr": stderr,
            "log_excerpt": log_excerpt,
            "stdout_size": len(stdout),
            "stderr_size": len(stderr),
        })

    @app.route("/api/workflows/<path:task_id>/drift")
    def api_workflow_drift(task_id):
        """Phase 6: Get drift metrics for a completed task run."""
        from core.workflow_engine import WorkflowStateMachine
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "./tasks")
        m = re.match(r"^(.*)_(\d{8}_\d{6}(?:_[0-9a-f]{4})?)$", task_id)
        if not m:
            return jsonify({"error": "Invalid task_id"}), 400
        wf_dir, ts = m.group(1), m.group(2)
        state_path = os.path.join(tasks_dir, wf_dir, ts, "state.json")
        if not os.path.exists(state_path):
            return jsonify({"error": "Task not found"}), 404
        with open(state_path) as f:
            state = json.load(f)
        drift = WorkflowStateMachine.drift_from_state(state)
        return jsonify(drift)

    @app.route("/api/safety")
    def api_safety():
        """Return safety policy configuration."""
        sc = config.get("safety", {})
        return jsonify({
            "allowed_targets": sc.get("allowed_targets", []),
            "blocked_targets": sc.get("blocked_targets", []),
            "require_confirmation": sc.get("require_confirmation", []),
            "log_all_commands": sc.get("log_all_commands", True),
        })


    @socketio.on("run_workflow")
    def handle_workflow_run(data):
        """Run a workflow via WebSocket with real-time events."""
        workflow_name = data.get("workflow")
        variables = data.get("variables", {})
        resume = data.get("resume", False)

        if not workflow_name:
            emit("error", {"message": "No workflow specified"})
            return

        try:
            result = orchestrator.run_workflow(workflow_name, variables, resume=resume)
            emit("workflow_result", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("run_multi_workflow")
    def handle_workflow_run_multi(data):
        """Run a workflow against multiple targets concurrently."""
        workflow_name = data.get("workflow")
        targets = data.get("targets", [])
        variables = data.get("variables", {})

        if not workflow_name or not targets:
            emit("error", {"message": "Workflow and targets required"})
            return

        try:
            result = orchestrator.run_multi_workflow(workflow_name, targets, variables)
            emit("workflow_multi_result", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("run_parallel_workflows")
    def handle_run_parallel_workflows(data):
        """
        v5.3: run multiple different workflow jobs concurrently and merge all
        findings via correlate_cross_workflow into a unified campaign report.
        """
        jobs = data.get("jobs", [])
        campaign_id = data.get("campaign_id")
        if not jobs:
            emit("error", {"message": "No jobs provided"})
            return
        for j in jobs:
            if not j.get("workflow") or not j.get("targets"):
                emit("error", {"message": "Each job needs 'workflow' + 'targets'"})
                return

        import threading as _threading

        def _run():
            try:
                result = orchestrator.run_parallel_workflows(
                    jobs, campaign_id=campaign_id)
                emit("parallel_complete", {
                    "status": result.get("status", "unknown"),
                    "jobs_total": len(jobs),
                    "paths_correlated": len(result.get("correlated_paths", [])),
                    "findings_total": len(result.get("pooled_findings", [])),
                    "risk_score": result.get("risk_score", {}).get("total", 0),
                    "report_path": result.get("report_path"),
                    "campaign_id": result.get("campaign_id"),
                })
            except Exception as e:
                logger.error(f"Parallel workflows failed: {e}", exc_info=True)
                emit("parallel_complete", {"status": "failed", "error": str(e)})

        _threading.Thread(target=_run, daemon=True).start()
        emit("parallel_started", {"jobs": len(jobs)})

    @socketio.on("generate_workflow")
    def handle_workflow_generate(data):
        """LLM-generate a workflow from a natural-language objective."""
        objective = data.get("objective", "")
        if not objective:
            emit("error", {"message": "No objective provided"})
            return
        try:
            result = orchestrator.generate_workflow(objective)
            emit("workflow_generated", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("auto_workflow")
    def handle_auto_workflow(data):
        """Auto-workflow: generate + validate + save + execute."""
        objective = data.get("objective", "")
        if not objective:
            emit("error", {"message": "No objective provided"})
            return
        variables = data.get("variables", {})
        auto_execute = bool(data.get("auto_execute", True))
        try:
            result = orchestrator.auto_workflow(objective, variables, auto_execute)
            emit("auto_workflow_result", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("chain_workflow")
    def handle_chain_workflow(data):
        """Chain multiple auto-generated workflows — the LLM picks the next
        objective after each link completes."""
        objective = data.get("objective", "")
        if not objective:
            emit("error", {"message": "No objective provided"})
            return
        variables = data.get("variables", {})
        max_links = data.get("max_links")
        try:
            result = orchestrator.chain_workflows(objective, variables, max_links)
            emit("chain_workflow_result", result)
        except Exception as e:
            emit("error", {"message": str(e)})
