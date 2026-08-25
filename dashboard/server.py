"""
RedTeam Harness — Dashboard Web Server v4.0
Flask + WebSocket server powering the cockpit UI.

v4.0 Assassin's Blade: streaming, plan display, autonomous toggle, token
tracking, report viewer, workflow engine, chain graph, multi-target,
findings correlation, drift metrics, template validation.
"""
import os
import re
import io
import json
import zipfile
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit

from core.orchestrator import Orchestrator
from core.campaign import CampaignManager
from core.correlation import build_attack_matrix
from tools import ALL_TOOL_MODULES

logger = logging.getLogger("redteam.dashboard")


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


def create_app(config=None):
    if config is None:
        config = {}

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.config["SECRET_KEY"] = "redteam-harness-secret"

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    orchestrator = Orchestrator(config)
    campaign_mgr = CampaignManager(
        tasks_dir=config.get("workflow", {}).get("tasks_dir", "tasks"))
    # Wire campaign manager into the multi-target scheduler
    orchestrator.scheduler._campaign_mgr = campaign_mgr

    # ═══════════════════════════════════════════════════
    # Campaign Event Forwarding → WebSocket
    # ═══════════════════════════════════════════════════
    def on_workflow_start_campaign(data):
        """Track workflow starts in active campaigns — thread-safe."""
        target = data.get("target", "unknown")
        for camp_summary in campaign_mgr.list_campaigns():
            cid = camp_summary["id"]
            camp = campaign_mgr.get_campaign(cid)
            if "error" in camp:
                continue
            if target in camp.get("targets", []) and camp["status"] == "running":
                campaign_mgr.mark_target_started(cid, target)
                socketio.emit("campaign_target_update", {
                    "campaign_id": cid,
                    "target": target,
                    "data": {"status": "running"},
                })

    def on_workflow_complete_campaign(data):
        """Track workflow completions in active campaigns — thread-safe."""
        target = data.get("target", "unknown")
        for camp_summary in campaign_mgr.list_campaigns():
            cid = camp_summary["id"]
            camp = campaign_mgr.get_campaign(cid)
            if "error" in camp:
                continue
            if target in camp.get("targets", []) and camp["status"] in ("running", "created"):
                status = data.get("status", "unknown")
                findings = data.get("findings", []) or data.get("pooled_findings", [])
                # NOTE: findings are intentionally NOT passed to update_target here —
                # the scheduler's run_one() already records them via its direct
                # campaign_mgr.update_target call (and covers standalone CLI use).
                # Passing them again would DOUBLE-COUNT severity counters, the
                # heatmap grid, and the cumulative risk score.
                campaign_mgr.update_target(cid, target, {
                    "status": status,
                    "completed_steps": data.get("completed_steps", 0),
                    "total_steps": data.get("total_steps", 0),
                    "error": data.get("error"),
                })
                steps = data.get("steps", [])
                drift_scores = [s.get("drift_score", 0) for s in steps if s.get("drift_score")]
                if drift_scores:
                    avg_drift = sum(drift_scores) / len(drift_scores)
                    campaign_mgr.update_target(cid, target, {"drift_score": avg_drift})
                socketio.emit("campaign_target_update", {
                    "campaign_id": cid,
                    "target": target,
                    "data": {
                        "status": status,
                        "progress": data.get("completed_steps", 0),
                        "total": data.get("total_steps", 0),
                        "findings_count": len(findings),
                    },
                })
                camp = campaign_mgr.get_campaign(cid)
                if "error" not in camp:
                    socketio.emit("campaign_update", {
                        "campaign_id": cid,
                        "risk_score": camp.get("risk_score", 0),
                        "completed": camp.get("completed_targets", 0),
                        "total": len(camp.get("targets", [])),
                        "findings_total": camp.get("findings_total", 0),
                    })

    orchestrator.on("on_workflow_start", on_workflow_start_campaign)
    orchestrator.on("on_workflow_complete", on_workflow_complete_campaign)

    def on_multi_target_progress(data):
        """Forward per-target live progress (target started/completed, step
        counts, findings counts) from the multi-target scheduler straight to
        the campaign dashboard. The scheduler includes campaign_id in the
        payload so the JS can match it against the active campaign."""
        socketio.emit("multi_target_progress", data)

    orchestrator.on("multi_target_progress", on_multi_target_progress)

    # ═══════════════════════════════════════════════════
    # Event forwarding to WebSocket
    # ═══════════════════════════════════════════════════
    def on_tool_start(data):
        socketio.emit("tool_start", data)
    def on_tool_complete(data):
        socketio.emit("tool_complete", data)
    def on_llm_thinking(data):
        socketio.emit("llm_thinking", data)
    def on_llm_response(data):
        socketio.emit("llm_response", data)
    def on_llm_chunk(data):
        socketio.emit("llm_chunk", data)
    def on_error(data):
        socketio.emit("error", data)
    def on_plan_generated(data):
        socketio.emit("plan_generated", data)
    def on_report_generated(data):
        socketio.emit("report_generated", data)

    def on_workflow_start(data):
        socketio.emit("workflow_start", data)
    def on_workflow_complete(data):
        socketio.emit("workflow_complete", data)

    orchestrator.on("on_tool_start", on_tool_start)
    orchestrator.on("on_tool_complete", on_tool_complete)
    orchestrator.on("on_llm_thinking", on_llm_thinking)
    orchestrator.on("on_llm_response", on_llm_response)
    orchestrator.on("on_llm_chunk", on_llm_chunk)
    orchestrator.on("on_error", on_error)
    orchestrator.on("on_plan_generated", on_plan_generated)
    orchestrator.on("on_report_generated", on_report_generated)
    orchestrator.on("on_workflow_start", on_workflow_start)
    orchestrator.on("on_workflow_complete", on_workflow_complete)

    # ═══════════════════════════════════════════════════
    # Routes
    # ═══════════════════════════════════════════════════
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status")
    def api_status():
        return jsonify(orchestrator.get_status())

    @app.route("/api/cache/stats")
    def api_cache_stats():
        """Phase 2: Result cache statistics."""
        return jsonify(orchestrator.runner.cache.get_stats())

    @app.route("/api/cache/clear", methods=["POST"])
    def api_cache_clear():
        """Phase 2: Clear the result cache."""
        orchestrator.runner.cache.clear()
        return jsonify({"cleared": True})

    @app.route("/api/tactics/suggest", methods=["POST"])
    def api_tactics_suggest():
        """Phase 5: Get tactical suggestions from findings."""
        data = request.get_json()
        findings = data.get("findings", [])
        context = data.get("context", {})
        suggestions = orchestrator.tactics.evaluate(findings, context)
        return jsonify({"suggestions": suggestions})

    @app.route("/api/tools")
    def api_tools():
        tools_data = {}
        for name, tool in orchestrator.tools.get_all_tools().items():
            cat = tool.category
            if cat not in tools_data:
                tools_data[cat] = []
            tools_data[cat].append(tool.to_dict())
        return jsonify(tools_data)

    @app.route("/api/tools/installed")
    def api_tools_installed():
        return jsonify([t.to_dict() for t in orchestrator.tools.get_installed_tools()])

    @app.route("/api/tools/quick-commands")
    def api_quick_commands():
        commands = []
        for module_class in ALL_TOOL_MODULES:
            module = module_class(orchestrator.tools)
            commands.extend(module.get_quick_commands())
        return jsonify(commands)

    @app.route("/api/tools/attack-chains")
    def api_attack_chains():
        chains = []
        for module_class in ALL_TOOL_MODULES:
            module = module_class(orchestrator.tools)
            chains.extend(module.get_preset_attack_chains())
        return jsonify(chains)

    @app.route("/api/task", methods=["POST"])
    def api_task():
        """Process a pentest task through the LLM."""
        data = request.get_json()
        prompt = data.get("prompt", "")
        if not prompt:
            return jsonify({"error": "No prompt provided"}), 400

        session_id = data.get("session_id")
        skip_plan = data.get("skip_plan", False)
        stream = data.get("stream", False)

        result = orchestrator.process_prompt(prompt, session_id,
                                              skip_plan=skip_plan, stream=stream)
        return jsonify(result)

    @app.route("/api/tool/execute", methods=["POST"])
    def api_execute_tool():
        """Execute a tool directly."""
        data = request.get_json()
        tool_name = data.get("tool")
        args = data.get("args", {})
        session_id = data.get("session_id")

        if not tool_name:
            return jsonify({"error": "No tool specified"}), 400

        result = orchestrator.execute_direct(tool_name, args, session_id)
        return jsonify(result)

    @app.route("/api/sessions")
    def api_sessions():
        return jsonify(orchestrator.sessions.list_sessions())

    @app.route("/api/sessions/<session_id>")
    def api_session_detail(session_id):
        return jsonify(orchestrator.sessions.get_summary(session_id))

    @app.route("/api/sessions/<session_id>/messages")
    def api_session_messages(session_id):
        """Get full message history for a session."""
        return jsonify(orchestrator.sessions.get_messages(session_id))

    @app.route("/api/prioritize", methods=["POST"])
    def api_prioritize():
        """Phase 7: Prioritize targets by attackability score."""
        data = request.get_json()
        targets_data = data.get("targets", [])
        findings = data.get("findings", [])
        return jsonify(orchestrator.prioritize_targets(targets_data, findings))

    @app.route("/api/llm/status")
    def api_llm_status():
        return jsonify(orchestrator.llm.get_status())

    @app.route("/api/llm/test", methods=["POST"])
    def api_llm_test():
        connected = orchestrator.llm.is_connected()
        return jsonify({"connected": connected})

    @app.route("/api/autonomous", methods=["POST"])
    def api_autonomous():
        """Enable or disable autonomous mode."""
        data = request.get_json()
        enabled = data.get("enabled", False)
        orchestrator.set_autonomous(enabled)
        return jsonify({"autonomous": enabled})

    # ═══════════════════════════════════════════════════
    # Autonomous Engagement Routes
    # ═══════════════════════════════════════════════════
    @app.route("/api/autonomous/start", methods=["POST"])
    def api_autonomous_start():
        """Start a continuous autonomous engagement."""
        data = request.get_json()
        targets = data.get("targets", [])
        objective = data.get("objective", "Full penetration test")
        if not targets:
            return jsonify({"error": "No targets provided"}), 400
        result = orchestrator.start_autonomous_engagement(targets, objective)
        return jsonify(result)

    @app.route("/api/autonomous/stop", methods=["POST"])
    def api_autonomous_stop():
        """Stop the running autonomous engagement."""
        result = orchestrator.stop_autonomous_engagement()
        return jsonify(result)

    @app.route("/api/autonomous/pause", methods=["POST"])
    def api_autonomous_pause():
        """Pause the running autonomous engagement."""
        result = orchestrator.pause_autonomous_engagement()
        return jsonify(result)

    @app.route("/api/autonomous/resume", methods=["POST"])
    def api_autonomous_resume():
        """Resume a paused autonomous engagement."""
        result = orchestrator.resume_autonomous_engagement()
        return jsonify(result)

    @app.route("/api/autonomous/status")
    def api_autonomous_status():
        """Get the status of the autonomous engagement."""
        return jsonify(orchestrator.get_autonomous_status())

    @app.route("/api/autonomous/mission-control")
    def api_autonomous_mission_control():
        """Get the full Mission Control payload: per-target kill-chain progress
        bars, finding severity histograms, retry escalations, phase timeline."""
        return jsonify(orchestrator.get_autonomous_mission_control())

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
        from core.task_isolation import TaskSandbox

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
        from core.task_isolation import TaskSandbox
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
        from core.task_isolation import TaskSandbox
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

    # ═══════════════════════════════════════════════════
    # Metasploit Auto-Exploit Routes
    # ═══════════════════════════════════════════════════
    @app.route("/api/msf/generate", methods=["POST"])
    def api_msf_generate():
        """Generate a Metasploit .rc script from nmap output."""
        from core.msf_generator import MetasploitScriptGenerator
        data = request.get_json()
        nmap_output = data.get("nmap_output", "")
        if not nmap_output:
            return jsonify({"error": "No nmap output provided"}), 400
        msf = MetasploitScriptGenerator(
            llm=orchestrator.llm, tools=orchestrator.tools, config=config)
        lhost = data.get("lhost", "0.0.0.0")
        lport = data.get("lport", 4444)
        payload = data.get("payload", "")
        objective = data.get("objective", "")
        result = msf.auto_exploit(nmap_output, lhost, lport, payload, objective, execute=False)
        return jsonify(result)

    @app.route("/api/msf/execute", methods=["POST"])
    def api_msf_execute():
        """Execute a saved .rc script via msfconsole."""
        from core.msf_generator import MetasploitScriptGenerator
        data = request.get_json()
        rc_path = data.get("rc_path", "")
        if not rc_path or not os.path.exists(rc_path):
            return jsonify({"error": "RC script not found"}), 404
        msf = MetasploitScriptGenerator(config=config)
        timeout = data.get("timeout", 600)
        result = msf.execute_rc_script(rc_path, timeout)
        return jsonify(result)

    @app.route("/api/msf/validate", methods=["POST"])
    def api_msf_validate():
        """Validate an .rc script for correctness."""
        from core.msf_generator import MetasploitScriptGenerator
        data = request.get_json()
        rc_content = data.get("rc_content", "")
        if not rc_content:
            return jsonify({"error": "No RC content provided"}), 400
        msf = MetasploitScriptGenerator(config=config)
        is_valid, warnings = msf.validate_rc_script(rc_content)
        return jsonify({"valid": is_valid, "warnings": warnings})

    @app.route("/api/msf/list")
    def api_msf_list():
        """List all generated .rc scripts."""
        from core.msf_generator import MetasploitScriptGenerator
        msf = MetasploitScriptGenerator(config=config)
        scripts = []
        if os.path.isdir(msf.rc_dir):
            for f in sorted(os.listdir(msf.rc_dir)):
                if f.endswith(".rc"):
                    path = os.path.join(msf.rc_dir, f)
                    size = os.path.getsize(path)
                    scripts.append({"name": f, "path": path, "size": size})
        return jsonify(scripts)

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

    # ═══════════════════════════════════════════════════
    # Engagement Replay Routes (v4.2)
    # ═══════════════════════════════════════════════════
    @app.route("/api/replay/list")
    def api_replay_list():
        """List all replayable engagements (sessions + campaign bundles)."""
        from core.replay import EngagementReplay  # noqa: F401 (validation)
        session_dir = config.get("harness", {}).get("session_dir", "./sessions")
        replay_dir = os.path.join(session_dir, "replays")
        entries = []
        for src_dir, kind in ((replay_dir, "campaign"), (session_dir, "session")):
            if not os.path.isdir(src_dir):
                continue
            for fn in sorted(os.listdir(src_dir), reverse=True):
                if not fn.endswith(".json") or fn in ("tool_scores.json",):
                    continue
                path = os.path.join(src_dir, fn)
                try:
                    with open(path) as f:
                        data = json.load(f)
                    if data.get("type") == "autonomous_campaign":
                        entries.append({
                            "id": fn.replace(".json", ""),
                            "kind": "campaign",
                            "path": path,
                            "objective": data.get("objective", ""),
                            "targets": data.get("targets_count", 0),
                            "findings": data.get("total_findings", 0),
                            "state": data.get("state", ""),
                            "start": data.get("start_time", ""),
                            "end": data.get("end_time", ""),
                        })
                    else:
                        entries.append({
                            "id": fn.replace(".json", ""),
                            "kind": "session",
                            "path": path,
                            "name": data.get("name", ""),
                            "messages": len(data.get("messages", [])),
                            "tool_executions": len(data.get("tool_log", [])),
                            "findings": len(data.get("findings", [])),
                            "created": data.get("created", ""),
                        })
                except Exception:
                    continue
        return jsonify(entries)

    @app.route("/api/replay/<path:replay_id>")
    def api_replay_detail(replay_id):
        """Load a replay and return the full timeline + analysis."""
        from core.replay import EngagementReplay
        session_dir = config.get("harness", {}).get("session_dir", "./sessions")
        replay_dir = os.path.join(session_dir, "replays")
        # Block path traversal
        safe_id = os.path.basename(replay_id)
        candidates = [
            os.path.join(replay_dir, f"{safe_id}.json"),
            os.path.join(session_dir, f"{safe_id}.json"),
        ]
        path = next((c for c in candidates if os.path.exists(c)), None)
        if not path:
            return jsonify({"error": "Replay not found"}), 404
        try:
            replay = EngagementReplay.from_file(path)
        except Exception as e:
            return jsonify({"error": f"Failed to load replay: {e}"}), 500
        return jsonify(replay.to_dict())

    @app.route("/api/replay/<path:replay_id>/step/<int:index>")
    def api_replay_step(replay_id, index):
        """Seek to a specific event index in a replay."""
        from core.replay import EngagementReplay
        session_dir = config.get("harness", {}).get("session_dir", "./sessions")
        replay_dir = os.path.join(session_dir, "replays")
        safe_id = os.path.basename(replay_id)
        candidates = [
            os.path.join(replay_dir, f"{safe_id}.json"),
            os.path.join(session_dir, f"{safe_id}.json"),
        ]
        path = next((c for c in candidates if os.path.exists(c)), None)
        if not path:
            return jsonify({"error": "Replay not found"}), 404
        try:
            replay = EngagementReplay.from_file(path)
        except Exception as e:
            return jsonify({"error": f"Failed to load replay: {e}"}), 500
        ev = replay.seek(index)
        if ev is None:
            return jsonify({"error": "Index out of range"}), 404
        return jsonify({"event": ev.to_dict(), "position": replay.position,
                        "total": replay.event_count,
                        "analysis": replay.analyze()})

    @app.route("/api/replay/<path:replay_id>/export")
    def api_replay_export(replay_id):
        """Export a replay as training data (JSONL download)."""
        from core.replay import EngagementReplay
        session_dir = config.get("harness", {}).get("session_dir", "./sessions")
        replay_dir = os.path.join(session_dir, "replays")
        safe_id = os.path.basename(replay_id)
        candidates = [
            os.path.join(replay_dir, f"{safe_id}.json"),
            os.path.join(session_dir, f"{safe_id}.json"),
        ]
        path = next((c for c in candidates if os.path.exists(c)), None)
        if not path:
            return jsonify({"error": "Replay not found"}), 404
        fmt = request.args.get("format", "jsonl")
        try:
            replay = EngagementReplay.from_file(path)
            records = replay.export_training(format=fmt)
        except Exception as e:
            return jsonify({"error": f"Export failed: {e}"}), 500
        body = "\n".join(json.dumps(r) for r in records)
        return Response(body, mimetype="application/x-ndjson",
                        headers={"Content-Disposition":
                                 f"attachment; filename={safe_id}_training.jsonl"})

    # ═══════════════════════════════════════════════════
    # Vector Memory / RAG Routes
    # ═══════════════════════════════════════════════════
    @app.route("/api/memory/stats")
    def api_memory_stats():
        """Get vector memory statistics."""
        return jsonify(orchestrator.memory.get_stats())

    @app.route("/api/memory/targets")
    def api_memory_targets():
        """List all targets stored in vector memory."""
        return jsonify(orchestrator.memory.list_targets())

    @app.route("/api/memory/query", methods=["POST"])
    def api_memory_query():
        """Search vector memory by text similarity."""
        data = request.get_json()
        query_text = data.get("query", "")
        if not query_text:
            return jsonify({"error": "No query provided"}), 400
        top_k = data.get("top_k", 10)
        target_filter = data.get("target", "")
        results = orchestrator.memory.query(query_text, top_k=top_k,
                                           target_filter=target_filter)
        return jsonify({"results": results, "count": len(results)})

    @app.route("/api/memory/target/<target>")
    def api_memory_target_findings(target):
        """Get all past findings for a specific target."""
        results = orchestrator.memory.query_by_target(target)
        context = orchestrator.memory.get_context_block(target)
        return jsonify({"target": target, "findings": results,
                        "count": len(results), "context_block": context})

    @app.route("/api/memory/export")
    def api_memory_export():
        """Export vector memory as a portable .zip bundle."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            mem_dir = orchestrator.memory._memory_dir
            for fname in ['index.json', 'vocab.json']:
                fpath = os.path.join(mem_dir, fname)
                if os.path.exists(fpath):
                    zf.write(fpath, fname)
            vectors_path = os.path.join(mem_dir, 'vectors.npy')
            if os.path.exists(vectors_path):
                zf.write(vectors_path, 'vectors.npy')
            zf.writestr('stats.json', json.dumps(orchestrator.memory.get_stats()))
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype='application/zip',
            headers={'Content-Disposition':
                     'attachment; filename=redteam_memory_export.zip'})

    @app.route("/api/memory/import", methods=["POST"])
    def api_memory_import():
        """Import vector memory from an uploaded .zip bundle."""
        f = request.files.get('file')
        if not f:
            return jsonify({"error": "No file uploaded"}), 400
        try:
            data = f.read()
            zf = zipfile.ZipFile(io.BytesIO(data))
            mem_dir = orchestrator.memory._memory_dir
            imported = 0
            for name in zf.namelist():
                if name in ('index.json', 'vocab.json', 'vectors.npy'):
                    zf.extract(name, mem_dir)
                    imported += 1
            if imported > 0:
                orchestrator.memory._load()
                return jsonify({"imported": imported,
                                "stats": orchestrator.memory.get_stats()})
            return jsonify({"error": "No valid memory files in archive"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/memory/reset", methods=["POST"])
    def api_memory_reset():
        """Clear all stored vector memory."""
        orchestrator.memory.reset()
        return jsonify({"reset": True})

    # ═══════════════════════════════════════════════════
    # Offline Knowledge Base (v5.6) — CVE / ATT&CK / exploits / remediation
    # ═══════════════════════════════════════════════════
    @app.route("/api/kb/stats")
    def api_kb_stats():
        """Get offline knowledge base statistics."""
        return jsonify(orchestrator.kb.get_stats())

    @app.route("/api/kb/search", methods=["POST"])
    def api_kb_search():
        """Search the offline KB by text (CVEs, techniques, signatures, playbooks)."""
        data = request.get_json() or {}
        query = (data.get("query") or "").strip()
        if not query:
            return jsonify({"error": "No query provided"}), 400
        top_k = min(int(data.get("top_k", 8)), 50)
        results = orchestrator.kb.search(query, top_k=top_k)
        return jsonify({"results": results, "count": len(results), "query": query})

    @app.route("/api/kb/cve/<cve_id>")
    def api_kb_cve(cve_id):
        """Look up a single CVE in the offline database."""
        entry = orchestrator.kb.lookup_cve(cve_id.upper())
        if not entry:
            return jsonify({"error": f"CVE {cve_id} not in offline database"}), 404
        entry["remediation"] = orchestrator.kb.remediation_for(cve_id.upper())
        return jsonify(entry)

    @app.route("/api/kb/technique/<tech_id>")
    def api_kb_technique(tech_id):
        """Look up a single MITRE ATT&CK technique."""
        entry = orchestrator.kb.lookup_technique(tech_id.upper())
        if not entry:
            return jsonify({"error": f"Technique {tech_id} not in offline database"}), 404
        return jsonify(entry)

    @app.route("/api/kb/ground", methods=["POST"])
    def api_kb_ground():
        """Ground a finding/scan text against the KB — returns matched
        CVEs, techniques, signatures and remediation for the given text."""
        data = request.get_json() or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"error": "No text provided"}), 400
        sigs = orchestrator.kb.signature_match(text)
        top = orchestrator.kb.search(text, top_k=4)
        return jsonify({"signatures": sigs,
                        "related": top,
                        "text_preview": text[:400]})

    # ═══════════════════════════════════════════════════
    # WebSocket Events
    # ═══════════════════════════════════════════════════
    @socketio.on("connect")
    def handle_connect():
        logger.info("Client connected")
        emit("status", orchestrator.get_status())

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.info("Client disconnected")

    @socketio.on("send_task")
    def handle_task(data):
        """Handle real-time task execution via WebSocket."""
        prompt = data.get("prompt", "")
        session_id = data.get("session_id")

        if not prompt:
            emit("error", {"message": "No prompt provided"})
            return

        try:
            result = orchestrator.process_prompt(prompt, session_id, stream=True)
            emit("task_complete", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("execute_tool")
    def handle_tool_execute(data):
        """Handle direct tool execution via WebSocket."""
        tool_name = data.get("tool")
        args = data.get("args", {})
        session_id = data.get("session_id")

        try:
            result = orchestrator.execute_direct(tool_name, args, session_id)
            emit("tool_result", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("execute_tactical")
    def handle_tactical_execute(data):
        """Execute a tactical suggestion with one click."""
        tool_name = data.get("tool")
        args = data.get("args", {})
        session_id = data.get("session_id")

        if not tool_name:
            emit("error", {"message": "No tool specified in tactical suggestion"})
            return

        try:
            result = orchestrator.execute_direct(tool_name, args, session_id)
            emit("tactical_result", {
                "tool": tool_name,
                "args": args,
                "result": result,
                "auto": True,
            })
        except Exception as e:
            emit("error", {"message": f"Tactical execution failed: {e}"})

    @socketio.on("set_autonomous")
    def handle_autonomous(data):
        """Toggle autonomous mode via WebSocket."""
        enabled = data.get("enabled", False)
        orchestrator.set_autonomous(enabled)
        emit("autonomous_changed", {"enabled": enabled})

    # ═══════════════════════════════════════════════════
    # Autonomous Engagement WebSocket Events
    # ═══════════════════════════════════════════════════
    @socketio.on("autonomous_start")
    def handle_autonomous_start(data):
        """Start a continuous autonomous engagement via WebSocket."""
        targets = data.get("targets", [])
        objective = data.get("objective", "Full penetration test")
        if not targets:
            emit("error", {"message": "No targets provided"})
            return
        try:
            result = orchestrator.start_autonomous_engagement(targets, objective)
            emit("autonomous_started", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("autonomous_stop")
    def handle_autonomous_stop():
        """Stop the running autonomous engagement."""
        try:
            result = orchestrator.stop_autonomous_engagement()
            emit("autonomous_stopped", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("autonomous_pause")
    def handle_autonomous_pause():
        """Pause the running autonomous engagement."""
        try:
            result = orchestrator.pause_autonomous_engagement()
            emit("autonomous_paused", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("autonomous_resume")
    def handle_autonomous_resume():
        """Resume a paused autonomous engagement."""
        try:
            result = orchestrator.resume_autonomous_engagement()
            emit("autonomous_resumed", result)
        except Exception as e:
            emit("error", {"message": str(e)})

    @socketio.on("autonomous_status")
    def handle_autonomous_status():
        """Get the current status of the autonomous engagement."""
        try:
            status = orchestrator.get_autonomous_status()
            emit("autonomous_status", status)
        except Exception as e:
            emit("error", {"message": str(e)})

    # ═══════════════════════════════════════════════════
    # Autonomous Event Forwarding → WebSocket
    # ═══════════════════════════════════════════════════
    def on_autonomous_status(data):
        socketio.emit("autonomous_status_update", data)
    def on_autonomous_phase(data):
        socketio.emit("autonomous_phase_update", data)
    def on_autonomous_complete(data):
        socketio.emit("autonomous_complete", data)
    def on_autonomous_error(data):
        socketio.emit("autonomous_error", data)
    def on_autonomous_retry(data):
        socketio.emit("autonomous_retry_escalation", data)
    def on_autonomous_report(data):
        socketio.emit("autonomous_report", data)
    def on_autonomous_priority(data):
        socketio.emit("autonomous_priority_update", data)
    def on_autonomous_mission(data):
        socketio.emit("autonomous_mission_control", data)

    orchestrator.on("on_autonomous_status", on_autonomous_status)
    orchestrator.on("on_autonomous_phase", on_autonomous_phase)
    orchestrator.on("on_autonomous_complete", on_autonomous_complete)
    orchestrator.on("on_autonomous_error", on_autonomous_error)
    orchestrator.on("on_autonomous_retry", on_autonomous_retry)
    orchestrator.on("on_autonomous_report", on_autonomous_report)
    orchestrator.on("on_autonomous_priority", on_autonomous_priority)
    orchestrator.on("on_mission_control", on_autonomous_mission)

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

    # ═══════════════════════════════════════════════════
    # Chain Event Forwarding → WebSocket
    # ═══════════════════════════════════════════════════
    def on_chain_start(data):
        socketio.emit("chain_start", data)
    def on_chain_link(data):
        socketio.emit("chain_link", data)
    def on_chain_complete(data):
        socketio.emit("chain_complete", data)

    orchestrator.on("on_chain_start", on_chain_start)
    orchestrator.on("on_chain_link", on_chain_link)
    orchestrator.on("on_chain_complete", on_chain_complete)

    return app