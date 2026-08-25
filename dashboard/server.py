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
from tools import ALL_TOOL_MODULES

logger = logging.getLogger("redteam.dashboard")


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
                campaign_mgr.update_target(cid, target, {
                    "status": status,
                    "completed_steps": data.get("completed_steps", 0),
                    "total_steps": data.get("total_steps", 0),
                    "findings": findings,
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
        # Collect all pooled findings from per-target state
        all_findings = []
        # Check if there's a combined state.json for this campaign
        tasks_dir = config.get("workflow", {}).get("tasks_dir", "tasks")
        for t_dir in os.listdir(tasks_dir) if os.path.isdir(tasks_dir) else []:
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
                            for f in state.get("pooled_findings", []):
                                all_findings.append(f)
                        except Exception:
                            pass
        if not all_findings and campaign.get("findings_total", 0) == 0:
            return jsonify({"paths": [], "findings": [], "paths_count": 0})
        return jsonify(orchestrator.correlate_findings(all_findings))

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
        # Run in background via orchestrator
        try:
            import threading as _threading
            def _run():
                try:
                    result = orchestrator.run_multi_workflow(
                        workflow, targets, variables)
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
        return jsonify({"campaign_id": campaign_id, "status": "started", "workflow": workflow, "targets": targets})

    @app.route("/api/campaigns/<campaign_id>", methods=["DELETE"])
    def api_delete_campaign(campaign_id):
        """Remove a campaign from memory."""
        result = campaign_mgr.delete_campaign(campaign_id)
        if "error" in result:
            return jsonify(result), 404
        return jsonify(result)

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

    orchestrator.on("on_autonomous_status", on_autonomous_status)
    orchestrator.on("on_autonomous_phase", on_autonomous_phase)
    orchestrator.on("on_autonomous_complete", on_autonomous_complete)
    orchestrator.on("on_autonomous_error", on_autonomous_error)
    orchestrator.on("on_autonomous_retry", on_autonomous_retry)
    orchestrator.on("on_autonomous_report", on_autonomous_report)

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

    return app