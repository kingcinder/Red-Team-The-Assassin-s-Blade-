"""
RedTeam Harness — Dashboard Web Server v4.0
Flask + WebSocket server powering the cockpit UI.

v4.0 Assassin's Blade: streaming, plan display, autonomous toggle, token
tracking, report viewer, workflow engine, chain graph, multi-target,
findings correlation, drift metrics, template validation.
"""
import os
import re
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

from core.orchestrator import Orchestrator
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

    @socketio.on("set_autonomous")
    def handle_autonomous(data):
        """Toggle autonomous mode via WebSocket."""
        enabled = data.get("enabled", False)
        orchestrator.set_autonomous(enabled)
        emit("autonomous_changed", {"enabled": enabled})

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

    return app