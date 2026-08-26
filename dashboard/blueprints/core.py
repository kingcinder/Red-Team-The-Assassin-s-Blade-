"""RedTeam Harness - Dashboard blueprint: core domain.
General REST routes (status/tools/task/sessions/llm/autonomous/safety)
plus the general + autonomous WebSocket event handlers.
"""
from flask import render_template, request, jsonify
from flask_socketio import emit
from tools import ALL_TOOL_MODULES


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

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
    # Safety: Tool Confirmation (audit item #7)
    # ═══════════════════════════════════════════════════
    @app.route("/api/safety/confirm", methods=["POST"])
    def api_safety_confirm():
        """Approve a tool that requires human confirmation.
        The approval is single-use and cannot be forged by the LLM because it
        originates from this HTTP API, not from tool_args the model controls.
        """
        data = request.get_json()
        tool_name = data.get("tool")
        args = data.get("args", {})
        if not tool_name:
            return jsonify({"error": "No tool specified"}), 400
        orchestrator.safety.approve_tool(tool_name, args)
        return jsonify({"confirmed": True, "tool": tool_name})

    @app.route("/api/safety/policy")
    def api_safety_policy():
        """Get the current safety policy (scope, blocked, confirmations)."""
        return jsonify(orchestrator.safety.get_policy_summary())

    @app.route("/api/safety/audit")
    def api_safety_audit():
        """Get the full audit trail from the HardenedToolRunner."""
        return jsonify({"entries": orchestrator.runner.get_audit_log()})
