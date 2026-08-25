"""RedTeam Harness - Dashboard blueprint: Metasploit auto-exploit domain.
Generate / execute / validate / list .rc resource scripts.
"""
import os
from flask import request, jsonify


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

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
