"""RedTeam Harness — Dashboard blueprint: Mech-Unit domain (v7.0 P4.1/P4.2).

Point-and-click cockpit backend: intent wall (probe-annotated), plan
compile/preview, run/pause/resume/abort, live step streaming over
SocketIO, VULN-GRAPH next moves, and the TARGETS live-scan bridge.

All runtime state lives in the MechUnit facade (core.mech); this module is
a thin HTTP/WS adapter. SocketIO channel names come from
core.mech.events.socketio_channel() — the single mapping point.
"""
import threading
import logging

from flask import request, jsonify

from core.mech import MechUnit
from core.mech import events as mech_events
from core.mech.events import socketio_channel

logger = logging.getLogger("redteam.dashboard.mech")


def register(ctx):
    """Register Mech-Unit routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    config = ctx.config

    mech_cfg = config.get("mech", {}) if isinstance(config, dict) else {}
    # Tests inject a stub unit via ctx.mech_unit; production builds the real one.
    unit = getattr(ctx, "mech_unit", None) or MechUnit(
        config=config,
        manifest_dir=mech_cfg.get("manifest_dir"),
        sandbox_root=mech_cfg.get("sandbox_root"),
        graph_path=mech_cfg.get("vuln_graph"),
    )
    # Shared executor bus → SocketIO relay. Every executor for this unit
    # subscribes its events here so the cockpit sees live steps.
    def _relay(enriched):
        socketio.emit(socketio_channel(enriched.get("event", "")), enriched)
    for event in mech_events.ALL_EVENTS:
        unit.on_event(event, _relay)

    # ═══════════════════════════════════════════════════
    # Routes — intents
    # ═══════════════════════════════════════════════════

    @app.route("/api/mech/intents")
    def api_mech_intents():
        """Cockpit card payloads for every attack intent."""
        try:
            return jsonify({"intents": unit.list_intents()})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/mech/intents/<intent_id>/probe")
    def api_mech_probe(intent_id):
        """Probe detail for one intent (intent-wall greying + reasons)."""
        try:
            return jsonify({"probes": unit.probe(intent_id)})
        except KeyError:
            return jsonify({"error": f"unknown intent '{intent_id}'"}), 404

    # ═══════════════════════════════════════════════════
    # Routes — plan lifecycle
    # ═══════════════════════════════════════════════════

    @app.route("/api/mech/plan/compile", methods=["POST"])
    def api_mech_compile():
        """Compile an intent into a previewable plan.

        Body: {intent_id, target?: {k:v}, facts?: {k:v}}
        A hard precondition failure → 403 with the probe reason + fix.
        """
        data = request.get_json(silent=True) or {}
        intent_id = data.get("intent_id", "")
        if not intent_id:
            return jsonify({"error": "intent_id is required"}), 400
        try:
            plan = unit.compile(
                intent_id,
                target=data.get("target") or {},
                facts=data.get("facts") or {},
                capture_state=getattr(orchestrator, "capture_state", None))
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404
        except PermissionError as exc:
            return jsonify({"error": str(exc), "blocked_by_probe": True}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(plan.to_dict())

    @app.route("/api/mech/plan/<plan_id>/run", methods=["POST"])
    def api_mech_run(plan_id):
        """Execute a compiled plan in a background thread (WS streams)."""
        plan = unit._plans.get(plan_id)
        if plan is None:
            return jsonify({"error": f"unknown plan '{plan_id}' — compile first"}), 404
        if not plan.runnable:
            return jsonify({
                "error": "plan has unresolved parameters",
                "unresolved": [u.to_dict() for u in plan.unresolved]}), 400
        thread = threading.Thread(
            target=unit.run, args=(plan,),
            name=f"mech-{plan_id}", daemon=True)
        thread.start()
        return jsonify({"status": "started", "plan_id": plan_id})

    @app.route("/api/mech/plan/<plan_id>/pause", methods=["POST"])
    def api_mech_pause(plan_id):
        return jsonify(unit.pause(plan_id))

    @app.route("/api/mech/plan/<plan_id>/resume", methods=["POST"])
    def api_mech_resume(plan_id):
        """Resume a persisted plan in a background thread (v7.1 fix).

        The previous handler returned resume_requested without calling
        anything — a no-op button. A plan is resumable when it is loaded in
        this session OR persisted from a previous (possibly crashed) one.
        """
        if plan_id not in unit._plans:
            try:
                unit.get_plan_report(plan_id)  # crash-recovery path
            except KeyError:
                return jsonify({"error": f"unknown plan '{plan_id}'"}), 404
        thread = threading.Thread(
            target=unit.resume, args=(plan_id,),
            name=f"mech-resume-{plan_id}", daemon=True)
        thread.start()
        return jsonify({"status": "started", "plan_id": plan_id})

    @app.route("/api/mech/plan/<plan_id>/abort", methods=["POST"])
    def api_mech_abort(plan_id):
        return jsonify(unit.abort(plan_id))

    @app.route("/api/mech/plan/<plan_id>/status")
    def api_mech_status(plan_id):
        return jsonify(unit.status(plan_id))

    @app.route("/api/mech/plan/<plan_id>")
    def api_mech_plan_detail(plan_id):
        """Full persisted compile report — cockpit reattach after refresh."""
        try:
            return jsonify(unit.get_plan_report(plan_id))
        except KeyError:
            return jsonify({"error": f"unknown plan '{plan_id}'"}), 404

    @app.route("/api/mech/plans")
    def api_mech_plans():
        """Every persisted plan run, newest first (reattach list)."""
        return jsonify({"plans": unit.list_plans()})

    @app.route("/api/mech/plan/<plan_id>/next-moves")
    def api_mech_next_moves(plan_id):
        return jsonify({"moves": unit.next_moves(plan_id)})

    # ═══════════════════════════════════════════════════
    # Routes — targets + capitalization
    # ═══════════════════════════════════════════════════

    @app.route("/api/mech/targets/scan", methods=["POST"])
    def api_mech_target_scan():
        """Live TARGETS-grid scan (wireless APs via airodump).

        Optional body: {interface?: str, duration?: int seconds}
        Deterministic: runs the scan through the hardened runner, parses
        BSSID/ESSID/channel/power/encryption/clients, persists scan hints
        to capture_state so resolvers pick them up. No LLM.
        """
        from core.mech.targets import scan_wireless
        data = request.get_json(silent=True) or {}
        result = scan_wireless(
            orchestrator,
            interface=data.get("interface"),
            duration=int(data.get("duration") or 10),
        )
        status = 200 if result.get("ok") else 503
        return jsonify(result), status

    @app.route("/api/mech/targets")
    def api_mech_targets():
        """Known targets: last wireless scan + scan hints for the grid."""
        capture_state = getattr(orchestrator, "capture_state", None)
        scan = {}
        iface = None
        if capture_state is not None:
            try:
                scan = capture_state.get_scan() or {}
                iface = capture_state.get()
            except Exception:
                pass
        return jsonify({
            "selected_interface": iface,
            "scan_hints": scan,
            "known_targets": orchestrator.config.get("mech_known_targets", []),
        })

    @app.route("/api/mech/suggest", methods=["POST"])
    def api_mech_suggest():
        """VULN-GRAPH next moves for arbitrary findings (no plan needed)."""
        data = request.get_json(silent=True) or {}
        findings = data.get("findings", [])
        return jsonify({"moves": unit.suggest_moves(findings)})
