"""Ligolo pivot control routes (v7.2) — cockpit panel backend.

Thin REST surface over core/mech/ligolo_api.py: daemon lifecycle,
agent/session listing, tunnel start/stop, and TUN route management.
The ligolo daemon itself must be running (manager.start spawns it with
a generated argon2id credential set — see LigoloDaemonManager).
"""
_MANAGER = None  # production singleton; tests inject via ctx.ligolo_manager


def _get_manager(ctx):
    m = getattr(ctx, "ligolo_manager", None)
    if m is not None:
        return m
    global _MANAGER
    if _MANAGER is None:
        from core.mech.ligolo_api import LigoloDaemonManager
        _MANAGER = LigoloDaemonManager()
    return _MANAGER


def _ok(payload=None, **extra):
    out = {"ok": True}
    if payload:
        out.update(payload)
    out.update(extra)
    return jsonify(out)


def _err(message, status=502):
    return jsonify({"ok": False, "error": str(message)}), status


from flask import jsonify, request  # noqa: E402


def register(ctx):
    app = ctx.app

    @app.route("/api/ligolo/status", methods=["GET"])
    def ligolo_status():
        try:
            return _ok(status=_get_manager(ctx).status())
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/daemon/start", methods=["POST"])
    def ligolo_daemon_start():
        body = request.get_json(silent=True) or {}
        try:
            st = _get_manager(ctx).start(
                agent_laddr=body.get("agent_laddr", "0.0.0.0:11601"),
                api_port=int(body.get("api_port", 11602)),
            )
            return _ok(status=st)
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/daemon/stop", methods=["POST"])
    def ligolo_daemon_stop():
        try:
            return _ok(result=_get_manager(ctx).stop())
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/agents", methods=["GET"])
    def ligolo_agents():
        try:
            return _ok(agents=_get_manager(ctx).client().agents())
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/tunnel/start", methods=["POST"])
    def ligolo_tunnel_start():
        body = request.get_json(silent=True) or {}
        try:
            res = _get_manager(ctx).client().start_tunnel(
                int(body.get("agent_id", 0)),
                interface=body.get("interface", "ligolo"))
            return _ok(result=res)
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/tunnel/stop", methods=["POST"])
    def ligolo_tunnel_stop():
        body = request.get_json(silent=True) or {}
        try:
            res = _get_manager(ctx).client().stop_tunnel(
                int(body.get("agent_id", 0)))
            return _ok(result=res)
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/route", methods=["POST"])
    def ligolo_route_add():
        body = request.get_json(silent=True) or {}
        try:
            res = _get_manager(ctx).client().add_route(
                body.get("interface", "ligolo"), body.get("route"))
            return _ok(result=res)
        except Exception as e:
            return _err(e)

    @app.route("/api/ligolo/route", methods=["DELETE"])
    def ligolo_route_delete():
        body = request.get_json(silent=True) or {}
        try:
            res = _get_manager(ctx).client().delete_route(
                body.get("interface", "ligolo"), body.get("route"))
            return _ok(result=res)
        except Exception as e:
            return _err(e)
