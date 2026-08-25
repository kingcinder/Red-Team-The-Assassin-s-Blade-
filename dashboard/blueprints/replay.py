"""RedTeam Harness - Dashboard blueprint: engagement replay domain.
List / detail / seek / export completed engagements as training data.
"""
import os
import json
from flask import request, jsonify, Response


def register(ctx):
    """Register this domain routes/handlers against the shared app context."""
    app = ctx.app
    socketio = ctx.socketio
    orchestrator = ctx.orchestrator
    campaign_mgr = ctx.campaign_mgr
    config = ctx.config
    logger = ctx.logger

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
