"""
RedTeam Harness - Dashboard Web Server v5.7
Flask + WebSocket server powering the cockpit UI.

v5.7 architecture: request handlers live in per-domain blueprint modules
(dashboard/blueprints/). This module owns only the app assembly, the
orchestrator<->SocketIO event-forwarding glue, and blueprint registration.
"""
import os
import logging
from types import SimpleNamespace
from flask import Flask
from flask_socketio import SocketIO

from core.orchestrator import Orchestrator
from core.campaign import CampaignManager

# Re-exported for consumers/tests (defined in the campaigns blueprint).
from dashboard.blueprints.campaigns import _collect_campaign_findings  # noqa: F401

from dashboard.blueprints import (
    core as bp_core,
    workflows as bp_workflows,
    campaigns as bp_campaigns,
    msf as bp_msf,
    replay as bp_replay,
    memory_kb as bp_memory_kb,
)

logger = logging.getLogger("redteam.dashboard")

# Every blueprint exposes register(ctx) where ctx carries the shared app state.
_BLUEPRINTS = (
    bp_core,
    bp_workflows,
    bp_campaigns,
    bp_msf,
    bp_replay,
    bp_memory_kb,
)

def create_app(config=None):
    if config is None:
        config = {}

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    from dashboard.auth import get_secret_key
    app.config["SECRET_KEY"] = get_secret_key()

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

    # Shared context handed to every blueprint's register().
    ctx = SimpleNamespace(
        app=app,
        socketio=socketio,
        orchestrator=orchestrator,
        campaign_mgr=campaign_mgr,
        config=config,
        logger=logger,
    )
    for bp in _BLUEPRINTS:
        bp.register(ctx)

    return app
