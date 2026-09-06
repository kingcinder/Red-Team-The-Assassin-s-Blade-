import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.autonomous import AutonomousAgent, AgentState


class DummyOrchestrator:
    pass


def test_start_rejects_empty_targets_without_starting_thread():
    agent = AutonomousAgent(DummyOrchestrator())
    result = agent.start([])
    assert result == {"status": "error", "error": "at least one non-empty target is required"}
    assert agent.state == AgentState.IDLE
    assert agent._thread is None


def test_start_strips_empty_target_entries(monkeypatch):
    agent = AutonomousAgent(DummyOrchestrator())
    started = {}

    def fake_thread(*, target, daemon, name):
        started["target"] = target
        class Thread:
            def start(self):
                pass
        return Thread()

    monkeypatch.setattr("core.autonomous.threading.Thread", fake_thread)
    result = agent.start(["  host-a ", "", "   "])
    assert result["status"] == "started"
    assert result["targets"] == ["host-a"]
    assert agent._targets == ["host-a"]
