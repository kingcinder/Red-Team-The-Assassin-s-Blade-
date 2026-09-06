import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import harness


def test_dashboard_bind_failure_exits_nonzero(monkeypatch):
    class FailingApp:
        def run(self, **kwargs):
            raise OSError("Address already in use")

    monkeypatch.setattr("dashboard.server.create_app", lambda config: FailingApp())
    with pytest.raises(SystemExit) as exc:
        harness.run_dashboard({"harness": {"port": 9999}})
    assert exc.value.code == 1
