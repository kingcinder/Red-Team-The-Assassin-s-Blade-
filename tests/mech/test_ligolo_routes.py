"""Route tests for the ligolo cockpit blueprint (v7.2).

Pins the cockpit's ligolo REST surface: daemon lifecycle, agent listing,
tunnel start/stop, and TUN route management — all behind a stub manager
injected via ctx.ligolo_manager (mirrors test_mech_routes.py's seam).
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from flask import Flask  # noqa: E402


def make_app(manager):
    from dashboard.blueprints.ligolo import register
    ctx = SimpleNamespace(app=Flask(__name__), ligolo_manager=manager)
    register(ctx)
    return ctx.app


class StubClient:
    def __init__(self):
        self.started = []
        self.stopped = []
        self.routes_added = []
        self.routes_deleted = []

    def agents(self):
        return {"1": {"Name": "agent1", "SessionID": "abc",
                      "Interface": "", "Running": False}}

    def start_tunnel(self, agent_id, interface="ligolo"):
        self.started.append((agent_id, interface))
        return {"message": "tunnel starting"}

    def stop_tunnel(self, agent_id):
        self.stopped.append(agent_id)
        return {"message": "tunnel stopping"}

    def add_route(self, interface, routes):
        self.routes_added.append((interface, routes))
        return {"message": "routes added"}

    def delete_route(self, interface, route):
        self.routes_deleted.append((interface, route))
        return {"message": "route deleted"}


class StubManager:
    def __init__(self):
        self._client = StubClient()
        self.start_calls = []
        self.stop_calls = 0

    def client(self):
        return self._client

    def status(self):
        return {"running": True, "pid": 1, "agents": self._client.agents()}

    def start(self, agent_laddr="0.0.0.0:11601", api_port=11602):
        self.start_calls.append((agent_laddr, api_port))
        return {"running": True}

    def stop(self):
        self.stop_calls += 1
        return {"stopped": True}


class TestLigoloRoutes(unittest.TestCase):
    def setUp(self):
        self.mgr = StubManager()
        self.app = make_app(self.mgr)
        self.c = self.app.test_client()

    def test_status(self):
        r = self.c.get("/api/ligolo/status")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["status"]["running"])

    def test_daemon_start_passes_tunables(self):
        r = self.c.post("/api/ligolo/daemon/start",
                        json={"agent_laddr": "0.0.0.0:11601",
                              "api_port": 11602})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(self.mgr.start_calls, [("0.0.0.0:11601", 11602)])

    def test_daemon_stop(self):
        r = self.c.post("/api/ligolo/daemon/stop")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mgr.stop_calls, 1)

    def test_agents_listing(self):
        r = self.c.get("/api/ligolo/agents")
        self.assertEqual(r.status_code, 200)
        agents = r.get_json()["agents"]
        self.assertEqual(agents["1"]["Name"], "agent1")

    def test_tunnel_start_and_stop(self):
        r = self.c.post("/api/ligolo/tunnel/start",
                        json={"agent_id": 1, "interface": "ligolo"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mgr._client.started, [(1, "ligolo")])

        r = self.c.post("/api/ligolo/tunnel/stop", json={"agent_id": 1})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mgr._client.stopped, [1])

    def test_route_add_and_delete(self):
        r = self.c.post("/api/ligolo/route",
                        json={"interface": "ligolo", "route": "10.0.0.0/24"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mgr._client.routes_added,
                         [("ligolo", "10.0.0.0/24")])

        r = self.c.delete("/api/ligolo/route",
                          json={"interface": "ligolo", "route": "10.0.0.0/24"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mgr._client.routes_deleted,
                         [("ligolo", "10.0.0.0/24")])

    def test_upstream_error_maps_to_502(self):
        class BrokenManager(StubManager):
            def client(self):
                raise RuntimeError("daemon not started")

        app = make_app(BrokenManager())
        r = app.test_client().get("/api/ligolo/agents")
        self.assertEqual(r.status_code, 502)
        body = r.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("daemon not started", body["error"])


if __name__ == "__main__":
    unittest.main()
