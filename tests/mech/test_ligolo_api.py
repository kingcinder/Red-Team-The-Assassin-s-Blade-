"""Tests for the ligolo daemon API client + manager (v7.2).

The client's contract is pinned against ligolo-ng v0.9.1's daemon.go:
  - Authorization header carries the RAW JWT (no Bearer prefix)
  - POST /api/v1/tunnel/:id takes {"Interface": "..."}
  - 401 → single re-auth + retry (1h token expiry)
The manager must write a config with web.enabled + an argon2id hash
ligolo's decoder accepts, and own the daemon process lifecycle.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.ligolo_api import (  # noqa: E402
    LigoloAPIError,
    LigoloClient,
    LigoloDaemonManager,
)


class FakeTransport:
    """Records calls, replays scripted (status, body) responses."""

    def __init__(self, script=None):
        self.calls = []
        self.script = list(script or [])   # list of (status, body-bytes)

    def __call__(self, method, url, body_bytes, headers, timeout):
        self.calls.append({"method": method, "url": url,
                           "body": body_bytes, "headers": headers})
        if self.script:
            return self.script.pop(0)
        return 200, b"{}"


class TestLigoloClient(unittest.TestCase):
    def _client(self, transport):
        return LigoloClient(host="127.0.0.1", port=11602,
                            username="harness", password="pw",
                            transport=transport)

    def test_auth_then_raw_jwt_header(self):
        t = FakeTransport(script=[
            (200, json.dumps({"token": "jwtABC"}).encode()),
            (200, json.dumps({"message": "pong"}).encode()),
        ])
        c = self._client(t)
        self.assertEqual(c.ping(), {"message": "pong"})
        auth_call, ping_call = t.calls[0], t.calls[1]
        self.assertEqual(auth_call["url"].endswith("/api/auth"), True)
        self.assertEqual(json.loads(auth_call["body"]),
                         {"Username": "harness", "Password": "pw"})
        # RAW token — no Bearer prefix (ligolo jwt.Parses the header directly)
        self.assertEqual(ping_call["headers"]["Authorization"], "jwtABC")

    def test_401_reauth_then_retry(self):
        t = FakeTransport(script=[
            (200, json.dumps({"token": "OLD"}).encode()),   # initial auth
            (401, b'{"error": "Unauthorized"}'),            # stale token
            (200, json.dumps({"token": "NEW"}).encode()),   # re-auth
            (200, json.dumps(
                [{"Name": "agent1"}]).encode()),            # retried call
        ])
        c = self._client(t)
        c.authenticate()
        c._token = "STALE"   # force the expiry path
        agents = c.agents()
        self.assertEqual(agents, [{"Name": "agent1"}])
        self.assertEqual(t.calls[2]["url"].endswith("/api/auth"), True)
        self.assertEqual(t.calls[3]["headers"]["Authorization"], "NEW")

    def test_error_mapping(self):
        t = FakeTransport(script=[
            (200, json.dumps({"token": "jwtABC"}).encode()),
            (500, b'{"error": "invalid agent"}'),
        ])
        c = self._client(t)
        with self.assertRaises(LigoloAPIError) as ctx:
            c.agents()
        self.assertEqual(ctx.exception.status, 500)
        self.assertEqual(ctx.exception.message, "invalid agent")

    def test_tunnel_payloads(self):
        t = FakeTransport(script=[
            (200, json.dumps({"token": "jwtABC"}).encode()),
            (200, b'{"message": "tunnel starting"}'),
            (200, b'{"message": "tunnel stopping"}'),
        ])
        c = self._client(t)
        c.start_tunnel(3, interface="ligolo")
        self.assertEqual(t.calls[1]["method"], "POST")
        self.assertTrue(t.calls[1]["url"].endswith("/api/v1/tunnel/3"))
        self.assertEqual(json.loads(t.calls[1]["body"]),
                         {"Interface": "ligolo"})
        c.stop_tunnel(3)
        self.assertEqual(t.calls[2]["method"], "DELETE")
        self.assertTrue(t.calls[2]["url"].endswith("/api/v1/tunnel/3"))

    def test_route_string_coerced_to_list(self):
        t = FakeTransport(script=[
            (200, json.dumps({"token": "jwtABC"}).encode()),
            (200, b'{"message": "routes added"}'),
        ])
        c = self._client(t)
        c.add_route("ligolo", "10.10.10.0/24")
        self.assertEqual(json.loads(t.calls[1]["body"]),
                         {"Interface": "ligolo",
                          "Route": ["10.10.10.0/24"]})


class TestLigoloDaemonManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mgr = LigoloDaemonManager(state_dir=self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_start_writes_config_with_verifiable_argon2_hash(self):
        with mock.patch("core.mech.ligolo_api.Popen") as popen, \
             mock.patch.object(LigoloClient, "ping",
                               return_value={"message": "pong"}), \
             mock.patch.object(LigoloDaemonManager, "_pid_alive",
                               return_value=True):
            proc = mock.MagicMock()
            proc.pid = 424242
            proc.poll.return_value = None
            popen.return_value = proc

            st = self.mgr.start(ligolo_bin="/fake/ligolo")

        self.assertTrue(st["running"])
        self.assertEqual(st["pid"], 424242)
        # config file: web enabled on the pinned API port, argon2id user
        cfg = open(self.mgr._config_path()).read()
        self.assertIn("enabled: true", cfg)
        self.assertIn('listen: "127.0.0.1:11602"', cfg)
        self.assertIn("harness: \"", cfg)
        hash_line = [ln for ln in cfg.splitlines()
                     if ln.strip().startswith("harness:")][0]
        phc = hash_line.split('"')[1]
        self.assertTrue(phc.startswith("$argon2id$v=19$m=32768,t=3,p=4$"))
        from argon2 import PasswordHasher
        state = self.mgr._load_state()
        PasswordHasher(time_cost=3, memory_cost=32768,
                       parallelism=4).verify(phc, state["password"])
        # daemon spawned with the explicit config + agent listener
        argv = popen.call_args[0][0]
        self.assertIn("--config", argv)
        self.assertIn("-daemon", argv)
        self.assertIn("-laddr", argv)
        self.assertIn("0.0.0.0:11601", argv)
        # plaintext password lives ONLY in the state file, never the config
        self.assertNotIn(state["password"], cfg)

    def test_status_dead_pid_reports_not_running(self):
        with open(self.mgr._state_path(), "w") as fh:
            json.dump({"pid": -5, "password": "x", "username": "harness",
                       "api_host": "127.0.0.1", "api_port": 11602,
                       "agent_laddr": "0.0.0.0:11601"}, fh)
        st = self.mgr.status()
        self.assertFalse(st["running"])

    def test_stop_terminates_and_clears_state(self):
        with mock.patch("core.mech.ligolo_api.Popen") as popen, \
             mock.patch.object(LigoloClient, "ping",
                               return_value={"message": "pong"}), \
             mock.patch.object(LigoloDaemonManager, "_pid_alive",
                               return_value=True):
            proc = mock.MagicMock()
            proc.pid = 424242
            proc.poll.return_value = None
            popen.return_value = proc
            self.mgr.start(ligolo_bin="/fake/ligolo")

        out = self.mgr.stop()
        self.assertTrue(out["stopped"])
        self.assertFalse(os.path.exists(self.mgr._state_path()))
        proc.terminate.assert_called()

    def test_start_twice_reports_already_running(self):
        with mock.patch("core.mech.ligolo_api.Popen") as popen, \
             mock.patch.object(LigoloClient, "ping",
                               return_value={"message": "pong"}), \
             mock.patch.object(LigoloDaemonManager, "_pid_alive",
                               return_value=True):
            proc = mock.MagicMock()
            proc.pid = 424242
            proc.poll.return_value = None
            popen.return_value = proc
            self.mgr.start(ligolo_bin="/fake/ligolo")
            st = self.mgr.start(ligolo_bin="/fake/ligolo")
            self.assertTrue(st["already_running"])
            self.assertEqual(popen.call_count, 1)


if __name__ == "__main__":
    unittest.main()
