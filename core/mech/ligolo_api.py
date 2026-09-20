"""Ligolo-ng daemon API client + daemon lifecycle manager (v7.2).

The cockpit talks to ligolo-ng's experimental REST API (gin + JWT). The
proxy must be started with `web.enabled: true` in its config for the API
to exist; our daemon manager writes that config (generated argon2id
credentials + JWT secret) and spawns ligolo in daemon mode.

API contract (verified against ligolo-ng v0.9.1 source, cmd/proxy/app/daemon.go):
    POST   /api/auth            {Username, Password} -> {"token": jwt}
    GET    /api/v1/ping         -> {"message": "pong"}
    GET    /api/v1/agents       -> {agentID: {Name, SessionID, Interface, Running, ...}}
    POST   /api/v1/tunnel/:id   {Interface: "ligolo"}  -> tunnel starting
    DELETE /api/v1/tunnel/:id   -> tunnel stopping
    GET    /api/v1/interfaces   -> configured TUN interfaces
    POST   /api/v1/interfaces   {Interface}
    DELETE /api/v1/interfaces   {Interface}
    POST   /api/v1/routes       {Interface, Route: ["10.10.10.0/24", ...]}
    DELETE /api/v1/routes       {Interface, Route}

Auth header is the RAW JWT (no "Bearer " prefix) — ligolo's middleware
jwt.Parses the header string directly.
"""
import json
import os
import secrets
import time
from core.ligolo_process import Popen, TimeoutExpired, STDOUT, DEVNULL
import urllib.error
import urllib.request

AUTH_USER = "harness"


class LigoloAPIError(RuntimeError):
    """The ligolo daemon API returned an error (or was unreachable)."""

    def __init__(self, status, message):
        super().__init__(f"ligolo API {status}: {message}")
        self.status = status
        self.message = message


def _default_transport(method, url, body_bytes, headers, timeout):
    """Stdout-side HTTP transport; tests replace this seam."""
    req = urllib.request.Request(url, data=body_bytes, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise LigoloAPIError(0, f"unreachable: {e.reason}")


class LigoloClient:
    """Thin authenticated client for the ligolo-ng daemon REST API."""

    def __init__(self, host="127.0.0.1", port=11602,
                 username=AUTH_USER, password="", transport=None,
                 timeout=6):
        self.base = f"http://{host}:{int(port)}"
        self.username = username
        self.password = password
        self._token = None
        self._transport = transport or _default_transport
        self._timeout = timeout

    # ── transport ──
    def _call(self, method, path, body=None, auth=True):
        if auth and self._token is None:
            self.authenticate()
        headers = {"Content-Type": "application/json"}
        if auth and self._token:
            headers["Authorization"] = self._token
        data = json.dumps(body).encode() if body is not None else None
        status, raw = self._transport(method, self.base + path, data,
                                      headers, self._timeout)
        if status == 401 and auth and self._token:
            # token expired (1h JWT) — re-auth once and retry
            self.authenticate()
            headers["Authorization"] = self._token
            status, raw = self._transport(method, self.base + path, data,
                                          headers, self._timeout)
        if status >= 400:
            try:
                msg = json.loads(raw.decode()).get("error", raw.decode()[:120])
            except Exception:
                msg = raw.decode(errors="replace")[:120]
            raise LigoloAPIError(status, msg)
        if not raw:
            return None
        return json.loads(raw.decode())

    # ── auth ──
    def authenticate(self):
        payload = self._call("POST", "/api/auth",
                             {"Username": self.username,
                              "Password": self.password}, auth=False)
        if not payload or "token" not in payload:
            raise LigoloAPIError(500, "auth response missing token")
        self._token = payload["token"]
        return self._token

    # ── API surface ──
    def ping(self):
        return self._call("GET", "/api/v1/ping")

    def agents(self):
        """map[agentID] -> {Name, SessionID, Interface, Running, ...}"""
        return self._call("GET", "/api/v1/agents")

    def start_tunnel(self, agent_id, interface="ligolo"):
        return self._call("POST", f"/api/v1/tunnel/{int(agent_id)}",
                          {"Interface": interface})

    def stop_tunnel(self, agent_id):
        return self._call("DELETE", f"/api/v1/tunnel/{int(agent_id)}")

    def interfaces(self):
        return self._call("GET", "/api/v1/interfaces")

    def create_interface(self, name):
        return self._call("POST", "/api/v1/interfaces", {"Interface": name})

    def delete_interface(self, name):
        return self._call("DELETE", "/api/v1/interfaces", {"Interface": name})

    def add_route(self, interface, routes):
        if isinstance(routes, str):
            routes = [routes]
        return self._call("POST", "/api/v1/routes",
                          {"Interface": interface, "Route": routes})

    def delete_route(self, interface, route):
        return self._call("DELETE", "/api/v1/routes",
                          {"Interface": interface, "Route": route})


def _argon2_hash(password: str) -> str:
    """PHC hash compatible with ligolo's argon2id decoder."""
    from argon2 import PasswordHasher
    ph = PasswordHasher(time_cost=3, memory_cost=32768, parallelism=4)
    return ph.hash(password)


class LigoloDaemonManager:
    """Writes ligolo's config, spawns the daemon, owns its credentials.

    State lives in <state_dir>/daemon.json; the generated credentials are
    the only copy (the config file carries the argon2 hash, never the
    plaintext password — the password itself stays in the state file so
    the cockpit can re-authenticate).
    """

    def __init__(self, state_dir=None):
        base = state_dir or os.path.expanduser(
            "~/.local/state/redteam-harness/ligolo")
        self.state_dir = base
        os.makedirs(self.state_dir, exist_ok=True)
        self._proc = None

    # ── paths ──
    def _state_path(self):
        return os.path.join(self.state_dir, "daemon.json")

    def _config_path(self):
        return os.path.join(self.state_dir, "ligolo-ng.yaml")

    def _log_path(self):
        return os.path.join(self.state_dir, "daemon.log")

    # ── state ──
    def _load_state(self):
        path = self._state_path()
        if not os.path.exists(path):
            return None
        with open(path) as fh:
            return json.load(fh)

    def _save_state(self, state):
        with open(self._state_path(), "w") as fh:
            json.dump(state, fh, indent=1)

    def _clear_state(self):
        if os.path.exists(self._state_path()):
            os.remove(self._state_path())

    def _pid_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    # ── lifecycle ──
    def status(self):
        """{running, pid, laddr, api, agents?} — never raises."""
        state = self._load_state()
        if not state:
            return {"running": False}
        running = self._pid_alive(state.get("pid", -1))
        out = {"running": running, "pid": state.get("pid"),
               "agent_laddr": state.get("agent_laddr"),
               "api": f"{state.get('api_host')}:{state.get('api_port')}"}
        if running:
            try:
                out["agents"] = self.client().agents()
            except Exception as e:  # API not ready yet / daemon wedged
                out["agents_error"] = str(e)
        return out

    def client(self):
        state = self._load_state()
        if not state:
            raise LigoloAPIError(0, "daemon not started")
        return LigoloClient(host=state.get("api_host", "127.0.0.1"),
                            port=state.get("api_port", 11602),
                            username=state.get("username", AUTH_USER),
                            password=state.get("password", ""))

    def start(self, ligolo_bin="ligolo", agent_laddr="0.0.0.0:11601",
              api_host="127.0.0.1", api_port=11602, wait_secs=15):
        cur = self.status()
        if cur.get("running"):
            return {**cur, "already_running": True}
        # stale state from a dead daemon
        self._clear_state()

        password = secrets.token_urlsafe(12)
        secret = secrets.token_hex(32)
        config_body = (
            "web:\n"
            "  enabled: true\n"
            f"  listen: \"{api_host}:{int(api_port)}\"\n"
            f"  secret: \"{secret}\"\n"
            "  enableui: false\n"
            f"  users:\n"
            f"    {AUTH_USER}: \"{_argon2_hash(password)}\"\n"
        )
        with open(self._config_path(), "w") as fh:
            fh.write(config_body)

        cmd = [ligolo_bin, "--config", self._config_path(),
               "-selfcert", "-laddr", agent_laddr, "-daemon"]
        log = open(self._log_path(), "w")
        self._proc = Popen(
            cmd, cwd=self.state_dir, stdout=log, stderr=STDOUT,
            stdin=DEVNULL,
        )
        state = {
            "pid": self._proc.pid, "password": password,
            "username": AUTH_USER, "api_host": api_host,
            "api_port": int(api_port), "agent_laddr": agent_laddr,
            "config": self._config_path(),
        }
        self._save_state(state)

        # wait for the API to answer
        deadline = time.time() + wait_secs
        last_err = "timeout"
        while time.time() < deadline:
            if self._proc.poll() is not None:
                self._clear_state()
                raise LigoloAPIError(
                    0, f"daemon exited rc={self._proc.returncode} "
                       f"— see {self._log_path()}")
            try:
                self.client().ping()
                return self.status()
            except LigoloAPIError as e:
                last_err = str(e)
                time.sleep(0.5)
        self.stop()
        raise LigoloAPIError(0, f"daemon API not ready: {last_err}")

    def stop(self):
        state = self._load_state()
        stopped = False
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except TimeoutExpired:
                self._proc.kill()
            stopped = True
            self._proc = None
        elif state and self._pid_alive(state.get("pid", -1)):
            pid = state["pid"]
            os.kill(pid, 15)
            stopped = True
        self._clear_state()
        return {"stopped": stopped}
