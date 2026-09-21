#!/usr/bin/env python3
"""No-LLM dashboard smoke test — drives the cockpit end-to-end.

Regression class this guards (found by the Omega GUI-usability audit,
2026-09-20): the dashboard is meant to be a first-class operator surface
with NO LLM running, but that path had quietly rotted —

  - nmap_scan built multi-flag scan_type as ONE argv token → every
    template-driven workflow aborted at its first gate step;
  - the socket error handler read data.message while emitters send
    data.error → operator saw "❌ Error: undefined";
  - sending a chat objective with no LLM produced a raw connection
    error instead of guidance.

Every test here runs with the LLM pointed at a closed port (connected:
False) and asserts the cockpit still serves, executes tools, runs a real
workflow through the engine, and speaks the error contract the GUI's
JavaScript expects. Uses Flask's test_client + flask_socketio's
SocketIOTestClient — no network, no external processes beyond the
harmless tools the workflows run.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))

# LLM pointed at a port nothing listens on: every test proves the cockpit
# works (or fails loudly with the right contract) while "LLM: Disconnected".
NO_LLM_CONFIG = {
    "llm": {"backend": "llama-server",
            "llama-server": {"host": "127.0.0.1", "port": 1}},
}


@pytest.fixture(scope="module")
def app():
    from dashboard.server import create_app
    return create_app(NO_LLM_CONFIG)


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


# ── 1. The cockpit page and its data endpoints serve ───────────────────

def test_cockpit_page_serves_with_llm_free_quick_starts(client):
    resp = client.get("/")
    assert resp.status_code == 200, f"GET / returned {resp.status_code}"
    html = resp.get_data(as_text=True)
    # The GUI the operator actually receives must carry the LLM-free wiring.
    assert "launchQuickWorkflow(" in html, (
        "quick-start buttons must open the workflow modal, not the LLM chat")
    assert "sendQuickPrompt(" not in html.split('class="quick-start"')[1].split("</div>")[0]
    assert 'id="llm-banner"' in html


def test_llm_status_reports_disconnected(client):
    data = client.get("/api/llm/status").get_json()
    assert data["connected"] is False, "test requires a no-LLM environment"
    assert "error" not in data


def test_gui_data_endpoints_respond(client):
    # The read endpoints the cockpit's tabs poll on load.
    for endpoint in ("/api/status", "/api/interfaces", "/api/workflows",
                     "/api/llm/status", "/api/campaigns"):
        resp = client.get(endpoint)
        assert resp.status_code == 200, f"{endpoint} returned {resp.status_code}"


# ── 2. Direct tool execution works with no LLM ──────────────────────────

def test_tool_execute_llm_free(client):
    resp = client.post("/api/tool/execute", json={"tool": "process_list", "args": {}})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["blocked"] is False, f"unexpected block: {data.get('block_reason')}"
    assert data["exit_code"] == 0
    assert data["stdout"], "expected process listing on stdout"
    # The audit block the GUI renders must come back parseable.
    audit = data["audit"]
    assert audit["tool"] == "process_list" and audit["exit_code"] == 0
    assert audit["stdout_len"] == len(data["stdout"])


def test_tool_execute_unknown_tool_refuses_cleanly(client):
    resp = client.post("/api/tool/execute", json={"tool": "definitely_not_a_tool", "args": {}})
    data = resp.get_json()
    assert data["blocked"] is True
    assert data["block_reason"] == "unknown_tool"


# ── 3. Socket error contract (the "Error: undefined" regression) ────────

def test_socket_send_task_error_uses_gui_contract(app):
    """Emitters must send {message} — the JS handler's primary field.

    cockpit.js reads data.message ?? data.error since the fix, but core.py's
    send_task path emits {message}; this pins the no-LLM objective path to a
    readable message instead of "undefined".
    """
    socketio = app.extensions["socketio"]
    client = socketio.test_client(app, flask_test_client=app.test_client())
    assert client.is_connected()

    client.get_received()  # drain the connect/status burst
    client.emit("send_task", {"prompt": "network recon of 192.0.2.1"})

    deadline = time.time() + 60
    events = []
    while time.time() < deadline:
        events = client.get_received()
        if any(e["name"] in ("task_complete", "error") for e in events):
            break
        time.sleep(0.2)
    names = [e["name"] for e in events]
    assert "task_complete" in names or "error" in names, \
        f"send_task produced no terminal event within 60s: {names}"

    for e in events:
        if e["name"] == "error":
            payload = e["args"][0]
            msg = payload.get("message") or payload.get("error")
            assert msg, f"error event without readable message: {payload}"


# ── 4. Full workflow run through the engine — no LLM ─────────────────────

def test_workflow_run_end_to_end_no_llm(client):
    """POST /api/workflows/run must execute a real template.

    Uses the Recon Scan template with multi-flag scan_type ("-sS -Pn -T4")
    — the exact shape that used to abort every GUI workflow at its first
    gate ("Scantype   not supported"). Target is loopback; the run must
    reach a terminal status without any LLM.
    """
    resp = client.post("/api/workflows/run", json={
        "workflow": "Recon Scan",
        "variables": {"target": "127.0.0.1", "ports": "1-200"},
    })
    assert resp.status_code == 200, f"workflow run returned {resp.status_code}"
    result = resp.get_json()

    if "error" in result:
        pytest.fail(f"workflow run errored: {result['error']}")

    status = result.get("status")
    steps = result.get("steps", [])
    assert status in ("completed", "partial", "failed"), \
        f"non-terminal workflow status: {status}"

    # host_discovery (ping scan on loopback) must succeed.
    host_disc = next((s for s in steps if s.get("name") == "host_discovery"), None)
    assert host_disc is not None, f"steps missing host_discovery: {result}"
    assert host_disc.get("status") == "success", \
        f"host_discovery did not succeed: {host_disc}"

    # THE regression: port_scan with scan_type "-sS -Pn -T4" must not fail
    # on argv construction (nmap "Scantype   not supported" = exit 255).
    port_scan = next((s for s in steps if s.get("name") == "port_scan"), None)
    assert port_scan is not None
    if port_scan.get("status") != "success":
        err = str(port_scan.get("error", ""))
        assert "Scantype" not in err and "not supported" not in err, (
            f"multi-flag scan_type argv regression: {err}")

    # No step may fail with an LLM connection error — workflows are LLM-free.
    for s in steps:
        err = str(s.get("error", ""))
        assert "Cannot connect to LLM" not in err and "Cannot stream" not in err, (
            f"step {s.get('name')} leaked an LLM dependency: {err}")


if __name__ == "__main__":
    # Plain-script runner parity with the rest of the suite (CI runs
    # `python3 tests/test_*.py` for files without pytest markers).
    import sys as _s
    _rc = pytest.main([__file__, "-v", "--no-header", "-x"])
    raise SystemExit(0 if _rc == 0 else 1)
