#!/usr/bin/env python3
"""
Regression tests for core/model_manager.swap_model() — the dashboard's
hot-swap of the loaded model in llama-server.

Covers the fixes that made hot-swap actually work:
  - the launch-script model argument is rewritten to a CONCRETE path, handling
    both `-m "$MODEL"` (the real launch-gguf.sh form) and `--model ...`,
  - readiness is polled via /v1/models before the backend reference is updated,
  - a server that never becomes ready fails cleanly with a clear error,
  - a missing/unreadable launch script falls back to _launch_direct(),
  - invalid model paths are rejected before anything is touched.

All process/network side effects are mocked — nothing is killed, launched,
or polled for real.
"""
import os
import sys
import shutil
import tempfile
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import model_manager
from core.model_manager import swap_model


TEMP_SCRIPT = "/tmp/_redteam_model_swap.sh"
FAKE_SCRIPT_M = """#!/bin/bash
exec /usr/bin/llama-server \\
  -m "$MODEL" \\
  --host 127.0.0.1 --port 8080 \\
  > /tmp/llama.log 2>&1
"""
FAKE_SCRIPT_MODEL = """#!/bin/bash
exec /usr/bin/llama-server \\
  --model "/old/path/model.gguf" \\
  --host 127.0.0.1 --port 8080 \\
  > /tmp/llama.log 2>&1
"""


class FakeResp:
    """Minimal requests.Response stand-in for the readiness poll."""
    status_code = 200

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class FakeBackend:
    def __init__(self):
        self.model = "old-model"
        self._loaded_model = None
        self.detect_calls = 0

    def _detect_loaded_model(self):
        self.detect_calls += 1

    def get_loaded_model(self):
        return self._loaded_model or self.model


def _make_cfg(port=9999):
    return {"llm": {"llama-server": {"host": "127.0.0.1", "port": port}}}


def _fake_gguf(tmp):
    """Create a (valid per _validate_model_path) empty .gguf and return path."""
    path = os.path.join(tmp, "Carnice-Test-Q4_K_M.gguf")
    open(path, "w").close()
    return path


def _emit_capture():
    events = []
    return events, lambda evt, data: events.append((evt, data.get("status")))


def _module_path_patch(tmp):
    """Redirect swap_model's harness_dir to tmp so it discovers
    tmp/launch-gguf.sh as its launch script.

    IMPORTANT: abspath must return REAL values for everything except the
    module's own __file__ — os.path.realpath() calls abspath() internally, so
    a blanket return_value would break _validate_model_path.
    """
    real_abspath = os.path.abspath
    fake_file = os.path.join(tmp, "sub", "model_manager.py")

    def _fake_abspath(p):
        if p == model_manager.__file__:
            return fake_file
        return real_abspath(p)

    return patch("core.model_manager.os.path.abspath", side_effect=_fake_abspath)


def _script_patch(tmp, script_content):
    """Create tmp/launch-gguf.sh and make swap_model discover it."""
    script = os.path.join(tmp, "launch-gguf.sh")
    with open(script, "w") as f:
        f.write(script_content)
    return _module_path_patch(tmp)


# ═══════════════════════════════════════════════════════════════
# 1. `-m "$MODEL"` form is rewritten to a concrete path
# ═══════════════════════════════════════════════════════════════
def test_swap_rewrites_m_model_arg():
    tmp = tempfile.mkdtemp(prefix="rt_swap_")
    try:
        target = _fake_gguf(tmp)
        events, emit = _emit_capture()
        backend = FakeBackend()
        popen_calls = []

        with _script_patch(tmp, FAKE_SCRIPT_M), \
             patch("core.model_manager.find_llama_server_pid", return_value=None), \
             patch("core.model_manager.subprocess.Popen",
                   side_effect=lambda *a, **k: popen_calls.append(a) or Mock(pid=123)), \
             patch("core.model_manager.requests.get",
                   return_value=FakeResp({"data": [{"id": "/fake/loaded.gguf"}]})), \
             patch("core.model_manager.time.sleep"):
            result = swap_model(target, backend, _make_cfg(), emit_fn=emit)

        assert result["success"] is True, result
        assert result["model"] == os.path.basename(target), result
        assert result["loaded_model"] == "/fake/loaded.gguf", result

        # The rewritten temp script carries the concrete path, no $MODEL
        with open(TEMP_SCRIPT) as f:
            rewritten = f.read()
        assert f'-m "{target}"' in rewritten, rewritten
        assert "$MODEL" not in rewritten, rewritten
        assert os.access(TEMP_SCRIPT, os.X_OK), "temp script must be executable"

        # Launched via bash, backend updated, complete event emitted
        assert popen_calls and popen_calls[0][0] == ["bash", TEMP_SCRIPT], popen_calls
        assert backend.model == os.path.basename(target)
        assert backend._loaded_model == "/fake/loaded.gguf"
        assert backend.detect_calls == 1, "re-detect should run after swap"
        assert ("model_swap_progress", "complete") in events, events
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.exists(TEMP_SCRIPT):
            os.remove(TEMP_SCRIPT)


# ═══════════════════════════════════════════════════════════════
# 2. `--model /path.gguf` form is rewritten too
# ═══════════════════════════════════════════════════════════════
def test_swap_rewrites_double_dash_model_arg():
    tmp = tempfile.mkdtemp(prefix="rt_swap_")
    try:
        target = _fake_gguf(tmp)
        backend = FakeBackend()
        popen_calls = []

        with _script_patch(tmp, FAKE_SCRIPT_MODEL), \
             patch("core.model_manager.find_llama_server_pid", return_value=None), \
             patch("core.model_manager.subprocess.Popen",
                   side_effect=lambda *a, **k: popen_calls.append(a) or Mock(pid=7)), \
             patch("core.model_manager.requests.get",
                   return_value=FakeResp({"data": [{"id": "x"}]})), \
             patch("core.model_manager.time.sleep"):
            result = swap_model(target, backend, _make_cfg())

        assert result["success"] is True, result
        with open(TEMP_SCRIPT) as f:
            rewritten = f.read()
        assert f'--model "{target}"' in rewritten, rewritten
        assert "/old/path/model.gguf" not in rewritten, rewritten
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.exists(TEMP_SCRIPT):
            os.remove(TEMP_SCRIPT)


# ═══════════════════════════════════════════════════════════════
# 3. Readiness polling: server never comes up → clean failure
# ═══════════════════════════════════════════════════════════════
def test_swap_readiness_failure():
    tmp = tempfile.mkdtemp(prefix="rt_swap_")
    try:
        target = _fake_gguf(tmp)
        events, emit = _emit_capture()
        backend = FakeBackend()
        popen_calls = []

        def _refuse(*a, **k):
            raise __import__("requests").ConnectionError("refused")

        with _script_patch(tmp, FAKE_SCRIPT_M), \
             patch("core.model_manager.find_llama_server_pid", return_value=None), \
             patch("core.model_manager.subprocess.Popen",
                   side_effect=lambda *a, **k: popen_calls.append(a) or Mock(pid=9)), \
             patch("core.model_manager.requests.get", side_effect=_refuse), \
             patch("core.model_manager.time.sleep"):
            result = swap_model(target, backend, _make_cfg(), emit_fn=emit)

        assert result["success"] is False, result
        assert "did not become ready within 30s" in result["error"], result
        # The server WAS attempted, but the backend must not be touched
        assert popen_calls, "swap should have attempted to launch the server"
        assert backend.model == "old-model", "backend must not be updated on failure"
        assert ("model_swap_progress", "error") in events, events
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.exists(TEMP_SCRIPT):
            os.remove(TEMP_SCRIPT)


# ═══════════════════════════════════════════════════════════════
# 4. No launch script → falls back to _launch_direct()
# ═══════════════════════════════════════════════════════════════
def test_swap_falls_back_to_direct_launch():
    tmp = tempfile.mkdtemp(prefix="rt_swap_")
    try:
        target = _fake_gguf(tmp)
        direct_calls = []
        backend = FakeBackend()

        # Hide every script candidate (incl. the real /home/cody/launch-gguf.sh
        # which exists on dev machines) so discovery finds nothing.
        real_exists = os.path.exists
        candidates = [os.path.join(tmp, "launch-gguf.sh"),
                      os.path.join(os.path.dirname(tmp), "launch-gguf.sh"),
                      "/home/cody/launch-gguf.sh"]

        def _no_scripts(p):
            return False if p in candidates else real_exists(p)

        with _module_path_patch(tmp), \
             patch("core.model_manager.find_llama_server_pid", return_value=None), \
             patch("core.model_manager._launch_direct",
                   side_effect=lambda path, cfg, emit: direct_calls.append(path)), \
             patch("core.model_manager.os.path.exists", side_effect=_no_scripts), \
             patch("core.model_manager.requests.get",
                   return_value=FakeResp({"data": [{"id": "/fake/loaded.gguf"}]})), \
             patch("core.model_manager.time.sleep"):
            result = swap_model(target, backend, _make_cfg())

        assert result["success"] is True, result
        assert direct_calls == [target], direct_calls
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# 5. Invalid model path is rejected before touching anything
# ═══════════════════════════════════════════════════════════════
def test_swap_rejects_invalid_path():
    popen_calls = []
    with patch("core.model_manager.subprocess.Popen",
               side_effect=lambda *a, **k: popen_calls.append(a)), \
         patch("core.model_manager._launch_direct") as direct:
        result = swap_model("/tmp/not-a-model.txt", FakeBackend(), _make_cfg())
    assert result["success"] is False, result
    assert "Invalid or inaccessible" in result["error"], result
    assert not popen_calls, "nothing should launch for an invalid path"
    direct.assert_not_called()


# ═══════════════════════════════════════════════════════════════
# 6. reasoning_effort toggle (backend + config + config.yaml persist)
# ═══════════════════════════════════════════════════════════════
class _ReasoningBackend:
    def __init__(self, backend="llama-server"):
        self.backend = backend
        self.reasoning_effort = "none"
        self.model = "x"
        self._loaded_model = "x"

    def get_loaded_model(self):
        return self._loaded_model or self.model

    def get_status(self):
        return {"backend": self.backend, "connected": False, "machine_url": "http://x"}


def test_set_reasoning_effort_updates_backend_config_and_disk():
    tmp = tempfile.mkdtemp(prefix="rt_rsn_")
    try:
        disk = os.path.join(tmp, "config.yaml")
        # Realistic config WITH comments + surrounding keys (a comment-stripping
        # persistence would fail the raw-text assertions below).
        with open(disk, "w") as f:
            f.write(
                "# top comment\n"
                "llm:\n"
                "  backend: \"llama-server\"\n"
                "  llama-server:\n"
                "    host: \"127.0.0.1\"\n"
                "    # keep this comment\n"
                "    model: \"some.gguf\"\n"
                "    reasoning_effort: none\n"
                "    timeout: 120\n")
        backend = _ReasoningBackend()
        cfg = _make_cfg()

        with patch("core.model_manager._config_path", return_value=disk):
            result = model_manager.set_reasoning_effort(backend, cfg, "high")

        assert result["success"] is True, result
        assert result["reasoning_effort"] == "high"
        assert result["persisted"] is True
        # running backend updated
        assert backend.reasoning_effort == "high"
        # in-memory config updated
        assert cfg["llm"]["llama-server"]["reasoning_effort"] == "high"
        # Parsed YAML still valid and reflects the change
        import yaml
        with open(disk) as f:
            on_disk = yaml.safe_load(f)
        assert on_disk["llm"]["llama-server"]["reasoning_effort"] == "high"
        # The file was edited IN PLACE: comments + unrelated lines survive and
        # exactly ONE reasoning_effort line exists (no zone insert+replace dupe)
        raw = open(disk).read()
        assert "# top comment" in raw, "top comment lost!"
        assert "# keep this comment" in raw, "section comment lost!"
        assert "timeout: 120" in raw
        assert raw.count("reasoning_effort:") == 1, raw
        assert "reasoning_effort: high" in raw
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_set_reasoning_effort_accepts_all_valid_values():
    tmp = tempfile.mkdtemp(prefix="rt_rsn_")
    try:
        disk = os.path.join(tmp, "config.yaml")
        with open(disk, "w") as f:
            f.write("llm:\n  llama-server:\n    reasoning_effort: none\n")
        cfg = _make_cfg()
        with patch("core.model_manager._config_path", return_value=disk):
            for val in ("none", "low", "medium", "high"):
                r = model_manager.set_reasoning_effort(_ReasoningBackend(), cfg, val)
                assert r["success"] is True and r["reasoning_effort"] == val, r
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_set_reasoning_effort_rejects_invalid_value():
    backend = _ReasoningBackend()
    cfg = _make_cfg()
    r = model_manager.set_reasoning_effort(backend, cfg, "ultra")
    assert r["success"] is False, r
    assert "Invalid" in r["error"], r
    assert backend.reasoning_effort == "none", "backend must be untouched on error"
    assert "reasoning_effort" not in cfg.get("llm", {}).get("llama-server", {}), cfg


def test_current_model_info_includes_reasoning_effort():
    info = model_manager.get_current_model_info(_ReasoningBackend())
    assert info["reasoning_effort"] == "none"
    backend = _ReasoningBackend()
    backend.reasoning_effort = "medium"
    assert model_manager.get_current_model_info(backend)["reasoning_effort"] == "medium"


test_swap_rewrites_m_model_arg()
test_swap_rewrites_double_dash_model_arg()
test_swap_readiness_failure()
test_swap_falls_back_to_direct_launch()
test_swap_rejects_invalid_path()
test_set_reasoning_effort_updates_backend_config_and_disk()
test_set_reasoning_effort_accepts_all_valid_values()
test_set_reasoning_effort_rejects_invalid_value()
test_current_model_info_includes_reasoning_effort()

print("=== ALL MODEL-MANAGER SWAP TESTS PASSED ===")
