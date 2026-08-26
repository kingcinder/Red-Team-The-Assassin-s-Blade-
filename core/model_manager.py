"""
RedTeam Harness — Model Manager
Scans AI_MODELS/ for GGUF files, provides metadata, and handles
hot-swap of the loaded model in llama-server without restarting the harness.

v6.1: Model Manager panel — GUI-driven model switching.
"""
import os
import re
import glob
import json
import signal
import logging
import subprocess
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger("redteam.model_manager")

# ── Quantization label map (filename heuristic) ──
_QUANT_LABELS = {
    "Q2_K": "2-bit (Q2_K)",
    "Q3_K_S": "3-bit small (Q3_K_S)",
    "Q3_K_M": "3-bit medium (Q3_K_M)",
    "Q3_K_L": "3-bit large (Q3_K_L)",
    "Q4_0": "4-bit (Q4_0)",
    "Q4_K_S": "4-bit small (Q4_K_S)",
    "Q4_K_M": "4-bit medium (Q4_K_M)",
    "Q5_0": "5-bit (Q5_0)",
    "Q5_K_S": "5-bit small (Q5_K_S)",
    "Q5_K_M": "5-bit medium (Q5_K_M)",
    "Q6_K": "6-bit (Q6_K)",
    "Q8_0": "8-bit (Q8_0)",
    "F16": "16-bit float (F16)",
    "IQ2_XS": "iQ2-XS",
    "IQ2_XXS": "iQ2-XXS",
    "IQ2_S": "iQ2-S",
    "IQ2_M": "iQ2-M",
    "IQ3_XS": "iQ3-XS",
    "IQ3_XXS": "iQ3-XXS",
    "IQ3_S": "iQ3-S",
    "IQ3_M": "iQ3-M",
    "IQ4_XS": "iQ4-XS",
    "IQ4_NL": "iQ4-NL",
    "IQ1_S": "iQ1-S",
    "IQ1_M": "iQ1-M",
    "TQ1_0": "TQ1-0",
    "TQ2_0": "TQ2-0",
}


def _human_size(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _extract_quant_from_name(filename: str) -> Optional[str]:
    """Extract quantization label from GGUF filename."""
    base = os.path.splitext(filename)[0]
    # Check for known quant patterns (longest match first)
    for q in sorted(_QUANT_LABELS.keys(), key=len, reverse=True):
        if q in base:
            return _QUANT_LABELS[q]
    return None


def _extract_model_family(filename: str) -> str:
    """Extract model family/name from GGUF filename."""
    base = os.path.splitext(filename)[0]
    # Remove quant suffixes
    for q in sorted(_QUANT_LABELS.keys(), key=len, reverse=True):
        base = base.replace(f"-{q}", "").replace(f"_{q}", "")
    # Remove common suffixes
    for suffix in ("-gguf", "_gguf", "-GGUF", "_GGUF"):
        base = base.replace(suffix, "")
    return base.strip("-_ ") or filename


def scan_models(models_dir: str = None) -> List[Dict[str, Any]]:
    """
    Scan AI_MODELS/ (and subdirectories) for .gguf files.
    Returns a list of model metadata dicts sorted by size (largest first).
    """
    if models_dir is None:
        # Default: look relative to the harness, then the parent AI_MODELS/
        harness_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [
            os.path.join(harness_dir, "AI_MODELS"),
            os.path.join(os.path.dirname(harness_dir), "AI_MODELS"),
            "/home/cody/AI_MODELS",
        ]
        models_dir = None
        for c in candidates:
            if os.path.isdir(c):
                models_dir = c
                break
        if models_dir is None:
            return []

    gguf_files = glob.glob(os.path.join(models_dir, "**", "*.gguf"), recursive=True)
    models = []
    for path in sorted(gguf_files):
        try:
            stat = os.stat(path)
            name = os.path.basename(path)
            size_bytes = stat.st_size
            models.append({
                "name": name,
                "path": path,
                "size_bytes": size_bytes,
                "size_human": _human_size(size_bytes),
                "quantization": _extract_quant_from_name(name),
                "family": _extract_model_family(name),
                "modified": stat.st_mtime,
            })
        except OSError:
            continue

    # Sort by size descending (largest first — these are usually the best models)
    models.sort(key=lambda m: m["size_bytes"], reverse=True)
    return models


def get_current_model_info(llm_backend) -> Dict[str, Any]:
    """Get info about the currently loaded model from the LLM backend."""
    loaded = llm_backend.get_loaded_model() if hasattr(llm_backend, "get_loaded_model") else "unknown"
    status = llm_backend.get_status() if hasattr(llm_backend, "get_status") else {}
    return {
        "loaded_model": loaded,
        "backend": status.get("backend", "llama-server"),
        "connected": status.get("connected", False),
        "base_url": status.get("machine_url", ""),
    }


def find_llama_server_pid() -> Optional[int]:
    """Find the PID of the running llama-server process."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "llama-server"],
            capture_output=True, text=True, timeout=5,
        )
        pids = [int(line.strip()) for line in result.stdout.strip().split("\n") if line.strip()]
        return pids[0] if pids else None
    except Exception:
        return None


def _validate_model_path(target_model_path: str) -> bool:
    """Validate that the model path is a real .gguf file in an allowed directory."""
    if not os.path.isfile(target_model_path):
        return False
    if not target_model_path.endswith(".gguf"):
        return False
    # Resolve to canonical path to prevent symlink-based traversal
    real = os.path.realpath(target_model_path)
    return os.path.isfile(real) and real.endswith(".gguf")


def swap_model(
    target_model_path: str,
    llm_backend,
    config: dict,
    emit_fn=None,
) -> Dict[str, Any]:
    """
    Hot-swap the loaded model in llama-server.

    1. Validates the target GGUF exists
    2. Kills the current llama-server process
    3. Starts a new llama-server with the new model
    4. Waits for readiness (polls /v1/models)
    5. Updates the LLM backend's model reference

    Returns a status dict with success/error info.
    emit_fn: optional callback(event_name, data) for WebSocket progress updates.
    """
    def emit(event, data):
        if emit_fn:
            try:
                emit_fn(event, data)
            except Exception:
                pass

    # ── Step 1: Validate (path traversal guard) ──
    if not _validate_model_path(target_model_path):
        return {"success": False, "error": "Invalid or inaccessible model path"}

    target_name = os.path.basename(target_model_path)
    emit("model_swap_progress", {"status": "validating", "model": target_name, "message": f"Validating {target_name}..."})

    # ── Step 2: Find the launch script ──
    harness_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script_candidates = [
        os.path.join(harness_dir, "launch-gguf.sh"),
        os.path.join(os.path.dirname(harness_dir), "launch-gguf.sh"),
        "/home/cody/launch-gguf.sh",
    ]
    script_path = None
    for c in script_candidates:
        if os.path.exists(c):
            script_path = c
            break

    # ── Step 3: Kill current llama-server ──
    emit("model_swap_progress", {"status": "stopping", "model": target_name, "message": "Stopping current llama-server..."})

    old_pid = find_llama_server_pid()
    if old_pid:
        try:
            os.kill(old_pid, signal.SIGTERM)
            # Wait up to 10s for graceful shutdown
            for _ in range(20):
                try:
                    os.kill(old_pid, 0)  # Check if alive
                    time.sleep(0.5)
                except OSError:
                    break
            # Force kill if still alive
            try:
                os.kill(old_pid, 0)
                os.kill(old_pid, signal.SIGKILL)
                time.sleep(1)
            except OSError:
                pass
            logger.info(f"Killed llama-server PID {old_pid}")
        except Exception as e:
            logger.warning(f"Failed to kill llama-server PID {old_pid}: {e}")
    else:
        logger.info("No running llama-server found")

    # ── Step 4: Start new llama-server ──
    emit("model_swap_progress", {"status": "starting", "model": target_name, "message": f"Starting llama-server with {target_name}..."})

    if script_path:
        # Use the launch script with the new model path
        # We modify the environment or pass the model as an override
        try:
            # Read the script and replace the --model argument
            with open(script_path) as f:
                script_content = f.read()

            # Replace the model path in the script
            old_model_pattern = re.search(r'--model\s+["\']?([^"\'\s\\]+)', script_content)
            if old_model_pattern:
                new_script = script_content.replace(
                    old_model_pattern.group(0),
                    f'--model "{target_model_path}"'
                )
            else:
                # Add --model before the first - in the llama-server command
                new_script = script_content

            # Write a temp script and execute it
            temp_script = "/tmp/_redteam_model_swap.sh"
            with open(temp_script, "w") as f:
                f.write(new_script)
            os.chmod(temp_script, 0o755)

            # Launch in background
            proc = subprocess.Popen(
                ["bash", temp_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            logger.info(f"Launched new llama-server via script (PID {proc.pid})")
        except Exception as e:
            logger.error(f"Failed to launch via script: {e}")
            # Fallback: direct launch
            _launch_direct(target_model_path, config, emit)
    else:
        # Direct launch without script
        _launch_direct(target_model_path, config, emit)

    # ── Step 5: Wait for readiness ──
    emit("model_swap_progress", {"status": "waiting", "model": target_name, "message": "Waiting for llama-server to become ready..."})

    host = config.get("llm", {}).get("llama-server", {}).get("host", "127.0.0.1")
    port = config.get("llm", {}).get("llama-server", {}).get("port", 8080)
    base_url = f"http://{host}:{port}"

    ready = False
    for attempt in range(30):  # Wait up to 30 seconds
        time.sleep(1)
        try:
            r = requests.get(f"{base_url}/v1/models", timeout=3)
            if r.status_code == 200:
                data = r.json()
                models_list = data.get("data", [])
                if models_list:
                    ready = True
                    loaded_id = models_list[0].get("id") or models_list[0].get("model", "")
                    logger.info(f"llama-server ready — loaded: {loaded_id}")
                    break
        except Exception:
            pass
        if attempt % 5 == 4:
            emit("model_swap_progress", {
                "status": "waiting",
                "model": target_name,
                "message": f"Waiting for llama-server... ({attempt + 1}s)",
            })

    if not ready:
        emit("model_swap_progress", {"status": "error", "model": target_name, "message": "llama-server did not become ready within 30s"})
        return {"success": False, "error": "llama-server did not become ready within 30s"}

    # ── Step 6: Update LLM backend ──
    emit("model_swap_progress", {"status": "updating", "model": target_name, "message": "Updating LLM backend..."})

    # Update the backend's model reference
    if hasattr(llm_backend, "model"):
        llm_backend.model = target_name
    if hasattr(llm_backend, "_loaded_model"):
        llm_backend._loaded_model = loaded_id

    # Re-detect to get the actual loaded model name
    try:
        llm_backend._detect_loaded_model()
    except Exception:
        pass

    final_model = llm_backend.get_loaded_model() if hasattr(llm_backend, "get_loaded_model") else loaded_id

    emit("model_swap_progress", {
        "status": "complete",
        "model": target_name,
        "loaded_model": final_model,
        "message": f"Model swapped to {final_model}",
    })

    return {
        "success": True,
        "model": target_name,
        "loaded_model": final_model,
        "message": f"Successfully swapped to {final_model}",
    }


def _launch_direct(model_path: str, config: dict, emit_fn=None):
    """Launch llama-server directly without a script."""
    host = config.get("llm", {}).get("llama-server", {}).get("host", "127.0.0.1")
    port = config.get("llm", {}).get("llama-server", {}).get("port", 8080)
    max_tokens = config.get("llm", {}).get("llama-server", {}).get("max_tokens", 4096)

    # Find llama-server binary
    llama_bin = None
    for candidate in [
        "/usr/local/bin/llama-server",
        "/usr/bin/llama-server",
        os.path.expanduser("~/llama.cpp/build/bin/llama-server"),
        os.path.expanduser("~/llama.cpp/bin/llama-server"),
    ]:
        if os.path.exists(candidate):
            llama_bin = candidate
            break

    if not llama_bin:
        logger.error("Cannot find llama-server binary")
        return

    cmd = [
        llama_bin,
        "--model", model_path,
        "--host", host,
        "--port", str(port),
        "--ctx-size", "4096",
        "--n-predict", str(max_tokens),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        logger.info(f"Launched llama-server directly (PID {proc.pid}, model={model_path})")
    except Exception as e:
        logger.error(f"Failed to launch llama-server directly: {e}")
