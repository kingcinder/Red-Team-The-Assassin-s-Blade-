"""
RedTeam Harness — Task Isolation (Sandbox)
Creates per-workflow subfolder trees to isolate data by task.
Each workflow run gets its own timestamped directory with strict boundaries.
"""
import os
import shutil
import secrets
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("redteam.sandbox")

# ── Limits ──
MAX_TOTAL_OUTPUT_MB = 50
MAX_SINGLE_FILE_KB = 500


class TaskSandbox:
    """
    Creates and manages an isolated task directory:
      tasks/<workflow_name>/<timestamp>/
        ├── output/      # stdout/stderr per tool step
        ├── artifacts/   # downloaded files, screenshots, payloads
        ├── logs/        # command log, LLM conversation dump
        └── state.json   # workflow state for checkpoint/resume

    Enforces size limits and prevents cross-task data leakage.
    """

    def __init__(self, workflow_name: str, base_dir: str = "tasks"):
        self.workflow_name = workflow_name
        self.base_dir = os.path.abspath(base_dir)
        # Timestamp + random suffix → unique even for concurrent runs in the
        # same second (multi-target scheduler). Format keeps the trailing
        # 8digit_6digit timestamp parseable by server.py's task_id regex.
        self.timestamp = (datetime.now().strftime("%Y%m%d_%H%M%S")
                          + "_" + secrets.token_hex(2))
        self.task_id = f"{workflow_name}_{self.timestamp}"
        self.root = os.path.join(self.base_dir, workflow_name, self.timestamp)
        self._total_bytes = 0

    def setup(self) -> str:
        """Create the isolated directory tree. Returns the root path."""
        for sub in ["output", "artifacts", "logs"]:
            os.makedirs(os.path.join(self.root, sub), exist_ok=True)

        # Initialize state.json
        self.save_state({
            "workflow": self.workflow_name,
            "task_id": self.task_id,
            "started": datetime.now().isoformat(),
            "current_step": 0,
            "total_steps": 0,
            "status": "initialized",
            "steps_completed": [],
            "findings": [],
            "total_output_bytes": 0,
        })

        logger.info(f"Sandbox created: {self.root}")
        return self.root

    def write_output(self, step_name: str, stdout: str, stderr: str):
        """Write tool output files for a given step. Enforces per-file limits."""
        self._check_total_size()

        safe_name = step_name.replace("/", "_").replace(" ", "_")
        stdout = stdout[:MAX_SINGLE_FILE_KB * 1000] or "[empty stdout]"
        stderr = stderr[:MAX_SINGLE_FILE_KB * 1000] or "[empty stderr]"

        out_path = os.path.join(self.root, "output", f"{safe_name}.stdout.txt")
        err_path = os.path.join(self.root, "output", f"{safe_name}.stderr.txt")

        with open(out_path, "w") as f:
            f.write(stdout)
        with open(err_path, "w") as f:
            f.write(stderr)

        self._total_bytes += len(stdout) + len(stderr)

    def save_artifact(self, name: str, data: bytes):
        """Save an artifact (payload, screenshot, downloaded file)."""
        self._check_total_size()
        path = os.path.join(self.root, "artifacts", name)
        with open(path, "wb") as f:
            f.write(data)
        self._total_bytes += len(data)

    def write_log(self, log_name: str, content: str):
        """Append to a log file in the logs/ directory."""
        path = os.path.join(self.root, "logs", f"{log_name}.log")
        with open(path, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {content}\n")

    def save_state(self, state: dict):
        """Checkpoint the workflow state to state.json (atomic, via StateStore)."""
        from core.state_store import atomic_write_json
        state["last_updated"] = datetime.now().isoformat()
        state["total_output_bytes"] = self._total_bytes
        path = os.path.join(self.root, "state.json")
        atomic_write_json(path, state)

    def load_state(self) -> dict:
        """Load the current state from state.json (corruption-tolerant)."""
        from core.state_store import read_json
        path = os.path.join(self.root, "state.json")
        return read_json(path, {}) or {}

    def get_output_path(self, step_name: str) -> str:
        """Get the path where a step's stdout would be stored."""
        safe_name = step_name.replace("/", "_").replace(" ", "_")
        return os.path.join(self.root, "output", f"{safe_name}.stdout.txt")

    def read_output(self, step_name: str) -> str:
        """Read a step's stdout back from disk."""
        path = self.get_output_path(step_name)
        if os.path.exists(path):
            with open(path) as f:
                return f.read()
        return ""

    def get_total_size_mb(self) -> float:
        """Get the total size of all written data in MB."""
        return self._total_bytes / (1024 * 1024)

    def cleanup(self):
        """Remove the task directory entirely."""
        if os.path.exists(self.root):
            shutil.rmtree(self.root)
            logger.info(f"Sandbox cleaned: {self.root}")

    def list_tasks(self) -> list:
        """List all task directories for this workflow."""
        wf_dir = os.path.join(self.base_dir, self.workflow_name)
        if not os.path.exists(wf_dir):
            return []
        tasks = []
        for ts in sorted(os.listdir(wf_dir), reverse=True):
            path = os.path.join(wf_dir, ts)
            if os.path.isdir(path):
                state_path = os.path.join(path, "state.json")
                from core.state_store import read_json
                state = read_json(state_path, {}, quiet=True) or {}
                # task_id is workflow_<timestamp>
                tasks.append({
                    "task_id": f"{self.workflow_name}_{ts}",
                    "started": state.get("started", ts),
                    "status": state.get("status", "unknown"),
                    "current_step": state.get("current_step", 0),
                    "total_steps": state.get("total_steps", 0),
                    "root": path,
                })
        return tasks

    @staticmethod
    def find_latest_state(workflow_name: str, base_dir: str = "tasks") -> Optional[dict]:
        """
        Find the most recent state.json for a workflow (used for resume).
        Returns the state dict or None.
        """
        wf_dir = os.path.join(base_dir, workflow_name)
        if not os.path.exists(wf_dir):
            return None
        timestamps = sorted(
            (d for d in os.listdir(wf_dir)
             if os.path.isdir(os.path.join(wf_dir, d)) and not d.startswith("multi_")),
            reverse=True,
        )
        for ts in timestamps:
            from core.state_store import read_json
            state_path = os.path.join(wf_dir, ts, "state.json")
            state = read_json(state_path, quiet=True)
            if state is not None:
                state["_root"] = os.path.join(wf_dir, ts)
                state["_task_id"] = f"{workflow_name}_{ts}"
                return state
        return None

    def _check_total_size(self):
        """Raise if total output exceeds the workspace limit."""
        if self._total_bytes > MAX_TOTAL_OUTPUT_MB * 1024 * 1024:
            raise RuntimeError(
                f"Task output exceeds limit ({MAX_TOTAL_OUTPUT_MB}MB). "
                f"Clean up old tasks or increase the limit."
            )