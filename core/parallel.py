"""
RedTeam Harness — Parallel Execution Engine (v4.0)
Runs independent tool calls concurrently so a single LLM iteration that
requests N tools finishes in ~max(duration) instead of sum(duration).

Safety:
  - The underlying HardenedToolRunner still enforces its global
    MAX_CONCURRENT_EXECUTIONS semaphore, so parallelism here cannot exceed
    the harness-wide cap.
  - Results are returned in call order (not completion order) so the caller
    can map them 1:1 to tool_calls.
  - Worker exceptions are captured per-call and returned as error results.
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

logger = logging.getLogger("redteam.parallel")

DEFAULT_MAX_WORKERS = 4


class ParallelExecutor:
    """Executes multiple tool calls concurrently with ordered results."""

    def __init__(self, runner, max_workers: int = DEFAULT_MAX_WORKERS):
        self.runner = runner
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._parallel_runs = 0
        self._total_parallelized = 0

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def execute_many(self, calls: List[Dict[str, Any]],
                     timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Execute multiple tool calls concurrently.

        calls: list of {"tool": str, "args": dict, "timeout": int?}
        Returns a list of results aligned 1:1 with `calls` (in order).

        If calls has 0 or 1 entries, executes inline (no thread overhead).
        """
        if not calls:
            return []
        if len(calls) == 1:
            return [self._run_one(calls[0])]

        workers = max(1, min(self.max_workers, len(calls)))
        ordered: List[Optional[Dict]] = [None] * len(calls)

        with self._lock:
            self._parallel_runs += 1
            self._total_parallelized += len(calls)

        logger.info(f"Parallel execution: {len(calls)} calls across {workers} workers")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {}
            for i, call in enumerate(calls):
                future_map[pool.submit(self._run_one, call, timeout)] = i
            for fut in as_completed(future_map):
                idx = future_map[fut]
                try:
                    ordered[idx] = fut.result()
                except Exception as e:
                    logger.error(f"Parallel worker failed for call {idx}: {e}")
                    ordered[idx] = {"stdout": "", "stderr": str(e), "exit_code": -1,
                                    "duration": 0, "blocked": True,
                                    "block_reason": f"worker_error: {e}"}

        return ordered

    # ═══════════════════════════════════════════════════════════════
    # Internals
    # ═══════════════════════════════════════════════════════════════

    def _run_one(self, call: Dict[str, Any],
                 default_timeout: Optional[int] = None) -> Dict[str, Any]:
        """Run a single call through the hardened runner."""
        try:
            return self.runner.execute(
                call.get("tool", ""),
                call.get("args", {}),
                timeout=call.get("timeout") or default_timeout or 300,
            )
        except Exception as e:
            logger.error(f"Tool execution failed for {call.get('tool')}: {e}")
            return {"stdout": "", "stderr": str(e), "exit_code": -1,
                    "duration": 0, "blocked": True, "block_reason": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get parallelism statistics."""
        with self._lock:
            return {
                "parallel_runs": self._parallel_runs,
                "calls_parallelized": self._total_parallelized,
                "max_workers": self.max_workers,
            }
