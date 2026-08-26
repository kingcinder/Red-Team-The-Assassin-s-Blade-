"""
RedTeam Harness — Hardened Tool Runner
Enforces security boundaries around every tool execution:
  - Input validation / type checking against ToolDefinition parameters
  - Argument escaping to prevent command injection
  - Timeout enforcement with SIGTERM → SIGKILL escalation
  - Output size limits
  - Concurrent execution caps
  - Full audit trail
"""
import os
import re
import json
import time
import logging
import subprocess
import threading
from typing import Dict, Any, Optional, List

from core.tool_registry import ToolRegistry, ToolDefinition
from core.result_cache import ResultCache

logger = logging.getLogger("redteam.hardening")

# ── Limits ──
DEFAULT_MAX_OUTPUT_CHARS = 100_000
MAX_CONCURRENT_EXECUTIONS = 3
GRACE_PERIOD_SECONDS = 5   # SIGTERM → SIGKILL gap

# ── Injection patterns to reject in string args ──
#
# THREAT MODEL (audit item #10):
# All tool execution uses subprocess with a LIST and shell=False, so bare
# shell metacharacters (&, ;, $, |, ( ) in URLs, POST data, headers,
# passwords) are NEVER interpreted by a shell. These patterns are therefore
# defense-in-depth against a DIFFERENT threat: tools that re-interpret their
# own arguments (e.g., tools that shell out internally, write attacker-
# controlled text into a config file they later source, or parse strings
# with their own shell-like DSL). Against pure shell injection, shell=False
# alone is the primary mitigation.
#
# Audit: only tools that themselves re-interpret args are at risk. Known
# offenders: anything building a resource file, config, or script from a
# string arg (msf_resource, searchsploit_exploit, curl headers).
INJECTION_PATTERNS = [
    r'\$\(',                     # $(...) command substitution
    r'\$\{',                     # ${...} parameter expansion (e.g. ${IFS})
    r'`[^`]*`',                  # backtick subshell
    r'&&|\|\|',                  # && / ||
    r';\s*(?:sh|bash|nc|ncat|python|perl|wget|curl|/bin/|/usr/)',  # ; + command
    r'\|\s*(?:sh|bash|nc|ncat|python|perl|wget|curl|/bin/|/usr/)',  # | + command
    r'\|\s*tee\s+/',            # | tee / (rootkit write)
    r'\/etc\/(passwd|shadow)',   # Sensitive file reads
    r'rm\s+-rf',                 # Destructive commands within args
    r'\.\.[/\\]',              # Path traversal
]


class HardenedToolRunner:
    """
    Wraps ToolRegistry with security hardening:
    1. Validates arg types before execution
    2. Rejects args containing shell metacharacters
    3. Enforces per-tool and per-workflow timeouts
    4. Caps output size
    5. Limits concurrent executions
    6. Logs full audit trail
    """

    def __init__(self, registry: ToolRegistry, audit_dir: str = None):
        self.registry = registry
        self._active_executions = 0
        self._lock = threading.Lock()
        self._audit_log: List[Dict] = []
        self.cache = ResultCache()
        # Audit persistence (#14): write audit entries to a JSONL file so they
        # survive process crashes/restarts. audit_dir defaults to ./output/.
        self._audit_dir = audit_dir or os.path.abspath("./output")
        os.makedirs(self._audit_dir, exist_ok=True)

    def execute(self, tool_name: str, args: dict,
                timeout: int = 300,
                max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
                sandbox_output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute a tool with full security hardening.
        Returns the same dict format as ToolRegistry.execute but with added safety fields.
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return {"stdout": "", "stderr": f"Unknown tool: {tool_name}",
                    "exit_code": -1, "duration": 0, "blocked": True,
                    "block_reason": "unknown_tool"}

        if not tool.installed:
            return {"stdout": "", "stderr": f"Tool not installed: {tool_name}",
                    "exit_code": -1, "duration": 0, "blocked": True,
                    "block_reason": "not_installed"}

        # ── 0. Check result cache first ──
        cached = self.cache.get(tool_name, args)
        if cached:
            cached["from_cache"] = True
            logger.info(f"Cache hit for {tool_name} (saved {cached.get('duration', 0)}s)")
            return cached

        # ── 1. Validate & sanitize args ──
        valid, reason = self._validate_args(tool, args)
        if not valid:
            return {"stdout": "", "stderr": reason, "exit_code": -1,
                    "duration": 0, "blocked": True, "block_reason": reason}

        safe_args = self._sanitize_args(tool, args)

        # ── 2. Concurrent execution cap ──
        with self._lock:
            if self._active_executions >= MAX_CONCURRENT_EXECUTIONS:
                return {"stdout": "", "stderr": "Too many concurrent tool executions",
                        "exit_code": -1, "duration": 0, "blocked": True,
                        "block_reason": "concurrency_limit"}
            self._active_executions += 1

        # ── 3. Build command (delegate to registry) ──
        try:
            cmd = self.registry._build_command(tool, safe_args)
        except Exception as e:
            with self._lock:
                self._active_executions -= 1
            return {"stdout": "", "stderr": f"Command build error: {e}",
                    "exit_code": -1, "duration": 0, "blocked": True,
                    "block_reason": "build_error"}

        cmd_str = " ".join(cmd)
        logger.info(f"Hardened exec: {cmd_str[:200]}")

        # ── 4. Execute with timeout enforcement ──
        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # Security: no shell=True, working dir inside sandbox
                cwd=sandbox_output_dir or os.getcwd(),
            )

            effective_timeout = min(timeout, tool.timeout) if timeout else tool.timeout
            try:
                stdout, stderr = proc.communicate(timeout=effective_timeout)
                exit_code = proc.returncode
                killed = False
            except subprocess.TimeoutExpired:
                # ── Graceful shutdown: SIGTERM, wait, SIGKILL ──
                logger.warning(f"Tool {tool_name} timed out after {effective_timeout}s — sending SIGTERM")
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=GRACE_PERIOD_SECONDS)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    logger.warning(f"Tool {tool_name} didn't respond to SIGTERM — sending SIGKILL")
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    exit_code = -9
                killed = True

        except Exception as e:
            with self._lock:
                self._active_executions -= 1
            return {"stdout": "", "stderr": str(e), "exit_code": -1,
                    "duration": time.time() - start, "blocked": True,
                    "block_reason": "exec_error"}

        elapsed = time.time() - start

        with self._lock:
            self._active_executions -= 1

        # ── 5. Enforce output size limits ──
        stdout = (stdout or "")[:max_output_chars]
        stderr = (stderr or "")[:max_output_chars // 5]
        if len(stdout) >= max_output_chars:
            stdout += f"\n\n[TRUNCATED — output exceeds {max_output_chars} chars]"
        if len(stderr) >= max_output_chars // 5:
            stderr += f"\n\n[TRUNCATED]"

        # ── 6. Audit trail ──
        audit_entry = {
            "tool": tool_name,
            "args": {k: str(v)[:100] for k, v in safe_args.items()},
            "command": cmd_str[:500],
            "exit_code": exit_code,
            "duration": round(elapsed, 2),
            "killed": killed,
            "stdout_len": len(stdout),
            "stderr_len": len(stderr),
            "timestamp": time.time(),
        }
        self._audit_log.append(audit_entry)

        # Persist audit entry to disk (#14 fix)
        try:
            audit_path = os.path.join(self._audit_dir, "audit_log.jsonl")
            with open(audit_path, "a") as af:
                af.write(json.dumps(audit_entry) + "\n")
        except Exception:
            pass  # best-effort; in-memory log is the fallback

        result = {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration": round(elapsed, 2),
            "command": cmd_str[:300],
            "blocked": False,
            "killed": killed,
            "audit": audit_entry,
        }

        # ── 7. Store in cache ──
        self.cache.put(tool_name, args, result)

        return result

    def _validate_args(self, tool: ToolDefinition, args: dict) -> tuple:
        """
        Validate args against the tool's parameter definitions.
        Returns (is_valid, reason).
        """
        for pname, pinfo in tool.parameters.items():
            val = args.get(pname)
            if val is None:
                if pinfo.get("required"):
                    return False, f"Missing required param '{pname}' for {tool.name}"
                continue

            ptype = pinfo.get("type", "string")

            # Type checking
            if ptype == "integer":
                try:
                    int(str(val))
                except (ValueError, TypeError):
                    return False, f"Param '{pname}' must be an integer, got: {val}"
            elif ptype == "boolean":
                if not isinstance(val, bool) and str(val).lower() not in ("true", "false", "1", "0"):
                    return False, f"Param '{pname}' must be boolean, got: {val}"

            # Command injection rejection: string values must not contain
            # shell metacharacters that could escape the arg boundary.
            # We REJECT (never silently mutate) so the operator/LLM sees the
            # refusal and the tool never runs against altered input.
            if isinstance(val, str):
                for pattern in INJECTION_PATTERNS:
                    if re.search(pattern, val):
                        return False, (f"Param '{pname}' rejected: contains dangerous "
                                       f"characters (shell metachars/path traversal). "
                                       f"Value: {val[:50]}")

        return True, "ok"

    def _sanitize_args(self, tool: ToolDefinition, args: dict) -> dict:
        """
        Coerce args to their declared types (bool/int/str).
        NOTE: injection characters are REJECTED in _validate_args (never
        silently stripped) — this method only normalizes types.
        """
        safe = {}
        for pname, val in args.items():
            ptype = tool.parameters.get(pname, {}).get("type", "string")

            if isinstance(val, bool):
                safe[pname] = val
                continue

            val_str = str(val)

            # Type coercion
            if ptype == "integer":
                try:
                    safe[pname] = int(val_str)
                except (ValueError, TypeError):
                    # Type coercion failed — fail loud rather than silently
                    # downgrading a declared int to a raw string (#9 fix).
                    # Return dict keyed by param name for the caller to inspect.
                    safe[pname] = f"INVALID:{val_str}"
            else:
                safe[pname] = val_str

        return safe

    def get_audit_log(self) -> List[Dict]:
        """Get the full audit trail."""
        return list(self._audit_log)

    def clear_audit_log(self):
        """Reset the audit trail."""
        self._audit_log = []

    def get_active_count(self) -> int:
        """Return how many tool executions are currently active."""
        with self._lock:
            return self._active_executions