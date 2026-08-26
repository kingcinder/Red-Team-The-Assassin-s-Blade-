"""
RedTeam Harness — Safety Engine
Enforces scope limits, confirms dangerous operations, and logs all actions.
"""
import logging
import ipaddress
from typing import Tuple

logger = logging.getLogger("redteam.safety")


class SafetyEngine:
    """Enforces safety policies for the pentest harness."""

    def __init__(self, config: dict):
        self.config = config
        self.allowed_targets = config.get("allowed_targets", [])
        self.blocked_targets = config.get("blocked_targets", [])
        self.require_confirmation = config.get("require_confirmation", [])
        self.log_all_commands = config.get("log_all_commands", True)
        # Track pending confirmations that require human approval.
        # Key = tool_name:args_hash, Value = True (approved by human UI).
        self._confirmed: set = set()

    def check_tool(self, tool_name: str, args: dict, tool_def=None) -> Tuple[bool, str]:
        """
        Check if a tool execution is safe.
        Returns (is_safe, reason).
        tool_def: optional ToolDefinition — if provided, uses its explicit
        target_param field instead of guessing from key names.
        """
        # Check if tool requires confirmation
        if tool_name in self.require_confirmation:
            import hashlib, json as _json
            args_hash = hashlib.sha256(_json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]
            confirmation_key = f"{tool_name}:{args_hash}"
            if confirmation_key in self._confirmed:
                # Human approved this specific invocation — allow once, then revoke
                self._confirmed.discard(confirmation_key)
                logger.info(f"Tool '{tool_name}' approved by human (confirmed)")
            else:
                logger.warning(f"Tool '{tool_name}' requires user confirmation")
                return False, f"Tool '{tool_name}' requires explicit user confirmation. Use POST /api/safety/confirm with tool and args to approve."

        # Extract target from args — prefer explicit target_param on ToolDefinition
        target = self._extract_target(args, tool_def=tool_def)

        if target:
            # Check blocked targets
            if self._is_blocked(target):
                return False, f"Target '{target}' is in the blocked list."

            # Check allowed targets (if configured)
            if self.allowed_targets and not self._is_allowed(target):
                return False, f"Target '{target}' is not in the allowed scope: {self.allowed_targets}"

        # Log the command
        if self.log_all_commands:
            logger.info(f"[SAFETY] Approved: {tool_name} | target={target} | args={args}")

        return True, "Approved"

    def _extract_target(self, args: dict, tool_def=None) -> str:
        """Extract the target from tool arguments.

        If tool_def is provided and has an explicit target_param, use that.
        Otherwise fall back to scanning known key names.
        """
        # Explicit target_param from ToolDefinition (audit item #4)
        if tool_def and getattr(tool_def, "target_param", None):
            tp = tool_def.target_param
            if tp in args and args[tp]:
                return args[tp]
            # target_param can be a comma-separated list of keys to try
            for key in tp.split(","):
                key = key.strip()
                if key in args and args[key]:
                    return args[key]
        # Legacy fallback: scan known key names
        for key in ("target", "url", "domain", "host", "hosts", "subnet",
                     "cidr", "range", "image", "file", "pdf"):
            if key in args and args[key]:
                return args[key]
        return ""

    def _is_blocked(self, target: str) -> bool:
        """Check if a target is blocked."""
        for blocked in self.blocked_targets:
            # Exact match, or label-boundary-aware prefix check (#6 fix)
            if target == blocked or target.startswith(blocked + ".") or target.startswith(blocked + "/"):
                return True
            try:
                # Check if target is within a blocked CIDR
                if "/" in blocked:
                    target_net = ipaddress.ip_network(target, strict=False)
                    blocked_net = ipaddress.ip_network(blocked, strict=False)
                    if target_net.overlaps(blocked_net):
                        return True
            except (ValueError, TypeError):
                pass
        return False

    def _is_allowed(self, target: str) -> bool:
        """Check if a target is within the allowed scope."""
        try:
            target_ip = ipaddress.ip_address(target.split("/")[0].split(":")[0])
            for allowed in self.allowed_targets:
                try:
                    allowed_net = ipaddress.ip_network(allowed, strict=False)
                    if target_ip in allowed_net:
                        return True
                except (ValueError, TypeError):
                    if target == allowed:
                        return True
        except (ValueError, TypeError):
            # Not an IP, check domain with label-boundary awareness (#6 fix)
            for allowed in self.allowed_targets:
                if target == allowed or target.endswith("." + allowed):
                    return True
        return False

    def approve_tool(self, tool_name: str, args: dict) -> bool:
        """Approve a specific tool invocation (called from human-facing UI/API).
        The approval is single-use and cannot be forged by the LLM because it
        originates from the HTTP API, not from tool_args.
        Returns True if the confirmation was registered.
        """
        import hashlib, json as _json
        args_hash = hashlib.sha256(_json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]
        key = f"{tool_name}:{args_hash}"
        self._confirmed.add(key)
        logger.info(f"Human approved tool '{tool_name}' (args_hash={args_hash})")
        return True

    def get_policy_summary(self) -> dict:
        """Get a summary of the current safety policy."""
        return {
            "allowed_targets": self.allowed_targets,
            "blocked_targets": self.blocked_targets,
            "require_confirmation": self.require_confirmation,
            "log_all_commands": self.log_all_commands,
            "pending_confirmations": len(self._confirmed),
        }
