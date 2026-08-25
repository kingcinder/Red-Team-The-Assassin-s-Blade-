"""
RedTeam Harness — Safety Engine
Enforces scope limits, confirms dangerous operations, and logs all actions.
"""
import logging
import ipaddress
from typing import Tuple, List

logger = logging.getLogger("redteam.safety")


class SafetyEngine:
    """Enforces safety policies for the pentest harness."""

    def __init__(self, config: dict):
        self.config = config
        self.allowed_targets = config.get("allowed_targets", [])
        self.blocked_targets = config.get("blocked_targets", [])
        self.require_confirmation = config.get("require_confirmation", [])
        self.log_all_commands = config.get("log_all_commands", True)

    def check_tool(self, tool_name: str, args: dict) -> Tuple[bool, str]:
        """
        Check if a tool execution is safe.
        Returns (is_safe, reason).
        """
        # Check if tool requires confirmation
        if tool_name in self.require_confirmation:
            logger.warning(f"Tool '{tool_name}' requires user confirmation")
            return False, f"Tool '{tool_name}' requires explicit user confirmation due to potentially destructive nature."

        # Extract target from args
        target = self._extract_target(args)

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

    def _extract_target(self, args: dict) -> str:
        """Extract the target from tool arguments."""
        for key in ("target", "url", "domain", "host"):
            if key in args and args[key]:
                return args[key]
        return ""

    def _is_blocked(self, target: str) -> bool:
        """Check if a target is blocked."""
        for blocked in self.blocked_targets:
            if target == blocked or target.startswith(blocked):
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
            # Not an IP, check string match
            for allowed in self.allowed_targets:
                if target == allowed or target.endswith(allowed):
                    return True
        return False

    def get_policy_summary(self) -> dict:
        """Get a summary of the current safety policy."""
        return {
            "allowed_targets": self.allowed_targets,
            "blocked_targets": self.blocked_targets,
            "require_confirmation": self.require_confirmation,
            "log_all_commands": self.log_all_commands,
        }
