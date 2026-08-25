"""
RedTeam Harness — Base Tool Class
All tool modules inherit from this base class.
"""


class BaseTool:
    """Base class for all tool modules."""

    def __init__(self, registry):
        self.registry = registry

    def get_tools(self):
        """Return list of tool names provided by this module."""
        return []

    def get_quick_commands(self) -> list:
        """Return pre-built command templates for the dashboard."""
        return []

    def get_preset_attack_chains(self) -> list:
        """Return multi-step attack chain presets."""
        return []
