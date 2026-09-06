"""
RedTeam Harness — Social Engineering Tools Module
Phishing, credential harvesting, browser exploitation.
"""
from tools.base import BaseTool


class SocialTools(BaseTool):
    """Social engineering and phishing tools."""

    def get_tools(self):
        return ["setoolkit_attack", "beef_hook", "gophish_setup"]

    def get_quick_commands(self):
        return [
            {"name": "SEToolkit Phishing", "description": "Social Engineer Toolkit phishing attack",
             "tool": "setoolkit_attack",
             "args_template": {"attack": "1"},
             "note": "SEToolkit is interactive. Select attack vector when launched."},
            {"name": "BeEF Browser Hook", "description": "Browser Exploitation Framework — hook target browsers",
             "tool": "beef_hook",
             "args_template": {"target": "TARGET_URL"},
             "note": "BeEF starts a web UI. Point target's browser to the hook.js URL."},
            {"name": "GoPhish Campaign", "description": "Open-source phishing framework",
             "tool": "gophish_setup",
             "args_template": {"config": "config.json"},
             "note": "GoPhish starts a web admin panel at https://localhost:3333"},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Phishing Engagement Pipeline",
             "description": "SET → GoPhish → BeEF layered attack",
             "best_for": "Full phishing lifecycle — GoPhish campaigns plus BeEF browser hooks for payload delivery",
             "tradeoffs": "Mostly interactive GUI tools (less automatable); needs delivery infrastructure; high OPSEC risk",
             "steps": [
                 {"tool": "gophish_setup", "args": {"target": "TARGET"}, "description": "Set up GoPhish campaign to send phishing emails"},
                 {"tool": "beef_hook", "args": {"target": "TARGET"}, "description": "Hook target browser via BeEF XSS framework"},
                 {"tool": "setoolkit_attack", "args": {"attack": "1", "target": "TARGET"}, "description": "Fingerprint browser and pivot via BeEF"},
                 {"tool": "setoolkit_attack", "args": {"attack": "2", "target": "TARGET"}, "description": "Credential harvesting page via SEToolkit"},
             ]},
        ]