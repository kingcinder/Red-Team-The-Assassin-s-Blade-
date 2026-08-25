"""
RedTeam Harness — Session Manager
Manages engagement sessions, conversation history, and state.
"""
import os
import json
import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

logger = logging.getLogger("redteam.session")


class SessionManager:
    """Manages pentest engagement sessions with persistent storage."""

    def __init__(self, session_dir: str = "./sessions"):
        self.session_dir = session_dir
        os.makedirs(session_dir, exist_ok=True)
        self._sessions: Dict[str, Dict] = {}

    def create(self, name: Optional[str] = None) -> str:
        """Create a new engagement session."""
        session_id = f"engage_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        if not name:
            name = f"Engagement {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        self._sessions[session_id] = {
            "id": session_id,
            "name": name,
            "created": datetime.now().isoformat(),
            "messages": [],
            "tool_log": [],
            "findings": [],
            "state": "active",
        }
        self._save(session_id)
        return session_id

    def get_messages(self, session_id: str) -> List[Dict[str, str]]:
        """Get conversation history for a session."""
        session = self._load(session_id)
        return session.get("messages", [])

    def add_message(self, session_id: str, role: str, content: str):
        """Add a message to the session history."""
        session = self._load(session_id)
        session["messages"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        })
        self._save(session_id)

    def log_command(self, session_id: str, tool_name: str, args: dict, result: dict):
        """Log a tool execution to the session."""
        session = self._load(session_id)
        session["tool_log"].append({
            "tool": tool_name,
            "args": args,
            "result": {
                "exit_code": result.get("exit_code"),
                "stdout_preview": result.get("stdout", "")[:500],
                "duration": result.get("duration"),
            },
            "timestamp": datetime.now().isoformat(),
        })
        self._save(session_id)

    def add_finding(self, session_id: str, finding: dict):
        """Add a finding to the session."""
        session = self._load(session_id)
        finding["timestamp"] = datetime.now().isoformat()
        session["findings"].append(finding)
        self._save(session_id)

    def get_summary(self, session_id: str) -> dict:
        """Get a session summary."""
        session = self._load(session_id)
        return {
            "id": session["id"],
            "name": session["name"],
            "created": session["created"],
            "message_count": len(session["messages"]),
            "tool_calls": len(session["tool_log"]),
            "findings": len(session["findings"]),
            "state": session["state"],
        }

    def list_sessions(self) -> List[dict]:
        """List all sessions."""
        sessions = []
        for filename in os.listdir(self.session_dir):
            if filename.endswith(".json"):
                sid = filename.replace(".json", "")
                try:
                    summary = self.get_summary(sid)
                    sessions.append(summary)
                except Exception:
                    continue
        return sorted(sessions, key=lambda s: s["created"], reverse=True)

    def _save(self, session_id: str):
        """Save session to disk."""
        path = os.path.join(self.session_dir, f"{session_id}.json")
        with open(path, "w") as f:
            json.dump(self._sessions.get(session_id, {}), f, indent=2)

    def _load(self, session_id: str) -> dict:
        """Load session from disk or memory."""
        if session_id in self._sessions:
            return self._sessions[session_id]

        path = os.path.join(self.session_dir, f"{session_id}.json")
        if os.path.exists(path):
            with open(path) as f:
                self._sessions[session_id] = json.load(f)
            return self._sessions[session_id]

        return {"id": session_id, "messages": [], "tool_log": [], "findings": [], "state": "unknown"}
