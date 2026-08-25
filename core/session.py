"""
RedTeam Harness — Session Manager
Manages engagement sessions, conversation history, and state.
"""
import os
import uuid
import logging
from datetime import datetime
from typing import Optional, Dict, List

from core.state_store import JsonFileStore

logger = logging.getLogger("redteam.session")


class SessionManager:
    """Manages pentest engagement sessions with persistent storage."""

    def __init__(self, session_dir: str = "./sessions"):
        self.session_dir = session_dir
        self._store = JsonFileStore(session_dir)  # atomic, crash-safe persistence
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
        """List all sessions (delegates key scan to StateStore)."""
        sessions = []
        for sid in self._store.list_keys():
            try:
                sessions.append(self.get_summary(sid))
            except Exception:
                continue
        return sorted(sessions, key=lambda s: s["created"], reverse=True)

    def _save(self, session_id: str):
        """Save session to disk (atomic, via StateStore)."""
        self._store.save(session_id, self._sessions.get(session_id, {}))

    def _load(self, session_id: str) -> dict:
        """Load session from disk or memory (corruption-tolerant)."""
        if session_id in self._sessions:
            return self._sessions[session_id]

        data = self._store.load(session_id)
        if data is not None:
            self._sessions[session_id] = data
            return self._sessions[session_id]

        return {"id": session_id, "messages": [], "tool_log": [], "findings": [], "state": "unknown"}
