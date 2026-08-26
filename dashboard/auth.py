"""
RedTeam Harness — Dashboard Authentication (security audit item #2)

Provides a minimal but real authentication layer for the Flask dashboard:
  1. Random SECRET_KEY generated on first run and persisted to .env
  2. Bearer-token gate on all API routes + SocketIO handlers
  3. Token is auto-generated once and printed to the console on startup
  4. Bypass on 127.0.0.1 (loopback) unless HARNESS_AUTH_FORCE=1 is set

This closes the zero-auth remote-control surface exposed by binding to
0.0.0.0 (now fixed to 127.0.0.1 by default, but auth still matters on
shared multi-user boxes even on loopback).
"""
import os
import secrets
import logging
from functools import wraps
from typing import Optional

from flask import request, jsonify, g

logger = logging.getLogger("redteam.auth")

_ENV_PATH = os.path.join(os.path.expanduser("~"), ".redteam_harness", ".env")
os.makedirs(os.path.dirname(_ENV_PATH), exist_ok=True)
_token: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# Secret key & token management
# ═══════════════════════════════════════════════════════════════

def _load_or_create_token() -> str:
    """Load the API token from .env, or generate one and persist it."""
    global _token
    if _token:
        return _token

    # Try reading existing token from .env
    if os.path.isfile(_ENV_PATH):
        with open(_ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("HARNESS_API_TOKEN="):
                    _token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if _token:
                        return _token

    # Generate new token (32 bytes = 256 bits of entropy)
    _token = secrets.token_urlsafe(32)

    # Persist to .env (append or create)
    mode = "a" if os.path.isfile(_ENV_PATH) else "w"
    with open(_ENV_PATH, mode) as f:
        if mode == "a":
            f.write("\n")
        f.write(f"HARNESS_API_TOKEN={_token}\n")

    logger.warning(
        "Generated new API token. Dashboard API access requires this token.\n"
        f"  Token: {_token}\n"
        f"  Stored in: {_ENV_PATH}\n"
        "  Usage: Authorization: Bearer <token>"
    )
    # Print to console so the user sees it immediately on startup
    print(f"\n{'='*60}")
    print(f"  🔑 Dashboard API Token (auto-generated)")
    print(f"  { _token}")
    print(f"  Use: Authorization: Bearer {_token}")
    print(f"{'='*60}\n")
    return _token


def get_secret_key() -> str:
    """Return a random Flask SECRET_KEY, persisted across restarts."""
    if os.path.isfile(_ENV_PATH):
        with open(_ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("HARNESS_SECRET_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    key = secrets.token_hex(32)
    mode = "a" if os.path.isfile(_ENV_PATH) else "w"
    with open(_ENV_PATH, mode) as f:
        if mode == "a":
            f.write("\n")
        f.write(f"HARNESS_SECRET_KEY={key}\n")
    return key


def get_token() -> str:
    """Public accessor for the current API token."""
    return _load_or_create_token()


# ═══════════════════════════════════════════════════════════════
# Request authentication
# ═══════════════════════════════════════════════════════════════

def _is_loopback() -> bool:
    """True if the request comes from 127.0.0.1 / ::1 / localhost."""
    addr = request.remote_addr or ""
    return addr in ("127.0.0.1", "::1", "localhost")


def _auth_required() -> bool:
    """Return True if the current request must be authenticated."""
    force = os.environ.get("HARNESS_AUTH_FORCE", "0") == "1"
    # Bypass auth on loopback unless force-enabled
    if not force and _is_loopback():
        return False
    # All other addresses require auth
    return True


def _extract_token() -> Optional[str]:
    """Pull the bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def check_auth() -> Optional[str]:
    """
    Validate the request's auth token.
    Returns None on success, or an error message string on failure.
    """
    if not _auth_required():
        return None  # loopback — no auth needed
    token = _extract_token()
    expected = _load_or_create_token()
    if not token or token != expected:
        return "Invalid or missing API token. Use: Authorization: Bearer <token>"
    return None


def require_auth(f):
    """Decorator for Flask routes: rejects unauthenticated requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        err = check_auth()
        if err:
            return jsonify({"error": err}), 401
        return f(*args, **kwargs)
    return decorated


def socketio_require_auth(f):
    """
    Decorator for SocketIO handlers: rejects unauthenticated connections.
    SocketIO sends auth via the initial handshake query or a header.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # SocketIO handler signature varies; grab the first arg which is data
        # For connect handlers there's no data, for event handlers data is arg[0]
        # We check the socket's request.environ for auth
        from flask_socketio import disconnect
        # Check token from the socket's HTTP handshake
        environ = request.environ
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            # Also check query param ?token=...
            token = request.args.get("token", "")
        expected = _load_or_create_token()
        force = os.environ.get("HARNESS_AUTH_FORCE", "0") == "1"
        is_lb = _is_loopback()
        if not force and is_lb:
            return f(*args, **kwargs)
        if not token or token != expected:
            disconnect()
            return
        return f(*args, **kwargs)
    return decorated
