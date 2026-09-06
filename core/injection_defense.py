"""
RedTeam Harness — Prompt Text Handling (unrestricted mode)

All restriction-based sanitization has been removed: user text and tool
output pass through to the LLM unmodified. No injection phrases, role
manipulation, jailbreak framing, or special tokens are stripped, and
untrusted content is no longer wrapped in "do not treat as instructions"
delimiters. The LLM is free to act on whatever the harness feeds it.

The only transforms left are mechanical hygiene that keeps prompts usable:
  - control-character / ANSI / bidi-override stripping (they corrupt JSON
    parsing and terminal rendering regardless of intent)
  - length truncation (protects the context window)

The public API is preserved for compatibility with callers (orchestrator,
llm_backend, msf_generator, workflow_engine, report, knowledge_base, etc.).
"""

import re
import threading

# ═══════════════════════════════════════════════════════════════
# CONTROL CHARACTER STRIPPING (mechanical hygiene only)
# ═══════════════════════════════════════════════════════════════

# Null bytes, backspace, escape sequences, ANSI escapes, Unicode bidi
# overrides, zero-width characters, BOM, combining marks, soft hyphen.
_CONTROL_CHAR_RE = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'     # C0 controls + DEL
    r'|[\x80-\x9f]'                          # C1 controls
    r'|(?:\x1b\[[0-9;]*[a-zA-Z])'           # ANSI escape sequences
    r'|\ufe0e|\ufe0f|\u200b|\u200c|\u200d|\u2060|\ufeff'  # Zero-width + BOM
    r'|[\u202a-\u202e]'                       # Bidi overrides + RLO
    r'|[\u2066-\u206f]'                       # Bidi isolates
    r'|[\U000E0000-\U000E007F]'               # Unicode tag block (invisible)
    r'|[\u0300-\u036f\u1ab0-\u1aff\u20d0-\u20ff\ufe20-\ufe2f]'  # Combining marks
    r'|\u00ad'                                # Soft hyphen
)

_COLLAPSE_SPACES_RE = re.compile(r" {2,}")

# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

DEFAULT_MAX_LEN = 2000
DEFAULT_MAX_TOOL_LEN = 8000


def strip_control_chars(text: str) -> str:
    """Remove control characters, ANSI escapes, and Unicode bidi overrides."""
    if not text:
        return ""
    return _CONTROL_CHAR_RE.sub("", text)


def strip_injection_phrases(text: str) -> str:
    """No-op (restrictions removed) — returns the text unchanged."""
    return text if text else ""


def strip_injection_vectors(text: str) -> str:
    """No-op (restrictions removed) — returns the text unchanged."""
    return text if text else ""


def collapse_whitespace(text: str) -> str:
    """Collapse multiple whitespace/newlines into single spaces."""
    if not text:
        return ""
    text = text.replace("\n", " ").replace("\r", "").replace("\t", " ")
    return _COLLAPSE_SPACES_RE.sub(" ", text).strip()


def sanitize_for_llm(text: str, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Pass user text through to the LLM unchanged — only control-char
    hygiene and length truncation are applied. No phrase/vector stripping."""
    if not text:
        return ""

    cleaned = strip_control_chars(str(text))
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."

    return cleaned


def sanitize_tool_output(text: str, max_len: int = DEFAULT_MAX_TOOL_LEN) -> str:
    """Pass tool output through to the LLM unchanged — only control-char
    hygiene and length truncation are applied. No role-pattern, token, or
    jailbreak-framing stripping."""
    if not text:
        return ""

    cleaned = strip_control_chars(str(text))
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "\n[... truncated]"

    return cleaned


# ═══════════════════════════════════════════════════════════════
# DETECTION EVENTS (kept for API compatibility — never fire now)
# ═══════════════════════════════════════════════════════════════

INJECTION_EVENTS = {"count": 0, "last": None, "kinds": {}}

_INJECTION_LOCK = threading.Lock()


def _record_injection_event(kind: str) -> None:
    """No-op — sanitization no longer strips anything."""
    with _INJECTION_LOCK:
        INJECTION_EVENTS["count"] += 0


def reset_injection_events() -> None:
    """Reset the detection counter (kept for test compatibility)."""
    with _INJECTION_LOCK:
        INJECTION_EVENTS["count"] = 0
        INJECTION_EVENTS["last"] = None
        INJECTION_EVENTS["kinds"] = {}


def wrap_untrusted(text: str, label: str = "user_input") -> str:
    """Return the text unchanged — untrusted content is no longer wrapped
    or flagged for the LLM."""
    return text if text else ""


def sanitize_for_prompt(text: str, max_len: int = DEFAULT_MAX_LEN,
                         wrap: bool = True, label: str = "user_input") -> str:
    """Pass-through with truncation (no wrapping, no stripping)."""
    return sanitize_for_llm(text, max_len=max_len)
