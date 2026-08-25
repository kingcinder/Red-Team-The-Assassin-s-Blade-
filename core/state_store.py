"""
RedTeam Harness — StateStore (architecture candidate #5)

ONE deep module that owns every JSON persistence primitive in the harness.

Previously four modules hand-rolled the same fragile pattern:
    os.makedirs(dir, exist_ok=True)
    with open(path, "w") as f: json.dump(data, f)
    with open(path) as f: json.load(f)

...in session.py, task_isolation.py, campaign.py, and autonomous.py. The
repeated mistakes this centralizes:

  1. Direct writes  → a crash mid-dump truncates state.json (silent drift)
  2. No default=str → a non-serializable value (datetime, set, Path) blows
     up the save at the worst moment (mid-engagement)
  3. Unbounded loads → a corrupt/partial file returns junk or raises and the
     caller silently proceeds with empty state (drift)

StateStore provides:
  - atomic_write_json()  — write to a temp file in the same dir, fsync, then
    os.replace() into place. A crash can never leave a truncated file.
  - read_json()          — tolerant load with a caller-supplied default;
    corrupt files log a warning and return the default instead of raising.
  - ensure_dir()         — makedirs(exist_ok=True) wrapper.
  - safe_filename()      — sanitize IDs used in filenames.

The session / task / campaign / replay persistence call sites (the domains
this candidate owns) all delegate to this module so the survivable-write
contract is enforced in exactly one place.

Atomicity note: os.replace() is atomic on POSIX (rename(2)) — readers either
see the old complete file or the new complete file, never a partial write.
"""
import os
import re
import json
import logging
import tempfile

logger = logging.getLogger("redteam.state_store")

# Characters that are dangerous / illegal in filenames (and path separators).
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._\-]")


def ensure_dir(path: str) -> str:
    """Create a directory (and parents) if missing; return the path."""
    os.makedirs(path, exist_ok=True)
    return path


def safe_filename(name: str) -> str:
    """Sanitize an arbitrary string (session/campaign/task ID) for use as a
    filename component. Keeps [A-Za-z0-9._-], collapses everything else to
    underscore. Never returns an empty string."""
    cleaned = _UNSAFE_CHARS.sub("_", name)
    return cleaned or "_"


def atomic_write_json(path: str, data, indent: int = 2):
    """Atomically write ``data`` as JSON to ``path``.

    Writes to a unique temp file in the same directory, flushes + fsyncs it,
    then os.replace()s it into place. On POSIX this means readers can never
    observe a partially-written file. Uses ``default=str`` so non-serializable
    values (datetime, set, Path, bytes) degrade to strings instead of raising
    mid-save.

    Raises on failure (callers may choose to catch); a failed save never
    leaves a corrupt target file — only an orphaned temp file, which is
    removed on the way out.
    """
    directory = os.path.dirname(os.path.abspath(path))
    ensure_dir(directory)
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=directory,
            prefix=os.path.basename(path) + ".",
            suffix=".tmp",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None  # ownership transferred to the file object
            json.dump(data, f, indent=indent, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        tmp_path = None  # consumed by the rename
    except BaseException:
        # Best-effort cleanup of fd + temp file; never mask the original error
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def read_json(path: str, default=None, quiet: bool = False):
    """Load ``path`` as JSON; return ``default`` on any failure.

    Corrupt or partial files (e.g. from a crash before StateStore adoption,
    or manual edits) are logged and yield the caller's default instead of
    raising — the caller then proceeds with a well-defined empty state rather
    than drifting on uninitialized data.

    Pass ``quiet=True`` in hot loops that probe many files (e.g. task listing)
    where per-file warnings would be noise.
    """
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (ValueError, OSError, TypeError) as e:
        if not quiet:
            logger.warning(f"Corrupt/unreadable JSON at {path}: {e} — using default")
        return default


class JsonFileStore:
    """Small typed adapter: a directory of {key}.json files.

    Encapsulates the ubiquitous pattern of N JSON blobs keyed by ID in one
    directory (sessions, campaigns). Handles serialization and atomicity.
    """

    def __init__(self, directory: str):
        self.directory = directory
        ensure_dir(directory)

    def path_for(self, key: str) -> str:
        return os.path.join(self.directory, f"{safe_filename(key)}.json")

    def save(self, key: str, data) -> str:
        """Atomically persist ``data`` under ``key``; returns the path."""
        path = self.path_for(key)
        atomic_write_json(path, data)
        return path

    def load(self, key: str, default=None):
        """Load the blob for ``key``; ``default`` on missing/corrupt."""
        return read_json(self.path_for(key), default)

    def delete(self, key: str) -> bool:
        """Remove the blob for ``key``; returns True if a file was removed."""
        path = self.path_for(key)
        try:
            if os.path.exists(path):
                os.unlink(path)
                return True
        except OSError:
            pass
        return False

    def list_keys(self) -> list:
        """All stored keys (basenames without the .json suffix), sorted."""
        keys = []
        if os.path.isdir(self.directory):
            for fn in sorted(os.listdir(self.directory)):
                if fn.endswith(".json"):
                    keys.append(fn[:-5])
        return keys
