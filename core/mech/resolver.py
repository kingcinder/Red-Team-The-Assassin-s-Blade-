"""
RedTeam Harness — Mech-Unit Deterministic Resolver (v7.0 P1.3)

Fills every plan parameter from live state so the operator never types a
tool flag. Placeholder grammar inside manifest args:

    {{ target.<key> }}                       — operator's target selection
    {{ facts.<key> }}                        — facts extracted by earlier steps
    {{ artifacts.<name> }}                   — named plan artifacts (sandbox paths)
    {{ resolver.interface.monitor }}         — best monitor-mode interface
    {{ resolver.channel.or_hop }}            — scan hint channel, else hop-all "0"
    {{ resolver.artifacts.capture_prefix }}  — collision-safe capture prefix
    {{ resolver.wordlist.adaptive[:c1,c2] }} — first existing wordlist candidate
    {{ resolver.tool.first_installed:t1,t2 }}— first installed tool candidate

Rules (manifest §3.4):
  1. Operator input is selection, never typing.
  2. Every resolution is logged: (param, template → value ← source).
  3. Anything a resolver cannot fill raises UnresolvedPlaceholder — the
     compiler turns that into an unresolved-with-advice entry, never a guess.
"""
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("redteam.mech.resolver")

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.:\-]+?)\s*\}\}")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO_WORDLIST_DIR = os.path.join(_REPO_ROOT, "wordlists")

# Deterministic adaptive wordlist order: explicit candidates (from the
# manifest suffix) → router-default lists → repo-bundled → classic rockyou.
DEFAULT_WORDLIST_CANDIDATES = [
    os.path.join(REPO_WORDLIST_DIR, "rockyou.txt"),
    "/usr/share/wordlists/rockyou.txt",
    os.path.join(REPO_WORDLIST_DIR, "lab.txt"),
]


class UnresolvedPlaceholder(Exception):
    """A placeholder no deterministic resolver could fill.

    Carries the dotted path and the arg key so the compiler can surface
    'unresolved with advice' entries on the preview screen.
    """

    def __init__(self, path: str, arg_key: str = ""):
        self.path = path
        self.arg_key = arg_key
        super().__init__(f"unresolved placeholder '{{{{ {path} }}}}"
                         + (f" in arg '{arg_key}'" if arg_key else ""))


@dataclass
class Resolution:
    """One param ← source log entry (teaching mode)."""
    arg_key: str
    template: str
    value: Any
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {"arg": self.arg_key, "template": self.template,
                "value": self.value, "source": self.source}


@dataclass
class ResolveContext:
    """Everything a resolver may consult, all injectable for tests."""
    target: Dict[str, Any] = field(default_factory=dict)
    facts: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    plan_dir: str = ""
    capture_interface: Optional[str] = None
    scan: Dict[str, Any] = field(default_factory=dict)
    interfaces: Optional[List[Dict]] = None      # probes.list_interfaces() shape
    tool_exists: Optional[Callable[[str], bool]] = None
    path_exists: Optional[Callable[[str], bool]] = None

    @staticmethod
    def _exists(path: str) -> bool:
        return os.path.isfile(path)


class Resolver:
    """Deterministic placeholder resolver with a param ← source log."""

    def __init__(self, ctx: ResolveContext):
        self.ctx = ctx
        self.log: List[Resolution] = []

    # ── public API ───────────────────────────────────────────────────

    def resolve_mapping(self, args: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Resolution]]:
        """Resolve every string value in an args mapping.

        Returns (resolved_args, source_log). Non-string values pass through.
        Raises UnresolvedPlaceholder naming the first unfilled placeholder.
        """
        before = len(self.log)
        out: Dict[str, Any] = {}
        for key, value in args.items():
            out[key] = self.resolve_value(value, arg_key=key)
        return out, self.log[before:]

    def resolve_value(self, value: Any, arg_key: str = "") -> Any:
        if not isinstance(value, str):
            return value
        matches = list(PLACEHOLDER_RE.finditer(value))
        if not matches:
            return value

        # Whole-string single placeholder → typed value (bool/int/dict ok).
        if len(matches) == 1 and matches[0].span() == (0, len(value)):
            resolved, source = self._lookup(matches[0].group(1), arg_key)
            self.log.append(Resolution(arg_key, value, resolved, source))
            return resolved

        # Embedded placeholder(s) → string substitution.
        sources: List[str] = []

        def _sub(m: "re.Match") -> str:
            resolved, src = self._lookup(m.group(1), arg_key)
            sources.append(src)
            return str(resolved)

        resolved_str = PLACEHOLDER_RE.sub(_sub, value)
        # Single-source substitutions carry that source (teaching mode);
        # multi-source ones summarize.
        source = sources[0] if len(set(sources)) == 1 else \
            "resolver:embedded-substitution (multiple sources)"
        self.log.append(Resolution(
            arg_key, value, resolved_str, source))
        return resolved_str

    # ── path lookup ──────────────────────────────────────────────────

    def _lookup(self, path: str, arg_key: str) -> Tuple[Any, str]:
        root, _, rest = path.partition(".")
        if root == "plan_dir":
            if not self.ctx.plan_dir:
                raise UnresolvedPlaceholder(path, arg_key)
            return self.ctx.plan_dir, "plan_dir (plan sandbox root)"
        if root == "target":
            if rest in self.ctx.target:
                return self.ctx.target[rest], f"target.{rest} (operator selection)"
            raise UnresolvedPlaceholder(path, arg_key)
        if root == "facts":
            if rest in self.ctx.facts:
                return self.ctx.facts[rest], f"facts.{rest} (extracted from output)"
            raise UnresolvedPlaceholder(path, arg_key)
        if root == "artifacts":
            if rest in self.ctx.artifacts:
                return self.ctx.artifacts[rest], f"artifacts.{rest} (plan sandbox)"
            raise UnresolvedPlaceholder(path, arg_key)
        if root == "resolver":
            return self._resolve_builtin(rest, arg_key)
        raise UnresolvedPlaceholder(path, arg_key)

    # ── resolver.* builtins ──────────────────────────────────────────

    def _resolve_builtin(self, expr: str, arg_key: str) -> Tuple[Any, str]:
        # Optional candidate suffix after a colon: name:c1,c2
        name, _, suffix = expr.partition(":")
        candidates = [c.strip() for c in suffix.split(",")] if suffix else []

        if name == "interface.monitor":
            iface, source = self._pick_monitor_interface()
            return iface, source

        if name == "channel.or_hop":
            hint = str(self.ctx.scan.get("channel") or "").strip()
            if hint:
                return hint, "resolver.channel.or_hop (last scan hint)"
            return "0", "resolver.channel.or_hop (no scan hint — channel-hop all)"

        if name == "artifacts.capture_prefix":
            prefix = os.path.join(self.ctx.plan_dir, "capture")
            return prefix, "resolver.artifacts.capture_prefix (plan sandbox)"

        if name == "wordlist.adaptive":
            order = candidates or DEFAULT_WORDLIST_CANDIDATES
            for wl in order:
                if self._path_exists(wl):
                    return wl, f"resolver.wordlist.adaptive (first existing of {len(order)})"
            raise UnresolvedPlaceholder(f"resolver.{expr}", arg_key)

        if name == "tool.first_installed":
            for tool in candidates:
                if self._tool_exists(tool):
                    return tool, f"resolver.tool.first_installed (of {len(candidates)})"
            raise UnresolvedPlaceholder(f"resolver.{expr}", arg_key)

        raise UnresolvedPlaceholder(f"resolver.{name}", arg_key)

    # ── injectable predicates ────────────────────────────────────────

    def _path_exists(self, path: str) -> bool:
        if self.ctx.path_exists is not None:
            return bool(self.ctx.path_exists(path))
        return self.ctx._exists(path)

    def _tool_exists(self, tool: str) -> bool:
        if self.ctx.tool_exists is not None:
            return bool(self.ctx.tool_exists(tool))
        try:
            return shutil_which(tool) is not None
        except Exception:
            return False

    # ── adapter selection ────────────────────────────────────────────

    def _pick_monitor_interface(self) -> Tuple[str, str]:
        # 1. Operator's explicit capture-state selection wins (v6.3 contract).
        if self.ctx.capture_interface:
            return (self.ctx.capture_interface,
                    "resolver.interface.monitor (operator's capture-state selection)")
        # 2. Live inventory: an interface already in monitor mode.
        inv = self.ctx.interfaces
        if inv is None:
            from core.mech.probes import list_interfaces
            inv = list_interfaces()
        monitors = [it["name"] for it in inv if it.get("monitor")]
        if monitors:
            return monitors[0], "resolver.interface.monitor (already in monitor mode)"
        # 3. Any wireless phys — the plan's monitor_up step flips it.
        wireless = [it["name"] for it in inv if it.get("wireless")]
        if wireless:
            return (wireless[0],
                    "resolver.interface.monitor (wireless phys — monitor_up step will enable monitor mode)")
        raise UnresolvedPlaceholder("resolver.interface.monitor", arg_key="interface")


def shutil_which(binary: str) -> Optional[str]:
    import shutil
    return shutil.which(binary)


def resolve_manifest_placeholders(text: str, resolver: "Resolver",
                                  arg_key: str = "") -> str:
    """Convenience for non-args strings (gates, artifact templates)."""
    return resolver.resolve_value(text, arg_key=arg_key)
