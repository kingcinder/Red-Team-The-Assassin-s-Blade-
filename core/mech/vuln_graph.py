"""
RedTeam Harness — VULN-GRAPH Capitalization Engine (v7.0 P2.4 / P3)

Findings → scored, dependency-aware "next moves". Zero LLM.

A vertex fires when a finding's text matches its pattern. Each
capitalization entry under a fired vertex is one next move:

    score = confidence × value × precondition_satisfaction

where precondition_satisfaction is 1.0 when the entry's probe (if any)
passes and 0.0 when it fails — a failed probe zeroes the move and the
explanation says why (the operator learns what's missing, not just that
nothing is offered).

The requires/provides fields form a capability dependency graph between
vertices; cycles are rejected at load time (fail-fast, like manifests).

Determinism: moves are sorted by (-score, vertex_id, intent) — identical
inputs always yield identical orderings.
"""
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import yaml

logger = logging.getLogger("redteam.mech.vuln_graph")

_REQUIRED_VERTEX_FIELDS = ("id", "matched_by", "provides", "grants",
                           "capitalization")


@dataclass
class Capitalization:
    """One next move offered by a fired vertex."""
    intent: str
    confidence: float
    value: float = 0.5
    probe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"intent": self.intent, "confidence": self.confidence,
                "value": self.value, "probe": self.probe}


@dataclass
class Vertex:
    """One vulnerability-capitalization vertex."""
    id: str
    pattern: re.Pattern
    phase: str = "recon"
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    grants: List[str] = field(default_factory=list)
    capitalization: List[Capitalization] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "phase": self.phase,
                "requires": list(self.requires),
                "provides": list(self.provides), "grants": list(self.grants),
                "capitalization": [c.to_dict() for c in self.capitalization]}


@dataclass
class NextMove:
    """A scored, explainable next move for the run console."""
    vertex_id: str
    intent: str
    score: float
    confidence: float
    value: float
    probe_ok: bool
    why: str

    def to_dict(self) -> Dict[str, Any]:
        return {"vertex_id": self.vertex_id, "intent": self.intent,
                "score": round(self.score, 4),
                "confidence": self.confidence, "value": self.value,
                "probe_ok": self.probe_ok, "why": self.why}


def _fail(source: str, where: str, problem: str) -> None:
    raise ValueError(f"vuln graph {source}: {where}: {problem}")


def _detect_cycles(vertices: List[Vertex], source: str) -> None:
    """DFS over capability dependencies: vertex → producers of its requires.

    Multiple vertices may provide the same capability (parallel attack
    paths — e.g. handshake capture and PMKID both yield
    wifi.handshake_file); a requirement then depends on every producer.
    A cycle is reported only for a real directed loop.
    """
    producers: Dict[str, List[str]] = {}
    for v in vertices:
        for cap in v.provides:
            producers.setdefault(cap, [])
            if v.id not in producers[cap]:
                producers[cap].append(v.id)

    edges: Dict[str, List[str]] = {v.id: [] for v in vertices}
    for v in vertices:
        for req in v.requires:
            for producer in producers.get(req, []):
                if producer != v.id and producer not in edges[v.id]:
                    edges[v.id].append(producer)

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {v.id: WHITE for v in vertices}

    def dfs(node: str, path: List[str]) -> None:
        color[node] = GRAY
        path.append(node)
        for nxt in edges.get(node, []):
            if color[nxt] == GRAY:
                cycle = path[path.index(nxt):] + [nxt]
                _fail(source, "requires/provides graph",
                      "capability cycle: " + " → ".join(cycle))
            if color[nxt] == WHITE:
                dfs(nxt, path)
        path.pop()
        color[node] = BLACK

    for v in vertices:
        if color[v.id] == WHITE:
            dfs(v.id, [])


def load_vuln_graph(path: str) -> List[Vertex]:
    """Load + validate the vuln graph; returns vertices (fail-fast)."""
    source = os.path.basename(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or not isinstance(data.get("vertices"), list):
        _fail(source, "<root>", "expected a mapping with a 'vertices' list")

    vertices: List[Vertex] = []
    ids: set = set()
    for i, raw in enumerate(data["vertices"]):
        where = f"vertices[{i}]"
        if not isinstance(raw, dict):
            _fail(source, where, "expected a mapping")
        for req in _REQUIRED_VERTEX_FIELDS:
            if req not in raw:
                _fail(source, f"{where}.{req}", "missing required field")
        vid = raw["id"]
        if not isinstance(vid, str) or not vid:
            _fail(source, f"{where}.id", "expected a non-empty string")
        if vid in ids:
            _fail(source, f"{where}.id", f"duplicate vertex id '{vid}'")
        ids.add(vid)
        pattern = raw["matched_by"].get("pattern") \
            if isinstance(raw["matched_by"], dict) else None
        if not isinstance(pattern, str) or not pattern:
            _fail(source, f"{where}.matched_by.pattern",
                  "expected a non-empty regex string")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            _fail(source, f"{where}.matched_by.pattern", f"bad regex: {exc}")

        caps: List[Capitalization] = []
        if not isinstance(raw["capitalization"], list):
            _fail(source, f"{where}.capitalization", "expected a list")
        for j, cap in enumerate(raw["capitalization"]):
            cwhere = f"{where}.capitalization[{j}]"
            if not isinstance(cap, dict) or not cap.get("intent"):
                _fail(source, cwhere, "expected a mapping with 'intent'")
            try:
                conf = float(cap.get("confidence", 0.0))
                val = float(cap.get("value", 0.5))
            except (TypeError, ValueError):
                _fail(source, cwhere, "confidence/value must be numbers")
            if not (0.0 <= conf <= 1.0):
                _fail(source, cwhere + ".confidence", "must be within [0, 1]")
            caps.append(Capitalization(
                intent=str(cap["intent"]), confidence=conf, value=val,
                probe=cap.get("probe")))

        vertices.append(Vertex(
            id=vid, pattern=compiled, phase=raw.get("phase", "recon"),
            requires=[str(r) for r in raw.get("requires", [])],
            provides=[str(p) for p in raw["provides"]],
            grants=[str(g) for g in raw["grants"]],
            capitalization=caps))

    _detect_cycles(vertices, source)
    return vertices


class VulnGraph:
    """Query engine: findings → scored next moves."""

    def __init__(self, vertices: List[Vertex]):
        self.vertices = vertices

    @classmethod
    def from_file(cls, path: str) -> "VulnGraph":
        return cls(load_vuln_graph(path))

    def _finding_text(self, finding: Dict[str, Any]) -> str:
        parts = []
        for key in ("title", "detail", "evidence", "summary", "source_tool",
                    "finding", "category"):
            val = finding.get(key)
            if val:
                parts.append(str(val))
        return " ".join(parts)

    def match_vertices(self, findings: List[Dict[str, Any]]) -> List[Vertex]:
        """Vertices whose pattern matches at least one finding (deduped,
        graph order preserved)."""
        fired: Dict[str, Vertex] = {}
        for finding in findings:
            text = self._finding_text(finding)
            if not text:
                continue
            for v in self.vertices:
                if v.id not in fired and v.pattern.search(text):
                    fired[v.id] = v
        return list(fired.values())

    def next_moves(self, findings: List[Dict[str, Any]],
                   probe_checker: Optional[Callable[[str], bool]] = None
                   ) -> List[NextMove]:
        """Scored next moves for the given findings.

        probe_checker: name → bool. Missing checker ⇒ probes assumed ok.
        Deterministic ordering: (-score, vertex_id, intent).
        """
        moves: List[NextMove] = []
        for v in self.match_vertices(findings):
            for cap in v.capitalization:
                probe_ok = True
                if cap.probe and probe_checker is not None:
                    try:
                        probe_ok = bool(probe_checker(cap.probe))
                    except Exception:
                        probe_ok = False
                score = cap.confidence * cap.value * (1.0 if probe_ok else 0.0)
                why = (f"finding matched vertex '{v.id}' "
                      f"({cap.confidence:.2f} confidence × {cap.value:.2f} value)")
                if cap.probe and not probe_ok:
                    why += f" — blocked: probe '{cap.probe}' failed"
                moves.append(NextMove(
                    vertex_id=v.id, intent=cap.intent, score=score,
                    confidence=cap.confidence, value=cap.value,
                    probe_ok=probe_ok, why=why))
        moves.sort(key=lambda m: (-m.score, m.vertex_id, m.intent))
        return moves
