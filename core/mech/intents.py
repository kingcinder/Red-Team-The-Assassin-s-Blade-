"""
RedTeam Harness — Mech-Unit Attack Intent Manifests (v7.0 P1.1)

Loads and validates attack intent manifests (one YAML file per attack
family). A manifest encodes what an expert would know about an attack so the
operator only ever chooses *what outcome* and *against what target*.

Validation is fail-fast (pattern: core/kb_data._validate_dataset): the first
malformed field raises ValueError naming the field and the source file. A
manifest that passes validation is exposed as an IntentManifest dataclass.

Structural guarantees enforced here:
  - ``llm_required`` must be absent or false — a Mech-Unit manifest can never
    declare a hard LLM dependency (advisory calls are compile-time only).
  - Step names are unique within a plan; fallback step names never collide
    with main-plan step names (the plan state machine keys on step names).
  - Every precondition is a probe spec with a non-empty probe name.
"""
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("redteam.mech.intents")

VALID_CATEGORIES = {"wireless", "network", "web", "ad", "cloud", "host"}
VALID_NOISE = {"silent", "low", "medium", "high"}
# Failure-routing directives (v7.0): fallback *routing* lives in the step's
# fallbacks: list; on_fail/on_timeout only decide plan continuation.
VALID_DIRECTIVES = {"warn", "abort", "retry_then_fallback"}
_ID_RE = re.compile(r"^[a-z0-9_]+$")

REQUIRED_TOP_FIELDS = (
    "id", "name", "category", "operator_label", "operator_description",
    "outcome", "grants", "time_to_impact", "noise", "risk_notes",
    "preconditions", "plan",
)


@dataclass
class ProbeSpec:
    """One precondition entry: a named capability probe.

    YAML shape:
        - probe: tools_present
          with: [airodump-ng, aircrack-ng]
          optional: true          # (rare) probe failure compiles with a warning
    """
    probe: str
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def params(self) -> List[str]:
        # 'with' is a YAML-friendly key but a Python keyword — exposed as params.
        val = self.raw.get("with", [])
        return [str(v) for v in val] if isinstance(val, list) else [str(val)]

    @property
    def optional(self) -> bool:
        return bool(self.raw.get("optional", False))

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": self.probe, "with": self.params, "optional": self.optional}


@dataclass
class StepSpec:
    """One plan step: a tool invocation plus control flow."""
    step: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    when: Optional[str] = None
    gate: Optional[Dict[str, Any]] = None
    retries: int = 0
    max_wait: Optional[int] = None
    on_timeout: Optional[str] = None
    on_fail: Optional[str] = None
    fallbacks: List[Dict[str, Any]] = field(default_factory=list)
    extracts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step, "tool": self.tool, "args": dict(self.args),
            "when": self.when, "gate": self.gate, "retries": self.retries,
            "max_wait": self.max_wait, "on_timeout": self.on_timeout,
            "on_fail": self.on_fail, "fallbacks": list(self.fallbacks),
            "extracts": dict(self.extracts),
        }


@dataclass
class IntentManifest:
    """A validated attack intent manifest."""
    id: str
    name: str
    category: str
    operator_label: str
    operator_description: str
    outcome: str
    grants: List[str]
    time_to_impact: str
    noise: str
    risk_notes: str
    preconditions: List[ProbeSpec]
    plan: List[StepSpec]
    artifacts: Dict[str, str] = field(default_factory=dict)
    autonomous: bool = False
    llm_required: bool = False
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Cockpit card payload (id + labels + expectations + plan summary)."""
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "operator_label": self.operator_label,
            "operator_description": self.operator_description,
            "outcome": self.outcome, "grants": list(self.grants),
            "time_to_impact": self.time_to_impact, "noise": self.noise,
            "risk_notes": self.risk_notes,
            "preconditions": [p.to_dict() for p in self.preconditions],
            "plan": [s.to_dict() for s in self.plan],
            "artifacts": dict(self.artifacts),
            "autonomous": self.autonomous,
            "llm_required": self.llm_required,
            "steps": [s.step for s in self.plan],
        }


def _fail(source: str, field_name: str, problem: str) -> None:
    raise ValueError(f"manifest {source}: field '{field_name}': {problem}")


def _require_str(data: Dict[str, Any], key: str, source: str,
                 allow_empty: bool = False) -> str:
    val = data.get(key)
    if not isinstance(val, str):
        _fail(source, key, f"expected a string, got {type(val).__name__}")
    if not allow_empty and not val.strip():
        _fail(source, key, "must not be empty")
    return val


def _require_list(data: Dict[str, Any], key: str, source: str,
                  of_type: type = str, allow_empty: bool = False) -> List[Any]:
    val = data.get(key)
    if not isinstance(val, list):
        _fail(source, key, f"expected a list, got {type(val).__name__}")
    if not allow_empty and not val:
        _fail(source, key, "must not be empty")
    for item in val:
        if not isinstance(item, of_type):
            _fail(source, key,
                  f"expected all items to be {of_type.__name__}, got {type(item).__name__}")
    return val


def _validate_preconditions(data: List[Any], source: str) -> List[ProbeSpec]:
    specs: List[ProbeSpec] = []
    for i, entry in enumerate(data):
        key = f"preconditions[{i}]"
        if not isinstance(entry, dict):
            _fail(source, key, "expected a mapping with a 'probe' key")
        probe = entry.get("probe")
        if not isinstance(probe, str) or not probe.strip():
            _fail(source, key + ".probe", "expected a non-empty probe name")
        specs.append(ProbeSpec(probe=probe, raw=dict(entry)))
    return specs


def _validate_fallbacks(raw_fallbacks: Any, source: str, key: str,
                        main_step_names: set) -> List[Dict[str, Any]]:
    if not isinstance(raw_fallbacks, list):
        _fail(source, key, "expected a list of fallback step mappings")
    names = set()
    out: List[Dict[str, Any]] = []
    for i, fb in enumerate(raw_fallbacks):
        fb_key = f"{key}[{i}]"
        if not isinstance(fb, dict):
            _fail(source, fb_key, "expected a mapping")
        fb_name = fb.get("step")
        if not isinstance(fb_name, str) or not fb_name.strip():
            _fail(source, fb_key + ".step", "expected a non-empty step name")
        if fb_name in names:
            _fail(source, fb_key + ".step", f"duplicate fallback step name '{fb_name}'")
        if fb_name in main_step_names:
            _fail(source, fb_key + ".step",
                  f"fallback step name '{fb_name}' collides with a main plan step")
        if not (fb.get("tool") or fb.get("use_intent")):
            _fail(source, fb_key,
                  "fallback needs either 'tool' (inline step) or 'use_intent' (intent reroute)")
        names.add(fb_name)
        out.append(dict(fb))
    return out


def _validate_steps(raw_steps: List[Any], source: str) -> List[StepSpec]:
    if not raw_steps:
        _fail(source, "plan", "must contain at least one step")
    steps: List[StepSpec] = []
    names: set = set()
    for i, raw in enumerate(raw_steps):
        key = f"plan[{i}]"
        if not isinstance(raw, dict):
            _fail(source, key, "expected a mapping")
        name = raw.get("step")
        if not isinstance(name, str) or not name.strip():
            _fail(source, key + ".step", "expected a non-empty step name")
        if name in names:
            _fail(source, key + ".step", f"duplicate step name '{name}'")
        tool = raw.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            _fail(source, key + ".tool", "expected a non-empty tool name")
        args = raw.get("args", {})
        if not isinstance(args, dict):
            _fail(source, key + ".args", "expected a mapping")
        when = raw.get("when")
        if when is not None and not isinstance(when, str):
            _fail(source, key + ".when", "expected a string expression or null")
        gate = raw.get("gate")
        if gate is not None and not isinstance(gate, dict):
            _fail(source, key + ".gate", "expected a mapping (output/file/exit_code)")
        retries = raw.get("retries", 0)
        if not isinstance(retries, int) or isinstance(retries, bool) or retries < 0:
            _fail(source, key + ".retries", "expected a non-negative integer")
        max_wait = raw.get("max_wait")
        if max_wait is not None and (
                not isinstance(max_wait, int) or isinstance(max_wait, bool) or max_wait <= 0):
            _fail(source, key + ".max_wait", "expected a positive integer (seconds)")
        for opt in ("on_timeout", "on_fail"):
            if raw.get(opt) is not None and not isinstance(raw[opt], str):
                _fail(source, f"{key}.{opt}", "expected a string directive")
        for opt in ("on_timeout", "on_fail"):
            directive = raw.get(opt)
            if directive is not None and directive not in VALID_DIRECTIVES:
                _fail(source, f"{key}.{opt}",
                      f"must be one of {sorted(VALID_DIRECTIVES)}, got '{directive}'")
        extracts = raw.get("extracts", {})
        if not isinstance(extracts, dict):
            _fail(source, key + ".extracts", "expected a mapping of var → regex")
        for var, regex in extracts.items():
            if not isinstance(var, str) or not isinstance(regex, str):
                _fail(source, key + ".extracts", "expected string keys and values")
        fallbacks = _validate_fallbacks(
            raw.get("fallbacks", []), source, key + ".fallbacks", names)
        names.add(name)
        steps.append(StepSpec(
            step=name, tool=tool, args=dict(args), when=when, gate=gate,
            retries=retries, max_wait=max_wait,
            on_timeout=raw.get("on_timeout"), on_fail=raw.get("on_fail"),
            fallbacks=fallbacks, extracts=dict(extracts)))
    return steps


def validate_manifest_dict(data: Any, source: str = "<memory>") -> Dict[str, Any]:
    """Validate a raw manifest mapping; returns it unchanged on success.

    Raises ValueError naming the offending field on the first problem found.
    """
    if not isinstance(data, dict):
        _fail(source, "<root>", f"expected a mapping, got {type(data).__name__}")
    for req in REQUIRED_TOP_FIELDS:
        if req not in data:
            _fail(source, req, "missing required field")

    mid = data["id"]
    if not isinstance(mid, str) or not _ID_RE.match(mid or ""):
        _fail(source, "id", "expected a snake_case identifier (a-z, 0-9, _)")

    category = data["category"]
    if category not in VALID_CATEGORIES:
        _fail(source, "category",
              f"must be one of {sorted(VALID_CATEGORIES)}, got '{category}'")

    noise = data["noise"]
    if noise not in VALID_NOISE:
        _fail(source, "noise",
              f"must be one of {sorted(VALID_NOISE)}, got '{noise}'")

    for key in ("name", "operator_label", "operator_description", "outcome",
                "time_to_impact", "risk_notes"):
        _require_str(data, key, source)
    _require_list(data, "grants", source)

    if data.get("llm_required", False):
        _fail(source, "llm_required",
              "Mech-Unit manifests must set llm_required: false — the LLM is "
              "an optional advisor, never a dependency")

    _validate_preconditions(data["preconditions"], source)
    _validate_steps(data["plan"], source)

    artifacts = data.get("artifacts", {})
    if not isinstance(artifacts, dict):
        _fail(source, "artifacts", "expected a mapping of name → path template")
    return data


def load_manifest(path: str) -> IntentManifest:
    """Load and validate one manifest file → IntentManifest."""
    source = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"manifest {source}: unreadable YAML: {exc}") from exc
    validate_manifest_dict(data, source)
    return IntentManifest(
        id=data["id"], name=data["name"], category=data["category"],
        operator_label=data["operator_label"],
        operator_description=data["operator_description"],
        outcome=data["outcome"], grants=list(data["grants"]),
        time_to_impact=data["time_to_impact"], noise=data["noise"],
        risk_notes=data["risk_notes"],
        preconditions=_validate_preconditions(data["preconditions"], source),
        plan=_validate_steps(data["plan"], source),
        artifacts=dict(data.get("artifacts", {})),
        autonomous=bool(data.get("autonomous", False)),
        llm_required=False,
        source_path=os.path.abspath(path),
    )


def load_manifest_dir(directory: str) -> Dict[str, IntentManifest]:
    """Load every *.yaml/*.yml manifest in a directory, keyed by id.

    Raises ValueError on duplicate manifest ids. Files that fail validation
    raise immediately (fail-fast) — a broken manifest must never silently
    disappear from the operator's intent wall.

    Reserved data files (non-intent YAML, e.g. vuln_graph.yaml) are skipped.
    """
    if not os.path.isdir(directory):
        raise ValueError(f"manifest directory not found: {directory}")
    manifests: Dict[str, IntentManifest] = {}
    for fn in sorted(os.listdir(directory)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        if os.path.splitext(fn)[0].startswith(("vuln_graph", ".")):
            continue  # reserved non-intent data file
        manifest = load_manifest(os.path.join(directory, fn))
        if manifest.id in manifests:
            raise ValueError(
                f"duplicate manifest id '{manifest.id}' in {fn} "
                f"(already loaded from {manifests[manifest.id].source_path})")
        manifests[manifest.id] = manifest
    return manifests
