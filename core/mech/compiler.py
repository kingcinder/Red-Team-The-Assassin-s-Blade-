"""
RedTeam Harness — Mech-Unit Plan Compiler (v7.0 P1.4)

Turns (intent manifest + live state) into a validated plan DAG:

    compile_intent(manifest, ctx) → CompiledPlan

Compilation is fully deterministic:
  1. Precondition probes run — a hard probe failure blocks compilation with
     the exact probe reason + fix (surfaced on the intent card).
  2. Every placeholder in every step's args, gates, and artifact paths is
     resolved by core.mech.resolver. Anything unresolvable is collected as
     an "unresolved (needs advice)" entry — never guessed, never LLM-filled.
  3. The compile report records param ← source for every filled value
     (teaching mode, manifest §3.4 rule 2).
"""
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.mech.intents import IntentManifest, StepSpec
from core.mech.resolver import Resolver, ResolveContext, UnresolvedPlaceholder
from core.mech.probes import ProbeResult, run_probe
from core.state_store import atomic_write_json, read_json, safe_filename

logger = logging.getLogger("redteam.mech.compiler")


@dataclass
class CompiledStep:
    """One plan step with resolved args and its param ← source log."""
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
    resolution_log: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step, "tool": self.tool, "args": dict(self.args),
            "when": self.when, "gate": dict(self.gate) if self.gate else None,
            "retries": self.retries, "max_wait": self.max_wait,
            "on_timeout": self.on_timeout, "on_fail": self.on_fail,
            "fallbacks": [dict(f) for f in self.fallbacks],
            "extracts": dict(self.extracts),
            "resolution_log": list(self.resolution_log),
        }


@dataclass
class UnresolvedEntry:
    """A placeholder no resolver could fill — surfaced, never guessed."""
    step: str
    arg: str
    template: str
    placeholder: str

    def to_dict(self) -> Dict[str, Any]:
        return {"step": self.step, "arg": self.arg,
                "template": self.template, "placeholder": self.placeholder}


@dataclass
class CompiledPlan:
    """The compile product: a validated, parameterized plan."""
    plan_id: str
    intent: IntentManifest
    target: Dict[str, Any]
    plan_dir: str
    steps: List[CompiledStep]
    artifacts: Dict[str, str]
    probe_results: List[ProbeResult]
    unresolved: List[UnresolvedEntry]
    compiled_at: str
    resolution_log: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def runnable(self) -> bool:
        """True when compilation left nothing unresolved."""
        return not self.unresolved

    def step_names(self) -> List[str]:
        return [s.step for s in self.steps]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "intent_id": self.intent.id,
            "intent_name": self.intent.name,
            "category": self.intent.category,
            "target": dict(self.target),
            "plan_dir": self.plan_dir,
            "steps": [s.to_dict() for s in self.steps],
            "artifacts": dict(self.artifacts),
            "probe_results": [p.to_dict() for p in self.probe_results],
            "unresolved": [u.to_dict() for u in self.unresolved],
            "runnable": self.runnable,
            "compiled_at": self.compiled_at,
            "resolution_log": list(self.resolution_log),
        }

    def write_report(self) -> str:
        """Persist plan.json (the compile report) atomically; returns path."""
        path = os.path.join(self.plan_dir, "plan.json")
        atomic_write_json(path, self.to_dict())
        return path

    @classmethod
    def from_report(cls, plan_dir: str, intent: IntentManifest) -> "CompiledPlan":
        """Rebuild a CompiledPlan from its persisted plan.json (v7.1).

        This is the crash-recovery seam: a NEW process can resume a plan
        compiled by a dead one. Raises ValueError when no report exists.
        probe_results/unresolved are not reconstructed (compile-time data;
        a resumable plan had none that mattered — runnable was true).
        """
        data = read_json(os.path.join(plan_dir, "plan.json"))
        if not data:
            raise ValueError(f"no plan.json report in {plan_dir}")
        steps = [CompiledStep(
            step=s["step"], tool=s["tool"], args=dict(s.get("args", {})),
            when=s.get("when"), gate=s.get("gate"), retries=s.get("retries", 0),
            max_wait=s.get("max_wait"), on_timeout=s.get("on_timeout"),
            on_fail=s.get("on_fail"), fallbacks=list(s.get("fallbacks", [])),
            extracts=dict(s.get("extracts", {})),
            resolution_log=list(s.get("resolution_log", [])))
            for s in data.get("steps", [])]
        return cls(plan_id=data["plan_id"], intent=intent,
                   target=dict(data.get("target", {})), plan_dir=plan_dir,
                   steps=steps, artifacts=dict(data.get("artifacts", {})),
                   probe_results=[], unresolved=[],
                   compiled_at=data.get("compiled_at", ""),
                   resolution_log=list(data.get("resolution_log", [])))


def _probe_manifest(manifest: IntentManifest) -> List[ProbeResult]:
    results = []
    for spec in manifest.preconditions:
        results.append(run_probe(spec.probe, spec.params))
    return results


def _hard_failures(manifest: IntentManifest,
                   results: List[ProbeResult]) -> List[ProbeResult]:
    """Probe failures that block compilation (non-optional preconditions)."""
    optional = {s.probe for s in manifest.preconditions if s.optional}
    return [r for r in results if not r.ok and r.probe not in optional]


def _resolve_gate(gate: Dict[str, Any], resolver: Resolver,
                  step_name: str, log: List[Dict[str, Any]],
                  unresolved: List[UnresolvedEntry]) -> Dict[str, Any]:
    """Resolve placeholder strings inside a gate dict (values and lists)."""
    resolved_gate: Dict[str, Any] = {}
    for gkey, gval in gate.items():
        if isinstance(gval, str):
            try:
                out = resolver.resolve_value(gval, arg_key=f"gate:{gkey}")
                resolved_gate[gkey] = out
                log.extend(r.to_dict() for r in resolver.log[-1:])
            except UnresolvedPlaceholder as exc:
                unresolved.append(UnresolvedEntry(
                    step=step_name, arg=f"gate:{gkey}", template=str(gval),
                    placeholder=exc.path))
        elif isinstance(gval, list):
            new_list = []
            for item in gval:
                if isinstance(item, str):
                    try:
                        out = resolver.resolve_value(item, arg_key=f"gate:{gkey}")
                        new_list.append(out)
                        log.extend(r.to_dict() for r in resolver.log[-1:])
                    except UnresolvedPlaceholder as exc:
                        unresolved.append(UnresolvedEntry(
                            step=step_name, arg=f"gate:{gkey}",
                            template=str(item), placeholder=exc.path))
                else:
                    new_list.append(item)
            resolved_gate[gkey] = new_list
        else:
            resolved_gate[gkey] = gval
    return resolved_gate


def _resolve_step_args(step: StepSpec, resolver: Resolver
                       ) -> tuple[Dict[str, Any], Optional[Dict[str, Any]], List[Dict[str, Any]], List[UnresolvedEntry]]:
    """Resolve one step's args AND its gate; returns (args, gate, log, unresolved)."""
    unresolved: List[UnresolvedEntry] = []
    try:
        args, log = resolver.resolve_mapping(step.args)
        log_dicts = [r.to_dict() for r in log]
    except UnresolvedPlaceholder:
        # Re-run per-arg so the remaining args still resolve and the
        # unresolved entry names the exact arg (preview shows a blank).
        args = {}
        log_dicts = []
        for key, value in step.args.items():
            try:
                resolved, res_log = resolver.resolve_mapping({key: value})
                args.update(resolved)
                log_dicts.extend(r.to_dict() for r in res_log)
            except UnresolvedPlaceholder as arg_exc:
                unresolved.append(UnresolvedEntry(
                    step=step.step, arg=key, template=str(value),
                    placeholder=arg_exc.path))
    gate = _resolve_gate(step.gate, resolver, step.step, log_dicts, unresolved) \
        if step.gate else None
    return args, gate, log_dicts, unresolved


def compile_intent(manifest: IntentManifest,
                   ctx: ResolveContext,
                   sandbox_root: str = "./tasks/mech",
                   plan_id: Optional[str] = None) -> CompiledPlan:
    """Compile an intent manifest against live state into a CompiledPlan.

    Raises PermissionError when a hard precondition probe fails (the error
    message carries the probe's reason + fix for the intent card).
    """
    # 1. Precondition probes.
    probe_results = _probe_manifest(manifest)
    hard = _hard_failures(manifest, probe_results)
    if hard:
        first = hard[0]
        detail = "; ".join(
            f"{r.probe}: {r.reason} (fix: {r.fix})" for r in hard)
        raise PermissionError(
            f"intent '{manifest.id}' cannot compile — preconditions failed: {detail}")
    logger.info("intent %s: %d/%d preconditions satisfied",
                manifest.id,
                sum(1 for r in probe_results if r.ok), len(probe_results))

    # 2. Sandbox + identity.
    if not plan_id:
        plan_id = f"{safe_filename(manifest.id)}_{time.strftime('%Y%m%d_%H%M%S')}"
    plan_dir = os.path.join(sandbox_root, plan_id)
    os.makedirs(plan_dir, exist_ok=True)
    ctx.plan_dir = plan_dir

    # 3. Resolve artifacts first (steps may reference them implicitly).
    resolver = Resolver(ctx)
    artifacts: Dict[str, str] = {}
    artifact_log: List[Dict[str, Any]] = []
    for name, template in manifest.artifacts.items():
        resolved = resolver.resolve_value(template, arg_key=f"artifact:{name}")
        artifacts[name] = str(resolved)
    artifact_log = [r.to_dict() for r in resolver.log]
    # Feed the resolved artifacts back into the resolver context so step args
    # referencing {{ artifacts.<name> }} (e.g. wifi_wep.crack.cap_file) resolve
    # to the plan sandbox path. Without this the artifacts.* namespace is always
    # empty in production (MechUnit._resolve_context creates it blank) and every
    # plan that chains a later step off a named artifact compiles unresolved and
    # can never be run.
    ctx.artifacts = artifacts

    # 4. Resolve every step.
    steps: List[CompiledStep] = []
    all_unresolved: List[UnresolvedEntry] = []
    for step in manifest.plan:
        args, gate, log, unresolved = _resolve_step_args(step, resolver)
        all_unresolved.extend(unresolved)
        steps.append(CompiledStep(
            step=step.step, tool=step.tool, args=args, when=step.when,
            gate=gate, retries=step.retries, max_wait=step.max_wait,
            on_timeout=step.on_timeout, on_fail=step.on_fail,
            fallbacks=[dict(f) for f in step.fallbacks],
            extracts=dict(step.extracts), resolution_log=log))

    # 5. Structural guarantee: a compiled plan never requires an LLM.
    if manifest.llm_required:
        raise ValueError(
            f"intent '{manifest.id}': llm_required must be false ( Mech-Unit contract)")

    plan = CompiledPlan(
        plan_id=plan_id, intent=manifest, target=dict(ctx.target),
        plan_dir=plan_dir, steps=steps, artifacts=artifacts,
        probe_results=probe_results, unresolved=all_unresolved,
        compiled_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        resolution_log=artifact_log + [r.to_dict() for r in resolver.log[len(artifact_log):]],
    )
    plan.write_report()
    logger.info("intent %s → plan %s (%d steps, %d unresolved)",
                manifest.id, plan_id, len(steps), len(all_unresolved))
    return plan
